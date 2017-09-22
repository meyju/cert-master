#!/usr/bin/env python3
# _*_ coding: utf-8


##############################################
#  Prog: cert-master
#  Version: 0.1
#  Autor: Julian Meyer
#  URL: https://github.com/meyju/cert-master
#
#  LICENSE: MIT - see LICENSE for details.
##############################################

import argparse
import logging
import os
import sys
import time
import yaml
from datetime import timedelta
from multiprocessing.dummy import Pool as ThreadPool
from cert_master.route53 import r53
from cert_master.ca_LetsEncrypt import CaLetsEncrypt
from cert_master.ca_Local import CaLocal
from cert_master.certificate import MyCertificate


PROG='cert-master.py'

# Logging
logformat = '%(asctime)s - %(levelname)s\t- %(module)s ( %(threadName)s )\t- %(message)s'
logging.basicConfig(level=logging.ERROR, format=logformat)
logger = logging.getLogger(__name__)

stats = {}
stats['certificates'] = 0
stats['fqdns'] = 0
stats['cert_config_error'] = 0
stats['cert_total_LetsEncrypt'] = 0
stats['cert_total_LocalCA'] = 0
stats['cert_check_successful'] = 0
stats['cert_check_renew'] = 0
stats['cert_renew_successful'] = 0
stats['cert_renew_failed'] = 0

def defineParser():
    '''
    Definition if all commandline Flags
    '''

    parser = argparse.ArgumentParser(prog=PROG)
    parser.add_argument('--config', '-c', dest="config",  help='YAML file with config',required=True)
    parser.add_argument('-v', '--verbose', default=0, action='count', help='Loglevel -vvv for debug')
    parser.add_argument('--no-multiprocessing', dest = 'multiprocessing', required=False, action='store_false',
                        help='work without Multitasking')
    parser.add_argument('--threads', type=int, default=10, required=False , help='how many threads should be used')
    parser.add_argument('--stage', dest='stage', required=False, action='store_false',
                        help='switch to staging mode')
    args = parser.parse_args()

    if args.verbose == 0:
        logger.setLevel(logging.WARN)
    elif args.verbose == 1:
        logger.setLevel(logging.INFO)
    elif args.verbose >= 2:
        logger.setLevel(logging.DEBUG)

    return parser


def main():

    # Args
    args = defineParser().parse_args()
    logger.info('startup program ' + PROG)
    logger.debug('using config file: ' + str(args.config))

    with open(args.config, 'r') as fstream:
        baseconfig = yaml.load(fstream)

    # loading yaml config for domains
    domainconfig = []
    files = os.listdir(baseconfig['Generic']['confdirectory'])
    for f in files:
        if f.endswith('.yaml'):
            conffile = open(baseconfig['Generic']['confdirectory'] + f, "r")
            docs = yaml.load_all(conffile)
            for doc in docs:
                domainconfig.append(doc)

    # TODO: Check Generic Default Config
    # TODO: Check CAs Default Config

    # TODO: Check LE Account/Connection
    # TODO: Check AWS Route53 Account/Connection

    # Connect to Route53:
    if baseconfig['Route53']['aws_accesskey'] and baseconfig['Route53']['aws_secretkey']:
        logger.debug('aws accesskey: ' + str(baseconfig['Route53']['aws_accesskey']))
        Route53 = r53(baseconfig['Route53']['aws_accesskey'], baseconfig['Route53']['aws_secretkey'], logger=logger)
    else:
        Route53 = r53(logger=logger)
    Route53.enable_connection()

    # Remove 'None' elements from domainconfig <- happens if there are yaml splits '---' without content
    domainconfig = list(filter(None.__ne__, domainconfig))

    logger.info('starting complete, checking now for certificates')

    threading_tasks = []

    for domain in domainconfig:
        stats['certificates'] += 1
        logger.info(50 * '=')

        # Append Defaults
        (domain,validation_error) = validate_and_fillup_with_defaults(domain, baseconfig)
        if domain['CA'] == "LetsEncrypt":
            stats['cert_total_LetsEncrypt'] += 1
        elif domain['CA'] == "LocalCA":
            stats['cert_total_LocalCA'] += 1
        if validation_error is not False:
            logger.error('Vailidation failure: {}'.format(validation_error))
            if 'Domain' not in domain:
                logger.error('skipping faulty configuration! {}'.format(domain))
            else:
                logger.error('skipping "{}" certificate!'.format(domain['Domain']))
            stats['cert_config_error'] += 1
            continue

        logger.info('Certificat (CN/Domain): ' + str(domain['Domain']))
        logger.debug('Domainconfig: ' + str(domain))
        stats['fqdns'] += (1 + len(domain['AlternativeName']))

        # Create Save Directory if it not exists:
        try:
            os.makedirs(domain['save_path'], exist_ok=True)
        except Exception as e:
            logger.error('could not create directory "{}" for certificate: {}'.format(domain['save_path'],e))
            logger.error('skipping "{}" certificate!'.format(domain['Domain']))
            continue

        # Check if Create or Renew Certificate
        (check_result, check_msg) = checkCertificate(domain, baseconfig)
        if check_result is True and domain['force_renew'] == False:
            logger.info('Certificate "{}" is valid and matches configuration.'.format(domain['Domain']))
            stats['cert_check_successful'] += 1
            continue
        else:
            for msg in check_msg:
                logger.warning('Certificate "{}" - {}'.format(domain['Domain'], msg))
            if domain['force_renew'] == True:
                logger.warning('Certificate "{}" - Forced to renew'.format(domain['Domain']))
            logger.info('Certificate "{}" has to be created/reissued.'.format(domain['Domain']))
            stats['cert_check_renew'] += 1

        # Create or Renew Certificate
        if args.multiprocessing:
            threading_tasks.append((domain, baseconfig, Route53, args))
        else:
            createCertificate(domain, baseconfig, Route53, args)

        # Reset for next Loop
        domain = None

    # Run Certificate Creation in parallel if configured
    if args.multiprocessing and len(threading_tasks) > 0:
        logger.info(50 * '=')
        max_threads = 20
        threads = max_threads if len(threading_tasks) > max_threads else len(threading_tasks)
        pool = ThreadPool(threads)

        start = time.time()
        results = pool.starmap(createCertificate, threading_tasks)
        # close the pool and wait for the work to finish
        pool.close()
        pool.join()
        end = time.time()
        duration = int(float(end - start))
        logger.info("Multiprocessing with {0} Threads - Duration: {1}".format(threads, timedelta(seconds=duration)))

    logStats()

    if stats['cert_renew_failed'] > 0:
        logger.info(PROG + ' finished with errors - Quit')
        sys.exit(2)
    elif stats['cert_config_error'] > 0:
        logger.info(PROG + ' finished with warnings - Quit')
        sys.exit(1)
    else:
        logger.info(PROG + ' finished - Quit')
        sys.exit(0)

def createCertificate(domain, baseconfig, Route53, args):
    logger.info('Requesting Certificate for "{}"'.format(domain['Domain']))
    if domain['CA'] == "LetsEncrypt":
        logger.info('Requesting Certificate signed by CA: LetsEncrypt')
        res = useLetsEncryptCA(domain, baseconfig, Route53, args)
        if res == False:
            stats['cert_renew_failed'] += 1
    elif domain['CA'] == "LocalCA":
        logger.info('Requesting Certificate signed by CA: LocalCA')
        res = useLocalCA(domain, baseconfig)
        if res == False:
            stats['cert_renew_failed'] += 1
    else:
        logger.error('Unknown CA "{}" requested for Certificate signing!'.format(domain['CA']))

    stats['cert_renew_successful'] += 1
    logger.info('Requesting Certificate for "{}" finished'.format(domain['Domain']))

def checkCertificate(domain, baseconfig):
    ''' Checking if the certificate is valid and matches configuration
        :param dict domain: Dictionary with all required information's for the domain
        :param dict baseconfig: Dictionary with all required information's for the CA's
        :param bool with_new_key: Force creation of a new private key
        :param bool KeyUsage: Add KeyUsage Extension to the CSR (Default: True)
                              Will be: digitalSignature, keyEncipherment (critical)
        :param bool ExtendedKeyUsage: Add ExtendedKeyUsage Extension to the CSR (Default: True)
                                      Will be: TLS Web Server Authentication, TLS Web Client Authentication

        :returns: True: if certificate is ok
                  False: if certificate has to be created/updated/renewed
        :rtype: `bool`
    '''

    check_result = True
    check_msg = []

    for keytype in domain['keytype']:
        cert_file = domain['save_path'] + domain['Domain'] + '_' + keytype.lower() + ".crt.pem"
        key_file = domain['save_path'] + domain['Domain'] + '_' + keytype.lower() + ".key"
        if not os.path.isfile(cert_file):
            check_result = False
            check_msg.append('Certification File can not be found: {}'.format(cert_file))
            continue
        if not os.path.isfile(key_file):
            check_result = False
            check_msg.append('Key File can not be found: {}'.format(key_file))
            continue

        checkCert = MyCertificate(logger=logger,keytype=keytype)
        checkCert.loadCertfromPEMfile(cert_file)
        checkCert.loadPrivateKEYfile(keyfile=key_file)

        # Check if key match with cert
        if not checkCert.checkKeyMatchCert():
            check_result = False
            check_msg.append('Cert File does NOT match with Key File! ({} != {})'.format(cert_file,key_file))
            continue

        # Check Issuer
        if domain['CA'] == 'LetsEncrypt':
            checkIssuerIs = baseconfig['LetsEncrypt']['Issuer_Name']
        elif domain['CA'] == 'LocalCA':
            checkIssuerIs = baseconfig['LocalCA']['Issuer_Name']
        if domain['CA'] is not None:
            if not checkCert.checkCertIssuerContains(checkIssuerIs):
                check_result = False
                check_msg.append('not issued by {})'.format(domain['CA']))

        # Check Time - Valid
        if not checkCert.checkCertTimeValid():
            check_result = False
            check_msg.append('has expired')
        else:
            check_lifetime = False
            check_days_left = False
            if domain['CA'] == 'LetsEncrypt':
                if 'cert_renew_lifetime_left' in baseconfig['LetsEncrypt']:
                    check_lifetime = baseconfig['LetsEncrypt']['cert_renew_lifetime_left']
                elif 'cert_renew_days_left' in baseconfig['LetsEncrypt']:
                    check_days_left = baseconfig['LetsEncrypt']['cert_renew_days_left']
            elif domain['CA'] == 'LocalCA':
                if 'cert_renew_lifetime_left' in baseconfig['LocalCA']:
                    check_lifetime = baseconfig['LocalCA']['cert_renew_lifetime_left']
                elif 'cert_renew_days_left' in baseconfig['LocalCA']:
                    check_days_left = baseconfig['LocalCA']['cert_renew_days_left']
            # Set Fallback Default 10% lifetime left
            if check_lifetime == False and check_days_left == False:
                check_lifetime = 0.1
            if check_days_left:
                if not checkCert.checkCertDaysLeft(check_days_left):
                    check_result = False
                    check_msg.append('has lower then {} days left'.format(check_days_left))
            elif check_lifetime:
                if not checkCert.checkCertLifetimeProceed(check_lifetime):
                    check_result = False
                    check_msg.append('has lower then {0:.0f}% lifetime left'.format(check_lifetime * 100))

        # TODO: Check Subject

        # Check Domain
        if not checkCert.checkCertDomain(domain['Domain']):
            check_result = False
            check_msg.append('Domain does not match (CN)')

        # Check SAN
        (san_result,san_msg) = checkCert.checkCertSAN(domain['Domain'], domain['AlternativeName'])
        if san_result == False:
            check_result = False
            check_msg.append('SubjectAlternativeName does not match: {}'.format(san_msg))

        # TODO: Key Usage
        # TODO: Extended Key Usage

        checkCert.clean_up()

    return (check_result, check_msg)


def useLocalCA(domain, baseconfig):
    # PrePare LetsEncrypt:
    LocalCA = CaLocal(logger=logger,
                      caKeyFile=baseconfig['LocalCA']['Key'],
                      caKeyPassphrase=baseconfig['LocalCA']['KeyPassphrase'],
                      caCertFile=baseconfig['LocalCA']['Cert']
                      )

    # Get Certificate
    res = LocalCA.request_certificate(domain)
    if res:
        res = LocalCA.save_certificates_and_key(domain)

    LocalCA.clean_up()
    return res


def useLetsEncryptCA(domain, baseconfig, Route53, args):
    # PrePare LetsEncrypt:
    leCA = CaLetsEncrypt(logger=logger, stageing=args.stage)
    leCA.loadLEaccountKey(accountKeyFile=baseconfig['LetsEncrypt']['account_key'],
                          accountKeyPassphrase=baseconfig['LetsEncrypt']['account_key_passphrase'])
    leCA.loadJWKToken()
    leCA.acme_Connection()
    leCA.setRoute53(Route53)

    # Challenge ACME
    leCA.get_acme_authorization(domain['Domain'], domain['AlternativeName'])
    if domain['zone'] is not None:
        leCA.setRoute53Zone(domain['zone'])
    leCA.challenge_acme_authorizations(force_renew=domain['force_renew'])

    # Get Certificate
    res = leCA.request_certificate(domain)
    if res:
        res = leCA.save_certificates_and_key(domain)

    leCA.clean_up()
    return res


def validate_and_fillup_with_defaults(domain, baseconfig):
    validation_error = False
    # Check for minimum:
    if 'Domain' not in domain:
        validation_error = "'Domain' is required"

    # Check if exists - otherwise fill with defaults
    if 'CA' not in domain:
        domain['CA'] = baseconfig['Generic']['defaultCA']

    if 'Subject' in domain:
        domain['subject']
    if 'subject' not in domain and domain['CA'] == 'LocalCA':
        domain['subject'] = baseconfig['LocalCA']['cert_subject_default']
    if 'subject' not in domain and domain['CA'] == 'LetsEncrypt':
        # LetsEncrypt does not require any cert subject, because they just create DV certs
        domain['subject'] = {}

    if 'zone' not in domain:
        domain['zone'] = None

    if 'AlternativeName' not in domain:
        domain['AlternativeName'] = []

    if 'force_renew' in domain:
        domain['force_renew'] = str2bool(domain['force_renew'])
    else:
        domain['force_renew'] = False

    if 'keytype' not in domain:
        domain['keytype'] = ['RSA']
        # ECDSA

    if 'Costumer' not in domain:
        domain['Costumer'] = ''

    if 'Stage' not in domain:
        domain['Stage'] = ''

    if 'Sub' not in domain:
        domain['Sub'] = ''

    if 'save_path' not in domain:
        domain['save_path'] = baseconfig['Generic']['certdirectory'] \
                              + '/' + domain['Costumer'] + '/' + domain['Stage'] + '/' + domain['Sub'] + '/'
        domain['save_path'] = domain['save_path'].replace('//', '/')

    return (domain, validation_error)


def logStats():
    logger.info(50 * '=')
    logger.info('Summary Report:')
    logger.info("Total Certificates: {}".format(stats['certificates']))
    logger.info("Count Certificates LetsEncrypt: {}".format(stats['cert_total_LetsEncrypt']))
    logger.info("Count Certificates LocalCA: {}".format(stats['cert_total_LocalCA']))
    logger.info("Total FQDN's (CN + SAN): {}".format(stats['fqdns']))
    logger.info("Certificates with configuration failures: {}".format(stats['cert_config_error']))
    logger.info("Certificates 'valid and matching configuration': {}".format(stats['cert_check_successful']))
    logger.info("Certificates to create/reissue: {}".format(stats['cert_check_renew']))
    logger.info("Certificates successfully created/reissued: {}".format(stats['cert_renew_successful']))
    logger.info("Certificates failed to create/reissue: {}".format(stats['cert_renew_failed']))
    logger.info(50 * '=')

def str2bool(s):
    return str(s).lower() in ("yes", "true", "t", "1")

if __name__ == "__main__":
    main()