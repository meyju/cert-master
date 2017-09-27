#!/usr/bin/env python
# _*_ coding: utf-8

# See LICENSE for details.

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

PROG='cert-master'

class CertMaster:
    def __init__(self):
        self

        # Logging
        logformat = '%(asctime)s - %(levelname)s\t- %(module)s ( %(threadName)s )\t- %(message)s'
        logging.basicConfig(level=logging.ERROR, format=logformat)
        logger = logging.getLogger(__name__)

        self.logger = logger
        self.stats =  {}
        self.stats['certificates'] = 0
        self.stats['fqdns'] = 0
        self.stats['cert_config_error'] = 0
        self.stats['cert_total_LetsEncrypt'] = 0
        self.stats['cert_total_LocalCA'] = 0
        self.stats['cert_check_successful'] = 0
        self.stats['cert_check_renew'] = 0
        self.stats['cert_renew_successful'] = 0
        self.stats['cert_renew_failed'] = 0

        self.args = None
        self.baseconfig = None
        self.domainconfig = None
        self.DNS_Route53 = None

        logger.info('startup program ' + PROG)


    def defineParser(self):
        '''
        Definition if all commandline Flags
        '''

        class Formatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
            pass

        DESCRIPTION = \
            """
        cert-master manages certificates in a central system.
    
        Certificates are signed by Let's Encrypt via DNS-01 challenge or by a LocalCA. 
    
        Call a command with -h for more instructions.
            """

        DESCRIPTION_INFO = \
            """
        Shows raw registration info for the current account.
            """

        DESCRIPTION_BOT = \
            """
        Check all configured certificates, if they are created like configured and are valid. If necessary they are created/reissued.
            """

        parser = argparse.ArgumentParser(prog=PROG,
                                         description=DESCRIPTION,
                                         formatter_class=Formatter,
                                         )

        subparsers = parser.add_subparsers()

        # Auto
        bot = subparsers.add_parser(
            'bot',
            help="Checking all configured certificates and renew/reissue if necessary",
            description=DESCRIPTION_BOT,
            formatter_class=Formatter,
        )
        bot.add_argument('--config', '-c', dest="config", help='YAML file with config', required=True)
        bot.add_argument('--no-multiprocessing', dest='multiprocessing', required=False, action='store_false',
                         help='work without Multitasking')
        bot.add_argument('--threads', type=int, default=10, required=False, help='how many threads should be used')
        bot.add_argument('--stage', dest='stage', required=False, action='store_false',
                         help='switch to staging mode')
        bot.add_argument('-v', '--verbose', default=0, action='count', help='Loglevel -vvv for debug')
        bot.set_defaults(mode='bot')

        # Account info
        info = subparsers.add_parser(
            'info',
            help="Shows account information from the service",
            description=DESCRIPTION_INFO,
            formatter_class=Formatter,
        )
        info.add_argument('--config', '-c', dest="config", help='YAML file with config', required=True)
        info.add_argument('-v', '--verbose', default=0, action='count', help='Loglevel -vvv for debug')
        info.set_defaults(mode='info')

        args = parser.parse_args()
        if not hasattr(args, 'mode'):
            parser.print_help()
            sys.exit(1)

        self.args = parser.parse_args()

        if self.args.verbose == 0:
            self.logger.setLevel(logging.WARN)
        elif self.args.verbose == 1:
            self.logger.setLevel(logging.INFO)
        elif self.args.verbose >= 2:
            self.logger.setLevel(logging.DEBUG)

        return self.args


    def main(self):
        # Main Prog
        self.defineParser()
        if self.args.mode == 'info':
            self.info()
        elif self.args.mode == 'bot':
            self.bot()
        elif self.args.mode == 'register':
            self.register()
        sys.exit(0)


    def info(self):
        self.logger.debug('CertMaster INFO')
        self._loadConfigs()
        leCA = CaLetsEncrypt(logger=self.logger)
        leCA.loadLEaccountKey(accountKeyFile=self.baseconfig['LetsEncrypt']['account_key'],
                              accountKeyPassphrase=self.baseconfig['LetsEncrypt']['account_key_passphrase'])
        leCA.loadJWKToken()
        leCA.acme_Connection()
        leCA.acme_AccountInfo()


    def register(self):
        self.logger.error('CertMaster REGISTER Function - NOT Implementet yet')


    def bot(self):
        self.logger.debug('CertMaster BOT')

        self._loadConfigs()

        # TODO: Check Generic Default Config
        # TODO: Check CAs Default Config

        # TODO: Check LE Account/Connection
        # TODO: Check AWS Route53 Account/Connection

        # Connect to Route53:
        self._ConnectDNSRoute53()



        self.logger.info('starting complete, checking now for certificates')

        threading_tasks = []

        for domain in self.domainconfig:
            self.stats['certificates'] += 1
            self.logger.info(50 * '=')

            # Append Defaults
            (domain, validation_error) = self._validate_and_fillup_with_defaults(domain)
            if domain['CA'] == "LetsEncrypt":
                self.stats['cert_total_LetsEncrypt'] += 1
            elif domain['CA'] == "LocalCA":
                self.stats['cert_total_LocalCA'] += 1
            if validation_error is not False:
                self.logger.error('Vailidation failure: {}'.format(validation_error))
                if 'Domain' not in domain:
                    self.logger.error('skipping faulty configuration! {}'.format(domain))
                else:
                    self.logger.error('skipping "{}" certificate!'.format(domain['Domain']))

                self.stats['cert_config_error'] += 1
                continue

            self.logger.info('Certificat (CN/Domain): {}'.format(domain['Domain']))
            self.logger.debug('Domainconfig: {}'.format(domain))
            self.stats['fqdns'] += (1 + len(domain['AlternativeName']))

            # Create Save Directory if it not exists:
            try:
                os.makedirs(domain['save_path'], exist_ok=True)
            except Exception as e:
                self.logger.error('could not create directory "{}" for certificate: {}'.format(domain['save_path'], e))
                self.logger.error('skipping "{}" certificate!'.format(domain['Domain']))
                continue

            # Check if Create or Renew Certificate
            (check_result, check_msg) = self._checkCertificate(domain)
            if check_result is True and domain['force_renew'] == False:
                self.logger.info('Certificate "{}" is valid and matches configuration.'.format(domain['Domain']))
                self.stats['cert_check_successful'] += 1
                continue
            else:
                for msg in check_msg:
                    self.logger.warning('Certificate "{}" - {}'.format(domain['Domain'], msg))
                if domain['force_renew'] == True:
                    self.logger.warning('Certificate "{}" - Forced to renew'.format(domain['Domain']))
                self.logger.info('Certificate "{}" has to be created/reissued.'.format(domain['Domain']))
                self.stats['cert_check_renew'] += 1

            # Create or Renew Certificate
            if self.args.multiprocessing:
                threading_tasks.append(domain)
            else:
                self._createCertificate(domain)

            # Reset for next Loop
            domain = None

        # Run Certificate Creation in parallel if configured
        if self.args.multiprocessing and len(threading_tasks) > 0:
            self.logger.info(50 * '=')
            max_threads = 20
            threads = max_threads if len(threading_tasks) > max_threads else len(threading_tasks)
            pool = ThreadPool(threads)

            start = time.time()
            results = pool.map(self._createCertificate, threading_tasks)
            # close the pool and wait for the work to finish
            pool.close()
            pool.join()
            end = time.time()
            duration = int(float(end - start))
            self.logger.info("Multiprocessing with {0} Threads - Duration: {1}".format(threads, timedelta(seconds=duration)))

        self._logStats()

        if self.stats['cert_renew_failed'] > 0:
            self.logger.info(PROG + ' finished with errors - Quit')
            sys.exit(2)
        elif self.stats['cert_config_error'] > 0:
            self.logger.info(PROG + ' finished with warnings - Quit')
            sys.exit(1)
        else:
            self.logger.info(PROG + ' finished - Quit')
            sys.exit(0)

    def _ConnectDNSRoute53(self):
        try:
            if self.baseconfig['Route53']['aws_accesskey'] and self.baseconfig['Route53']['aws_secretkey']:
                self.logger.debug('aws accesskey: {}'.format(self.baseconfig['Route53']['aws_accesskey']))
                self.DNS_Route53 = r53(self.baseconfig['Route53']['aws_accesskey'], self.baseconfig['Route53']['aws_secretkey'], logger=self.logger)
            else:
                self.DNS_Route53 = r53(logger=self.logger)
            self.DNS_Route53.enable_connection()
            return True
        except:
            return False


    def _loadConfigs(self):
        self.logger.debug('using config file: {}'.format(self.args.config))
        with open(self.args.config, 'r') as fstream:
            self.baseconfig = yaml.load(fstream)

        # loading yaml config for domains
        self.domainconfig = []
        files = os.listdir(self.baseconfig['Generic']['confdirectory'])
        for f in files:
            if f.endswith('.yaml'):
                conffile = open(self.baseconfig['Generic']['confdirectory'] + f, "r")
                docs = yaml.load_all(conffile)
                for doc in docs:
                    self.domainconfig.append(doc)

        # Remove 'None' elements from domainconfig <- happens if there are yaml splits '---' without content
        self.domainconfig = list(filter(None.__ne__, self.domainconfig))


    def _createCertificate(self, domain):
        self.logger.info('Requesting Certificate for "{}"'.format(domain['Domain']))
        if domain['CA'] == "LetsEncrypt":
            self.logger.info('Requesting Certificate signed by CA: LetsEncrypt')
            res = self._useLetsEncryptCA(domain)
            if res == False:
                self.stats['cert_renew_failed'] += 1
            else:
                self.stats['cert_renew_successful'] += 1
        elif domain['CA'] == "LocalCA":
            self.logger.info('Requesting Certificate signed by CA: LocalCA')
            res = self._useLocalCA(domain)
            if res == False:
                self.stats['cert_renew_failed'] += 1
            else:
                self.stats['cert_renew_successful'] += 1
        else:
            self.logger.error('Unknown CA "{}" requested for Certificate signing!'.format(domain['CA']))

        self.logger.info('Requesting Certificate for "{}" finished'.format(domain['Domain']))

    def _checkCertificate(self, domain):
        ''' Checking if the certificate is valid and matches configuration
            :param dict domain: Dictionary with all required information's for the domain
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

            checkCert = MyCertificate(logger=self.logger, keytype=keytype)
            checkCert.loadCertfromPEMfile(cert_file)
            checkCert.loadPrivateKEYfile(keyfile=key_file)

            # Check if key match with cert
            if not checkCert.checkKeyMatchCert():
                check_result = False
                check_msg.append('Cert File does NOT match with Key File! ({} != {})'.format(cert_file, key_file))
                continue

            # Check Issuer
            if domain['CA'] == 'LetsEncrypt':
                checkIssuerIs = self.baseconfig['LetsEncrypt']['Issuer_Name']
            elif domain['CA'] == 'LocalCA':
                checkIssuerIs = self.baseconfig['LocalCA']['Issuer_Name']
            else:
                checkIssuerIs = None
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
                    if 'cert_renew_lifetime_left' in self.baseconfig['LetsEncrypt']:
                        check_lifetime = self.baseconfig['LetsEncrypt']['cert_renew_lifetime_left']
                    elif 'cert_renew_days_left' in self.baseconfig['LetsEncrypt']:
                        check_days_left = self.baseconfig['LetsEncrypt']['cert_renew_days_left']
                elif domain['CA'] == 'LocalCA':
                    if 'cert_renew_lifetime_left' in self.baseconfig['LocalCA']:
                        check_lifetime = self.baseconfig['LocalCA']['cert_renew_lifetime_left']
                    elif 'cert_renew_days_left' in self.baseconfig['LocalCA']:
                        check_days_left = self.baseconfig['LocalCA']['cert_renew_days_left']
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
            (san_result, san_msg) = checkCert.checkCertSAN(domain['Domain'], domain['AlternativeName'])
            if san_result == False:
                check_result = False
                check_msg.append('SubjectAlternativeName does not match: {}'.format(san_msg))

            # TODO: Key Usage
            # TODO: Extended Key Usage

            checkCert.clean_up()

        return (check_result, check_msg)

    def _useLocalCA(self, domain):
        # PrePare LetsEncrypt:
        LocalCA = CaLocal(logger=self.logger,
                          caKeyFile=self.baseconfig['LocalCA']['Key'],
                          caKeyPassphrase=self.baseconfig['LocalCA']['KeyPassphrase'],
                          caCertFile=self.baseconfig['LocalCA']['Cert']
                          )

        # Get Certificate
        res = LocalCA.request_certificate(domain)
        if res:
            res = LocalCA.save_certificates_and_key(domain)

        LocalCA.clean_up()
        return res

    def _useLetsEncryptCA(self, domain):
        # PrePare LetsEncrypt:
        leCA = CaLetsEncrypt(logger=self.logger, stageing=self.args.stage)
        leCA.loadLEaccountKey(accountKeyFile=self.baseconfig['LetsEncrypt']['account_key'],
                              accountKeyPassphrase=self.baseconfig['LetsEncrypt']['account_key_passphrase'])
        leCA.loadJWKToken()
        leCA.acme_Connection()
        leCA.setRoute53(self.DNS_Route53)

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

    def _validate_and_fillup_with_defaults(self, domain):
        validation_error = False
        # Check for minimum:
        if 'Domain' not in domain:
            validation_error = "'Domain' is required"

        # Check if exists - otherwise fill with defaults
        if 'CA' not in domain:
            domain['CA'] = self.baseconfig['Generic']['defaultCA']

        if 'Subject' in domain:
            domain['subject']
        if 'subject' not in domain and domain['CA'] == 'LocalCA':
            domain['subject'] = self.baseconfig['LocalCA']['cert_subject_default']
        if 'subject' not in domain and domain['CA'] == 'LetsEncrypt':
            # LetsEncrypt does not require any cert subject, because they just create DV certs
            domain['subject'] = {}

        if 'zone' not in domain:
            domain['zone'] = None

        if 'AlternativeName' not in domain:
            domain['AlternativeName'] = []

        if 'force_renew' in domain:
            domain['force_renew'] = self._str2bool(domain['force_renew'])
        else:
            domain['force_renew'] = False

        if 'keytype' not in domain:
            domain['keytype'] = ['RSA']
            # TODO: ECDSA keytype

        if 'Costumer' not in domain:
            domain['Costumer'] = ''

        if 'Stage' not in domain:
            domain['Stage'] = ''

        if 'Sub' not in domain:
            domain['Sub'] = ''

        if 'save_path' not in domain:
            domain['save_path'] = self.baseconfig['Generic']['certdirectory'] \
                                  + '/' + domain['Costumer'] + '/' + domain['Stage'] + '/' + domain['Sub'] + '/'
            domain['save_path'] = domain['save_path'].replace('//', '/')

        return (domain, validation_error)

    def _logStats(self):
        self.logger.info(50 * '=')
        self.logger.info('Summary Report:')
        self.logger.info("Total Certificates: {}".format(self.stats['certificates']))
        self.logger.info("Count Certificates LetsEncrypt: {}".format(self.stats['cert_total_LetsEncrypt']))
        self.logger.info("Count Certificates LocalCA: {}".format(self.stats['cert_total_LocalCA']))
        self.logger.info("Total FQDN's (CN + SAN): {}".format(self.stats['fqdns']))
        self.logger.info("Certificates with configuration failures: {}".format(self.stats['cert_config_error']))
        self.logger.info("Certificates 'valid and matching configuration': {}".format(self.stats['cert_check_successful']))
        self.logger.info("Certificates to create/reissue: {}".format(self.stats['cert_check_renew']))
        self.logger.info("Certificates successfully created/reissued: {}".format(self.stats['cert_renew_successful']))
        self.logger.info("Certificates failed to create/reissue: {}".format(self.stats['cert_renew_failed']))
        self.logger.info(50 * '=')

    def _str2bool(self, s):
        return str(s).lower() in ("yes", "true", "t", "1")