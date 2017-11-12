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
from cert_master.configs import BaseConfig, CertConfig


PROG='cert-master'

class CertMaster:
    def __init__(self):
        self

        # Logging
        logformat = '%(asctime)s - %(levelname)s\t- %(module)s ( %(threadName)s )\t- %(message)s'
        logging.basicConfig(level=logging.ERROR, format=logformat)
        logger = logging.getLogger(__name__)

        self.logger = logger

        self.args = None
        self.baseconfig = None
        self.certconfig = None
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

        DESCRIPTION_REGISTER = \
            """
        Register configured account key of given ca
            """

        DESCRIPTION_BOT = \
            """
        Check all configured certificates, if they are created like configured and are valid. If necessary they are created/reissued.
            """

        DESCRIPTION_CERT = \
            """
        Check a specific configured certificates, if it is created like configured and is valid. If necessary it is created/reissued.
            """

        parser = argparse.ArgumentParser(prog=PROG,
                                         description=DESCRIPTION,
                                         formatter_class=Formatter,
                                         )

        subparsers = parser.add_subparsers()

        # Bot - Auto all
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
        bot.add_argument('-v', '--verbose', default=0, action='count', help='Loglevel -vvv for debug')
        bot.set_defaults(mode='bot')

        # Cert - Only one given Domain
        cert = subparsers.add_parser(
            'cert',
            help="Checking specific certificates if renew/reissue is necessary",
            description=DESCRIPTION_CERT,
            formatter_class=Formatter,
        )
        cert.add_argument('--config', '-c', dest="config", help='YAML file with config', required=True)
        cert.add_argument('--cert', '--certificate', dest='certificate', required=True, help='the certificate')
        cert.add_argument('--force', '--force-renew', dest='force_renew', required=False, action='store_true',
                          help='force renew of this certificate')
        cert.add_argument('-v', '--verbose', default=0, action='count', help='Loglevel -vvv for debug')
        cert.set_defaults(mode='cert')


        # Register ACME Key
        register = subparsers.add_parser(
            'register',
            help="Register configured account key of given ca",
            description=DESCRIPTION_CERT,
            formatter_class=Formatter,
        )
        register.add_argument('--config', '-c', dest="config", help='YAML file with config', required=True)
        register.add_argument('--ca', dest='ca', required=True,
                              help='Name of the configured ca where the registration should be done')
        register.add_argument('-v', '--verbose', default=0, action='count', help='Loglevel -vvv for debug')
        register.set_defaults(mode='register')

        # Update Registered ACME Key
        # TODO: Impelment Update existing Registration
        # updateregister = subparsers.add_parser(
        #     'update-register',
        #     help="Register configured account key of given ca",
        #     description=DESCRIPTION_CERT,
        #     formatter_class=Formatter,
        # )
        # updateregister.add_argument('--config', '-c', dest="config", help='YAML file with config', required=True)
        # updateregister.add_argument('--ca', dest='ca', required=True,
        #                       help='Name of the configured ca where the registration should be done')
        # updateregister.add_argument('-v', '--verbose', default=0, action='count', help='Loglevel -vvv for debug')
        # updateregister.set_defaults(mode='updateregister')

        # Deactivate ACME Key
        deactivate = subparsers.add_parser(
            'deactivate',
            help="Deactivate configured account key of given ca",
            description=DESCRIPTION_CERT,
            formatter_class=Formatter,
        )
        deactivate.add_argument('--config', '-c', dest="config", help='YAML file with config', required=True)
        deactivate.add_argument('--ca', dest='ca', required=True,
                              help='Name of the configured ca where the registration should be done')
        deactivate.add_argument('-v', '--verbose', default=0, action='count', help='Loglevel -vvv for debug')
        deactivate.set_defaults(mode='deactivate')

        # Account info
        info = subparsers.add_parser(
            'info',
            help="Shows account information from the service",
            description=DESCRIPTION_INFO,
            formatter_class=Formatter,
        )
        info.add_argument('--config', '-c', dest="config", help='YAML file with config', required=True)
        info.add_argument('--ca', dest='ca', required=True,
                              help='Name of the configured ca where the information should be recived')
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
        elif self.args.mode == 'cert':
            self.cert()
        elif self.args.mode == 'register':
            self.register()
        elif self.args.mode == 'updateregister':
            self.updateregister()
        elif self.args.mode == 'deactivate':
            self.deactivate()

        sys.exit(0)


    def info(self):
        self.logger.debug('CertMaster INFO')
        self._loadConfigs()

        acmeCA = CaLetsEncrypt(logger=self.logger,
                               ca=self.baseconfig.ca[self.baseconfig.ca_by_name[self.args.ca.lower()]])
        acmeCA.loadJWKToken()
        acmeCA.acme_Connection()
        acmeCA.acme_AccountInfo()


    def register(self):
        self.logger.info('CertMaster REGISTER Function')
        self._loadConfigs(load_cert_config=False)

        acmeCA = CaLetsEncrypt(logger=self.logger,
                               ca=self.baseconfig.ca[self.baseconfig.ca_by_name[self.args.ca.lower()]])
        acmeCA.loadJWKToken()
        acmeCA.acme_Connection()
        acmeCA.acme_AccountRegister()


    def updateregister(self):
        self.logger.info('CertMaster UPDATE-REGISTER Function')
        self._loadConfigs(load_cert_config=False)

        acmeCA = CaLetsEncrypt(logger=self.logger,
                               ca=self.baseconfig.ca[self.baseconfig.ca_by_name[self.args.ca.lower()]])
        acmeCA.loadJWKToken()
        acmeCA.acme_Connection()

        acmeCA.acme_AccountInfo()
        acmeCA.acme_AccountUpdateRegistration()


    def deactivate(self):
        self.logger.info('CertMaster DEACTIVATE Function')
        self._loadConfigs(load_cert_config=False)

        acmeCA = CaLetsEncrypt(logger=self.logger,
                               ca=self.baseconfig.ca[self.baseconfig.ca_by_name[self.args.ca.lower()]])
        acmeCA.loadJWKToken()
        acmeCA.acme_Connection()
        if self._confirm_yes("Are you sour that you want to deactivate your acme Account"):
            acmeCA.acme_AccountDeactivate()
        else:
            self.logger.error('Deactivation aborted')



    def cert(self):
        self.logger.debug('CertMaster CERT')
        self.logger.error('Running BOT with filter for given certificates')
        # Set Disable Multiprocessing
        self.args.multiprocessing = False
        self.bot(only_filter_cert=self.args.certificate)
        self.logger.debug('CertMaster CERT finished')


    def bot(self, only_filter_cert=None):
        self.logger.debug('CertMaster BOT')

        self._loadConfigs()

        # TODO: Check Generic Default Config
        # TODO: Check CAs Default Config
        #self._check_baseconfig()

        # TODO: Check LE Account/Connection
        # TODO: Check AWS Route53 Account/Connection

        # Connect to Route53:
        self._ConnectDNSRoute53()

        self.logger.info('startup complete, checking now for certificates')

        threading_tasks = []

        for domain in self.certconfig:

            if only_filter_cert:
                if only_filter_cert != domain.cert:
                    continue
                else:
                    # Overwrite force_renew with given args option
                    if self.args.force_renew:
                        domain.force_renew = self.args.force_renew

            self.logger.info(50 * '=')

            # Validate Cert Config / Append Defaults
            (domain, validation_error) = self._validate_and_fillup_with_defaults(domain)

            self.baseconfig.stats_ca_increment_certs(domain.ca, increment=1)
            self.baseconfig.stats_ca_increment_fqdns(domain.ca, increment=len(domain.san))

            if validation_error is not False:
                self.logger.error('Vailidation failure: {}'.format(validation_error))
                if domain.cert is None:
                    self.logger.error('skipping faulty configuration! {}'.format(domain))
                else:
                    self.logger.error('skipping "{}" certificate!'.format(domain.cert))
                self.baseconfig.stats_ca_increment_config_error(domain.ca, increment=1)
                continue

            self.logger.info('Certificat (CN/Domain): {}'.format(domain.cert))
            self.logger.debug('Domainconfig: {}'.format(domain))

            # Create Save Directory if it not exists:
            try:
                os.makedirs(domain.file_save_path, exist_ok=True)
            except Exception as e:
                self.logger.error('could not create directory "{}" for certificate: {}'.format(domain.file_save_path, e))
                self.logger.error('skipping "{}" certificate!'.format(domain.cert))
                continue

            # Check if Create or Renew Certificate
            (check_result, check_msg) = self._checkCertificate(domain)
            if check_result is True and domain.force_renew == False:
                self.logger.info('Certificate "{}" is valid and matches configuration.'.format(domain.cert))
                self.baseconfig.stats_ca_increment_check_successful(domain.ca)
            else:
                for msg in check_msg:
                    self.logger.warning('Certificate "{}" - {}'.format(domain.cert, msg))
                if domain.force_renew == True:
                    self.logger.warning('Certificate "{}" - Forced to renew'.format(domain.cert))
                self.logger.info('Certificate "{}" has to be created/reissued.'.format(domain.cert))
                self.baseconfig.stats_ca_increment_to_renew(domain.ca)

                # Create or Renew Certificate
                if self.args.multiprocessing:
                    threading_tasks.append(domain)
                else:
                    self._createCertificate(domain)


        # Run Certificate Creation in parallel if configured
        if self.args.multiprocessing and len(threading_tasks) > 0:
            self.logger.info(50 * '=')
            max_threads = 24
            threads = max_threads if len(threading_tasks) > max_threads else len(threading_tasks)
            pool = ThreadPool(threads)

            start = time.time()
            results = pool.map(self._createCertificate, threading_tasks)
            # close the pool and wait for the work to finish
            pool.close()
            pool.join()
            end = time.time()
            duration = int(float(end - start))
            self.logger.debug("Multiprocessing with {0} Threads finished - Duration: {1}".format(threads, timedelta(seconds=duration)))

        # No Stats if in 'cert' Mode
        if only_filter_cert == None:
            rc = self._logStats()

            if rc == 'error':
                self.logger.info(PROG + ' finished with errors - Quit')
                sys.exit(2)
            elif rc == 'warn':
                self.logger.info(PROG + ' finished with warnings - Quit')
                sys.exit(1)
            else:
                self.logger.info(PROG + ' finished - Quit')
                sys.exit(0)

    def _ConnectDNSRoute53(self):
        try:
            if self.baseconfig.dns_route53_aws_accesskey and self.baseconfig.dns_route53_aws_secretkey:
                self.logger.debug('connecting to aws route53 with accesskey: {}'.format(self.baseconfig.dns_route53_aws_accesskey))
                self.DNS_Route53 = r53(self.baseconfig.dns_route53_aws_accesskey, self.baseconfig.dns_route53_aws_secretkey, logger=self.logger)
            else:
                self.DNS_Route53 = r53(logger=self.logger)
            self.DNS_Route53.enable_connection()
            return True
        except:
            return False


    def _loadConfigs(self, load_cert_config=True):
        self.logger.debug('using config file: {}'.format(self.args.config))
        with open(self.args.config, 'r') as fstream:
            self.baseconfig = BaseConfig(logger=self.logger, BaseConfig=yaml.load(fstream))

        # loading yaml config for domains
        if load_cert_config:
            self.certconfig = []
            files = os.listdir(self.baseconfig.config_directory)
            for f in files:
                if f.endswith('.yaml'):
                    conffile = open(self.baseconfig.config_directory + f, "r")
                    docs = yaml.load_all(conffile)
                    for doc in docs:
                        # TODO: Filter if not BOT mode
                        if doc is not None:
                            self.certconfig.append(CertConfig(CertConfig=doc, BaseConfig=self.baseconfig))


    def _createCertificate(self, domain):
        self.logger.info('Requesting Certificate for "{}"'.format(domain.cert))

        ca_type = self.baseconfig.get_ca_type(domain.ca)
        self.logger.info(
            'Requesting Certificate signed by CA: "{}"'.format(self.baseconfig.get_ca_issuer_name(domain.ca)))

        if ca_type == "acme":
            res = self._useLetsEncryptCA(domain)
        elif ca_type == "local":
            res = self._useLocalCA(domain)
        else:
            self.logger.error('Unknown CA "{}" requested for Certificate signing!'.format(domain.ca))

        if res == False:
            self.baseconfig.stats_ca_increment_renew_failed(domain.ca)
            self.logger.error('Requesting Certificate for "{}" failed'.format(domain.cert))
        else:
            self.baseconfig.stats_ca_increment_renew_success(domain.ca)
            self.logger.info('Requesting Certificate for "{}" finished successfully'.format(domain.cert))


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

        for keytype in domain.key_type:
            cert_file = domain.file_save_path + domain.cert + '_' + keytype.lower() + ".crt.pem"
            key_file = domain.file_save_path + domain.cert + '_' + keytype.lower() + ".key"
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
            checkIssuerIs = self.baseconfig.get_ca_issuer_name(domain.ca)
            if checkIssuerIs is not None:
                if not checkCert.checkCertIssuerContains(checkIssuerIs):
                    check_result = False
                    check_msg.append('not issued by {})'.format(domain['CA']))

            # Check Time - Valid
            if not checkCert.checkCertTimeValid():
                check_result = False
                check_msg.append('has expired')
            else:
                check_lifetime = self.baseconfig.get_ca_renew_lifetime_left(domain.ca)
                check_days_left = self.baseconfig.get_ca_renew_days_left(domain.ca)
                cert_validity = checkCert.getCertValidity()

                # TODO: set defalut on configs -> CaConfig if nothing is specificed
                # Set Fallback Default 10% lifetime left
                if check_lifetime == None and check_days_left == None:
                    check_lifetime = 0.1

                if check_lifetime:
                    if not checkCert.checkCertLifetimeProceed(check_lifetime):
                        check_result = False
                        check_msg.append('has lower then {0:.0f}% lifetime left'.format(check_lifetime * 100))
                elif check_days_left and cert_validity > check_days_left:
                    if not checkCert.checkCertDaysLeft(check_days_left):
                        check_result = False
                        check_msg.append('has lower then {} days left'.format(check_days_left))
                elif check_days_left and cert_validity < check_days_left:
                    # When cert validity is lower then the ca configured minimum day - check lifetime 10% as fallback
                    check_lifetime = 0.1
                    if not checkCert.checkCertLifetimeProceed(check_lifetime):
                        check_result = False
                        check_msg.append('has lower then {0:.0f}% lifetime left'.format(check_lifetime * 100))
                        check_msg.append('certificate validity is lower then the days ' +
                                         'configured at CA level (cert_expire_days)!')

            # TODO: Check Subject

            # Check Domain
            if not checkCert.checkCertDomain(domain.cert):
                check_result = False
                check_msg.append('Domain does not match (CN)')

            # Check SAN
            (san_result, san_msg) = checkCert.checkCertSAN(domain.cert, domain.san)
            if san_result == False:
                check_result = False
                check_msg.append('SubjectAlternativeName does not match: {}'.format(san_msg))

            # TODO: Check Key Usage
            # TODO: Check Extended Key Usage

            checkCert.clean_up()

        return (check_result, check_msg)


    def _useLocalCA(self, domain):
        # PrePare LetsEncrypt:
        LocalCA = CaLocal(logger=self.logger, ca=self.baseconfig.ca[self.baseconfig.ca_by_name[domain.ca]])

        # Get Certificate
        res = LocalCA.request_certificate(domain)
        if res:
            res = LocalCA.save_certificates_and_key(domain)

        LocalCA.clean_up()
        return res


    def _useLetsEncryptCA(self, domain):
        # PrePare LetsEncrypt:
        leCA = CaLetsEncrypt(logger=self.logger, ca=self.baseconfig.ca[self.baseconfig.ca_by_name[domain.ca]])
        leCA.loadJWKToken()
        leCA.acme_Connection()

        leCA.setRoute53(self.DNS_Route53)

        # Challenge ACME
        leCA.get_acme_authorization(domain.cert, domain.san)
        if domain.dns_zone is not None:
            leCA.setRoute53Zone(domain.dns_zone)

        # TODO: Make Option for debug:
        cert_force_renew_is_also_force_renew_authorizations = False
        if cert_force_renew_is_also_force_renew_authorizations:
            leCA.challenge_acme_authorizations(force_renew_authorizations=domain.force_renew)
        else:
            leCA.challenge_acme_authorizations()

        # Get Certificate
        res = leCA.request_certificate(domain)
        if res:
            res = leCA.save_certificates_and_key(domain)

        leCA.clean_up()
        return res


    def _validate_and_fillup_with_defaults(self, domain):
        validation_error = False
        # Check for minimum:
        if domain.cert == None:
            validation_error = "'Domain' is required"

        # Todo: This shoud move to 'configs.CertConfig'
        if domain.subject is None and domain.ca == 'LocalCA'.lower():
            domain.subject = self.baseconfig.ca[self.baseconfig.ca_by_name['localca']].cert_default_subject
        if domain.subject is not None and domain.ca == 'LetsEncrypt'.lower():
            # LetsEncrypt does not require any cert subject, because they just create DV certs
            domain.subject = None

        return (domain, validation_error)


    def _confirm_yes(self,question):
        """
        Ask user to enter Y or N (case-insensitive).
        :return: True if the answer is Y.
        :rtype: bool
        """
        answer = ""
        while answer not in ["y", "n"]:
            answer = input(str(question)+" [y/n]? ").lower()
        return answer == "y"


    def _logStats(self):
        self.logger.info(50 * '=')
        self.logger.info('CA Report:')
        total_stats = {}
        total_stats['certs'] = 0
        total_stats['fqdn'] = 0
        total_stats['check_successful'] = 0
        total_stats['to_renew'] = 0
        total_stats['renew_success'] = 0
        total_stats['renew_failed'] = 0
        total_stats['config_error'] = 0
        for ca in self.baseconfig.ca:
            self.logger.info('CA "{}" Certificates: {}'.format(ca.issuer_name, ca.stats.certs))
            total_stats['certs'] += ca.stats.certs
            self.logger.info('CA "{}" FQDNs: {}'.format(ca.issuer_name, ca.stats.fqdn))
            total_stats['fqdn'] += ca.stats.fqdn
            self.logger.info('CA "{}" Certificates check successful(valid and matching configuration): {}'.format(ca.issuer_name, ca.stats.check_successful))
            total_stats['check_successful'] += ca.stats.check_successful
            self.logger.info('CA "{}" Certificates to create/reissue: {}'.format(ca.issuer_name, ca.stats.to_renew))
            total_stats['to_renew'] += ca.stats.to_renew
            self.logger.info('CA "{}" Certificates renew successful: {}'.format(ca.issuer_name, ca.stats.renew_success))
            total_stats['renew_success'] += ca.stats.renew_success
            self.logger.info('CA "{}" Certificates renew failed: {}'.format(ca.issuer_name, ca.stats.renew_failed))
            total_stats['renew_failed'] += ca.stats.renew_failed
            self.logger.info('CA "{}" Certificates with configuration failure: {}'.format(ca.issuer_name, ca.stats.config_error))
            total_stats['config_error'] += ca.stats.config_error

        self.logger.info(50 * '=')
        self.logger.info('Summary Report:')
        self.logger.info('Total Certificates: {}'.format(total_stats['certs']))
        self.logger.info('Total FQDNs: {}'.format(total_stats['fqdn']))
        self.logger.info('Total Certificates check successful(valid and matching configuration): {}'.format(total_stats['check_successful']))
        self.logger.info('Total Certificates to create/reissue: {}'.format(total_stats['to_renew']))
        self.logger.info('Total Certificates renew successful: {}'.format(total_stats['renew_success']))
        self.logger.info('Total Certificates renew failed: {}'.format(total_stats['renew_failed']))
        self.logger.info('Total Certificates with configuration failure: {}'.format(total_stats['config_error']))
        self.logger.info(50 * '=')

        if total_stats['renew_failed'] > 0:
            return 'error'
        elif total_stats['config_error'] > 0:
            return 'warn'
        else:
            return True

