#!/usr/bin/env python
# _*_ coding: utf-8

# See LICENSE for details.


class BaseConfig:
    def __init__(self, logger=None, BaseConfig=None):
        self
        self.logger = logger
        self.stageing = False
        self.config_directory = None
        self.default_key_type = 'RSA'

        # Storage
        self.storage_mode = 'file'
        self.storage_file_directory = None

        # DNS
        self.dns_provider = 'route53'
        self.dns_route53_aws_accesskey = None
        self.dns_route53_aws_secretkey = None

        # CA
        self.default_ca = 'LetsEncrypt'.lower()
        self.ca = []
        self.ca_by_name = {}


        if BaseConfig is not None:
            self.loadBaseConfig(self._LowerCaseOfKey(BaseConfig))

    def loadBaseConfig(self,BaseConfig):

        self.logger.info('Loading Base Config')
        self.config_directory = BaseConfig['generic']['confdirectory']

        if 'defaultca' in BaseConfig['generic']:
            self.default_ca = BaseConfig['generic']['defaultca'].lower()

        # Storage
        if 'certdirectory' in BaseConfig['generic']:
            self.storage_file_directory = BaseConfig['generic']['certdirectory']

        # DNS
        if 'aws_accesskey' in BaseConfig['route53']:
            self.dns_route53_aws_accesskey = BaseConfig['route53']['aws_accesskey']
        if 'aws_secretkey' in BaseConfig['route53']:
            self.dns_route53_aws_secretkey = BaseConfig['route53']['aws_secretkey']

        # CA Config
        increment=0
        for key, value in BaseConfig['ca'].items():
            if 'type' in value:
                if value['type'].lower() == 'local':
                    self.ca.append(CaLocalConfig(key, value))
                elif value['type'].lower() == 'acme':
                    self.ca.append(CaACMEConfig(key, value))
                else:
                    self.ca.append(CaConfig(key,value))
                self.ca_by_name[key] = increment
            increment += 1

        return True

    def _LowerCaseOfKey(self,x, recusiv=True):
        r = {}
        for k, v in x.items():
            if isinstance(v, dict) and recusiv == True:
                v = self._LowerCaseOfKey(v)
            if isinstance(k, str):
                r[k.lower()] = v
            else:
                r[k] = v
        return r


    def stats_ca_increment_certs(self, ca_name, increment=1):
        try:
            self.ca[self.ca_by_name[ca_name]].stats.increment_certs(increment)
        except Exception as e:
            pass

    def stats_ca_increment_fqdns(self, ca_name, increment=1):
        try:
            self.ca[self.ca_by_name[ca_name]].stats.increment_fqdn(increment)
        except Exception as e:
            pass

    def stats_ca_increment_to_renew(self, ca_name, increment=1):
        try:
            self.ca[self.ca_by_name[ca_name]].stats.increment_to_renew(increment)
        except Exception as e:
            pass

    def stats_ca_increment_renew_success(self, ca_name, increment=1):
        try:
            self.ca[self.ca_by_name[ca_name]].stats.increment_renew_success(increment)
        except Exception as e:
            pass

    def stats_ca_increment_renew_failed(self, ca_name, increment=1):
        try:
            self.ca[self.ca_by_name[ca_name]].stats.increment_renew_failed(increment)
        except Exception as e:
            pass

    def stats_ca_increment_check_successful(self, ca_name, increment=1):
        try:
            self.ca[self.ca_by_name[ca_name]].stats.increment_check_successful(increment)
        except Exception as e:
            pass

    def stats_ca_increment_config_error(self, ca_name, increment=1):
        try:
            self.ca[self.ca_by_name[ca_name]].stats.increment_config_error(increment)
        except Exception as e:
            pass

    def get_ca_issuer_name(self,ca_name):
        try:
            return self.ca[self.ca_by_name[ca_name]].issuer_name
        except Exception as e:
            return None

    def get_ca_renew_lifetime_left(self,ca_name):
        try:
            return self.ca[self.ca_by_name[ca_name]].cert_renew_lifetime_left
        except Exception as e:
            return None

    def get_ca_renew_days_left(self,ca_name):
        try:
            return self.ca[self.ca_by_name[ca_name]].cert_renew_days_left
        except Exception as e:
            return None

    def clean_up(self):
        self = None


class CaConfig:
    def __init__(self, name, CaConfig):
        self
        self.ca_name = name
        self.issuer_name = None

        # Certificate Settings
        self.cert_renew_lifetime_left = None
        self.cert_renew_days_left = None

        self.stats = CaStats()

        if CaConfig is not None:
            self.loadCaConfig(CaConfig)


    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)


    def loadCaConfig(self,CaConfig):

        self.issuer_name = CaConfig['issuer_name']

        if 'cert_renew_lifetime_left' in CaConfig:
            # Interpret Percentage Value for 'Lifetime Left'
            if isinstance(CaConfig['cert_renew_lifetime_left'], float) or isinstance(
                CaConfig['cert_renew_lifetime_left'], int):
                    self.cert_renew_lifetime_left = CaConfig['cert_renew_lifetime_left']
            else:
                if isinstance(CaConfig['cert_renew_lifetime_left'], str) and '%' in CaConfig['cert_renew_lifetime_left']:
                    self.cert_renew_lifetime_left = float(
                        CaConfig['cert_renew_lifetime_left'].strip(' ').strip('%')) / 100.0


        if 'cert_renew_days_left' in CaConfig:
            self.cert_renew_days_left = CaConfig['cert_renew_days_left']


class CaLocalConfig(CaConfig):
    def __init__(self, name, CaConfig):
        super().__init__(name, CaConfig)
        self.ca_type = 'local'
        self.cert_expire_days_default = 90
        self.cert_expire_days_min = 1
        self.cert_expire_days_max = 365*2

        self.cert_default_subject = None

        self.key = None
        self.key_passphrase = None
        self.cert = None

        if 'cert_subject_default' in CaConfig:
            self.loadSubject(CaConfig['cert_subject_default'])

        if CaConfig is not None:
            self.loadCaLocalConfig(CaConfig)

    def loadCaLocalConfig(self, CaConfig):
        if 'key' in CaConfig:
            self.key = CaConfig['key']
        if 'key_passphrase' in CaConfig:
            self.key_passphrase = CaConfig['key_passphrase']
        elif 'keypassphrase' in CaConfig:
            self.key_passphrase = CaConfig['keypassphrase']
        if 'cert' in CaConfig:
            self.cert = CaConfig['cert']

    def loadSubject(self, subject):
        self.cert_default_subject = CertSubject(subject)


class CaACMEConfig(CaConfig):
    def __init__(self, name, CaConfig):
        super().__init__(name, CaConfig)
        self.ca_type = 'ACME'

        # Authentification
        self.account_key = None
        self.account_key_passphrase = None

        if CaConfig is not None:
            self.loadCaACMEConfig(CaConfig)

    def loadCaACMEConfig(self, CaConfig):
        if 'account_key' in CaConfig:
            self.account_key = CaConfig['account_key']
        if 'account_key_passphrase' in CaConfig:
            self.account_key_passphrase = CaConfig['account_key_passphrase']


class CertSubject:
    def __init__(self, subject=None):
        self
        self.organization = None
        self.organizational_unit = None
        self.country = None
        self.state = None
        self.locality = None
        self.email = None

        if subject is not None:
            self.loadSubject(subject)


    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)


    def loadSubject(self, subject):
        if 'organization' in subject:
            self.organization = subject['organization']
        if 'organizational_unit' in subject:
            self.organizational_unit = subject['organizational_unit']
        if 'country' in subject:
            self.country = subject['country']
        if 'state' in subject:
            self.state = subject['state']
        if 'locality' in subject:
            self.locality = subject['locality']
        if 'email' in subject:
            self.email = subject['email']


class CertConfig:
    def __init__(self, CertConfig=None, BaseConfig=None):
        self
        self.cert = None
        self.san = []
        self.subject = None
        self.ca = None

        self.costumer = None
        self.stage = None
        self.sub = None
        self.file_save_path = None

        self.validity_days = None
        self.key_type = ['RSA']
        self.reuse_key = False

        self.dns_zone = None

        self.force_renew = False

        if CertConfig is not None:
            self.loadCertConfig(self._LowerCaseOfKey(CertConfig),BaseConfig)


    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)


    def loadCertConfig(self,CertConfig,BaseConfig):

        if 'domain' in CertConfig:
            self.cert = CertConfig['domain']
            self.san.append(self.cert)

        if 'alternativename' in CertConfig:
            for domain in CertConfig['alternativename']:
                self.san.append(domain)
        elif 'subjectalternativename' in CertConfig:
            for domain in CertConfig['subjectalternativename']:
                self.san.append(domain)

        if 'subject' in CertConfig:
            self.subject = CertSubject(CertConfig['subject'])

        if 'ca' in CertConfig:
            self.ca = CertConfig['ca'].lower()
        else:
            self.ca = BaseConfig.default_ca

        if 'costumer' in CertConfig:
            self.costumer = CertConfig['costumer']
        if 'stage' in CertConfig:
            self.stage = CertConfig['stage']
        if 'sub' in CertConfig:
            self.sub = CertConfig['sub']

        self.file_save_path = BaseConfig.storage_file_directory + '/'
        if self.costumer:
            self.file_save_path += self.costumer + '/'
        if self.stage:
            self.file_save_path += self.stage + '/'
        if self.sub:
            self.file_save_path += self.sub + '/'
        self.file_save_path = self.file_save_path.replace('//', '/')

        #if 'key_type' in CertConfig:
        #    self.key_type = CertConfig['key_type']

        if 'validity_days' in CertConfig:
            try:
                self.validity_days = int(float(CertConfig['validity_days']))
            except Exception as e:
                pass

        if 'reuse_key' in CertConfig:
            self.reuse_key = self._str2bool(CertConfig['reuse_key'])

        if 'dns_zone' in CertConfig:
            self.dns_zone = CertConfig['dns_zone']

        if 'force_renew' in CertConfig:
            self.force_renew = self._str2bool(CertConfig['force_renew'])


    def _LowerCaseOfKey(self,x, recusiv=True):
        r = {}
        for k, v in x.items():
            if isinstance(v, dict) and recusiv == True:
                v = self._LowerCaseOfKey(v)
            if isinstance(k, str):
                r[k.lower()] = v
            else:
                r[k] = v
        return r


    def _str2bool(self, s):
        return str(s).lower() in ("yes", "true", "y", "t", "1")


    def clean_up(self):
        self = None


class CaStats:
    def __init__(self):
        self
        self.certs = 0
        self.fqdn = 0
        self.to_renew = 0
        self.renew_success = 0
        self.renew_failed = 0
        self.check_successful = 0
        self.config_error = 0

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)


    def increment_certs(self,increment=1):
        self.certs += increment

    def increment_fqdn(self,increment=1):
        self.fqdn += increment

    def increment_to_renew(self,increment=1):
        self.to_renew += increment

    def increment_renew_success(self,increment=1):
        self.renew_success += increment

    def increment_renew_failed(self,increment=1):
        self.renew_failed += increment

    def increment_check_successful(self,increment=1):
        self.check_successful += increment

    def increment_config_error(self, increment=1):
        self.config_error += increment

