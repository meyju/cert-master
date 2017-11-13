#!/usr/bin/env python
# _*_ coding: utf-8

# See LICENSE for details.

from cert_master.certificate import MyCertificate

class CaLocal:
    def __init__(self, logger=None, ca=None):
        self
        self.logger = logger
        self.conf = ca
        self.caKey = None
        self.caCert = None
        self.caKey_rsa = None
        self.caCert_rsa = None
        self.caKey_ec = None
        self.caCert_ec = None

        self.cert_rsa = None
        self.cert_ec = None

        if self.conf.key is not None and self.conf.cert is not None:
            self.loadLocalCAkey()
            self.loadLocalCAcert()
        else:
            if self.conf.key_rsa is not None and self.conf.cert_rsa is not None:
                self.loadLocalCAkey(key_type='RSA')
                self.loadLocalCAcert(key_type='RSA')
            if self.conf.key_ec is not None and self.conf.cert_ec is not None:
                self.loadLocalCAkey(key_type='ECDSA')
                self.loadLocalCAcert(key_type='ECDSA')


    def loadLocalCAkey(self, key_type=None):
        if key_type is None:
            self.logger.info('Loading "{}" Key {}'.format(self.conf.issuer_name, self.conf.key))
            caKey = MyCertificate(logger=self.logger)
            if self.conf.key_passphrase:
                caKey.loadPrivateKEYfile(keyfile=self.conf.key, passphrase=self.conf.key_passphrase)
            else:
                caKey.loadPrivateKEYfile(keyfile=self.conf.key)
            self.caKey = caKey
            return True
        elif key_type == 'RSA':
            self.logger.info('Loading "{}" RSA Key {}'.format(self.conf.issuer_name, self.conf.key_rsa))
            caKey = MyCertificate(logger=self.logger)
            if self.conf.key_passphrase:
                caKey.loadPrivateKEYfile(keyfile=self.conf.key_rsa, passphrase=self.conf.key_passphrase)
            else:
                caKey.loadPrivateKEYfile(keyfile=self.conf.key_rsa)
            self.caKey_rsa = caKey
            return True
        elif key_type == 'ECDSA':
            self.logger.info('Loading "{}" ECDSA Key {}'.format(self.conf.issuer_name, self.conf.key_ec))
            caKey = MyCertificate(logger=self.logger)
            if self.conf.key_passphrase:
                caKey.loadPrivateKEYfile(keyfile=self.conf.key_ec, passphrase=self.conf.key_passphrase)
            else:
                caKey.loadPrivateKEYfile(keyfile=self.conf.key_ec)
            self.caKey_ec = caKey
            return True


    def loadLocalCAcert(self, key_type=None):
        if key_type is None:
            self.logger.info('Loading "{}" Cert {}'.format(self.conf.issuer_name, self.conf.cert))
            caCert = MyCertificate(logger=self.logger)
            caCert.loadCertfromPEMfile(self.conf.cert)
            self.caCert = caCert
            return True
        elif key_type == 'RSA':
            self.logger.info('Loading "{}" RSA Cert {}'.format(self.conf.issuer_name, self.conf.cert_rsa))
            caCert = MyCertificate(logger=self.logger)
            caCert.loadCertfromPEMfile(self.conf.cert_rsa)
            self.caCert_rsa = caCert
            return True
        elif key_type == 'ECDSA':
            self.logger.info('Loading "{}" ECDSA Cert {}'.format(self.conf.issuer_name, self.conf.cert_ec))
            caCert = MyCertificate(logger=self.logger)
            caCert.loadCertfromPEMfile(self.conf.cert_ec)
            self.caCert_ec = caCert
            return True


    def request_certificate(self,domain):
        # TODO: Check if Domain match with LocalCA CertificatePolicies
        try:
            for keytype in domain.key_type:
                if keytype == 'RSA':
                    if self.caKey_rsa != None:
                        self.caKey = self.caKey_rsa
                        self.caCert = self.caCert_rsa
                    self.cert_rsa = MyCertificate(logger=self.logger, keytype=keytype)
                    self.cert_rsa.generateNewCSR(with_new_key=True, fqdn=domain.cert, san=domain.san,
                                                 subject=domain.subject)
                    # Sign CSR with LocalCA
                    self.cert_rsa.setIntermediateCert(self.caCert.cert)
                    self.cert_rsa.generateNewCertFromCSRsignedByCA(self, validity_days=domain.validity_days,
                                                                   CaConfig=self.conf)
                elif keytype == 'ECDSA':
                    if self.caKey_ec != None:
                        self.caKey = self.caKey_ec
                        self.caCert = self.caCert_ec
                    self.cert_ec = MyCertificate(logger=self.logger, keytype=keytype)
                    self.cert_ec.generateNewCSR(with_new_key=True, fqdn=domain.cert, san=domain.san,
                                                 subject=domain.subject)
                    # Sign CSR with LocalCA
                    self.cert_ec.setIntermediateCert(self.caCert.cert)
                    self.cert_ec.generateNewCertFromCSRsignedByCA(self, validity_days=domain.validity_days,
                                                                   CaConfig=self.conf)

            return True
        except Exception as e:
            self.logger.error(e)
            return False

    def save_certificates_and_key(self, domain, save_csr=False):
        # Save all
        self.logger.info('Saving generated certificates and key signed by "{}"'.format(self.conf.issuer_name))
        for keytype in domain.key_type:
            if keytype == 'RSA':
                if save_csr:
                    self.cert_rsa.saveCSRasPEM(domain.file_save_path + domain.cert + '_rsa.csr')
                self.cert_rsa.saveKeyAsPEM(domain.file_save_path + domain.cert + '_rsa.key')
                self.cert_rsa.saveCrtAsPEM(domain.file_save_path + domain.cert + '_rsa.crt.pem')
                self.cert_rsa.saveIntermediateAsPEM(domain.file_save_path + domain.cert + '_rsa.intermediate.pem')
                self.cert_rsa.saveChainAsPEM(domain.file_save_path + domain.cert + '_rsa.chain.pem')
            elif keytype == 'ECDSA':
                if save_csr:
                    self.cert_ec.saveCSRasPEM(domain.file_save_path + domain.cert + '_ecdsa.csr')
                self.cert_ec.saveKeyAsPEM(domain.file_save_path + domain.cert + '_ecdsa.key')
                self.cert_ec.saveCrtAsPEM(domain.file_save_path + domain.cert + '_ecdsa.crt.pem')
                self.cert_ec.saveIntermediateAsPEM(domain.file_save_path + domain.cert + '_ecdsa.intermediate.pem')
                self.cert_ec.saveChainAsPEM(domain.file_save_path + domain.cert + '_ecdsa.chain.pem')
        return True

    def clean_up(self):
        self = None