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

        self.cert = None

        if self.conf.key is not None:
            self.loadLocalCAkey()

        if self.conf.cert is not None:
            self.loadLocalCAcert()


    def loadLocalCAkey(self):
        self.logger.info('Loading "{}" Key {}'.format(self.conf.issuer_name, self.conf.key))
        caKey = MyCertificate(logger=self.logger)
        if self.conf.key_passphrase:
            caKey.loadPrivateKEYfile(keyfile=self.conf.key, passphrase=self.conf.key_passphrase)
        else:
            caKey.loadPrivateKEYfile(keyfile=self.conf.key)
        self.caKey = caKey
        return True


    def loadLocalCAcert(self):
        self.logger.info('Loading "{}" Cert {}'.format(self.conf.issuer_name, self.conf.cert))
        caCert = MyCertificate(logger=self.logger)
        caCert.loadCertfromPEMfile(self.conf.cert)
        self.caCert = caCert
        return True



    def request_certificate(self,domain):
        # TODO: Check if Domain match with LocalCA CertificatePolicies
        try:
            self.cert = MyCertificate(logger=self.logger)
            self.cert.generateNewCSR(with_new_key=True,fqdn=domain.cert,san=domain.san, subject=domain.subject)
            # Sign CSR with LocalCA
            self.cert.setIntermediateCert(self.caCert.cert)
            self.cert.generateNewCertFromCSRsignedByCA(self,validity_days=domain.validity_days,CaConfig=self.conf)
            return True

        except Exception as e:
            self.logger.error(e)
            return False

    def save_certificates_and_key(self, domain, save_csr=False):
        # Save all
        self.logger.info('Saving generated certificates and key signed by "{}"'.format(self.conf.issuer_name))
        if save_csr:
            self.cert.saveCSRasPEM(domain.file_save_path + domain.cert + '_' + self.cert.keytype.lower() + ".csr")
        self.cert.saveKeyAsPEM(domain.file_save_path + domain.cert + '_' + self.cert.keytype.lower() + ".key")
        self.cert.saveCrtAsPEM(domain.file_save_path + domain.cert + '_' + self.cert.keytype.lower() + ".crt.pem")
        self.cert.saveIntermediateAsPEM(domain.file_save_path + domain.cert + '_' + self.cert.keytype.lower() + ".intermediate.pem")
        self.cert.saveChainAsPEM(domain.file_save_path + domain.cert + '_' + self.cert.keytype.lower() + ".chain.pem")
        return True

    def clean_up(self):
        self = None