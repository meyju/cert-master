#!/usr/bin/env python
# _*_ coding: utf-8

# See LICENSE for details.

from cert_master.certificate import MyCertificate

class CaLocal:
    def __init__(self, logger=None, caKeyFile=None,  caKeyPassphrase=None, caCertFile=None, cert_expire_days=90):
        self
        self.logger = logger
        self.caKey = None
        self.caKeyFile = caKeyFile
        self.caKeyPassphrase = caKeyPassphrase
        self.caCert = None
        self.caCertFile = caCertFile
        self.cert_expire_days = cert_expire_days

        self.cert = None

        if caKeyFile  is not None:
            self.loadLocalCAkey()

        if caCertFile  is not None:
            self.loadLocalCAcert()


    def loadLocalCAkey(self,caKeyFile=None, caKeyPassphrase=None):
        if caKeyFile:
            self.set_caKeyFile(caKeyFile)
        if caKeyPassphrase:
            self.set_caKeyPassphrase(caKeyPassphrase)

        self.logger.info('Loading LocalCA Key {}'.format(self.caKeyFile))

        Key = MyCertificate(logger=self.logger)
        if self.caKeyPassphrase:
            Key.loadPrivateKEYfile(keyfile=self.caKeyFile, passphrase=self.caKeyPassphrase)
        else:
            Key.loadPrivateKEYfile(keyfile=self.caKeyFile)

        self.caKey = Key
        return True


    def loadLocalCAcert(self,caCertFile=None):
        if caCertFile:
            self.caCertFile(caCertFile)

        self.logger.info('Loading LocalCA Cert {}'.format(self.caCertFile))

        Cert = MyCertificate(logger=self.logger)
        Cert.loadCertfromPEMfile(self.caCertFile)

        self.caCert = Cert
        return True


    def set_caKeyFile(self,caKeyFile=None):
        self.caKeyFile = caKeyFile


    def set_caKeyPassphrase(self,caKeyPassphrase=None):
        self.caKeyPassphrase = caKeyPassphrase


    def set_caCertFile(self,caCertFile=None):
        self.caCertFile = caCertFile


    def request_certificate(self,domain):

        # TODO: Check if Domain match with LocalCA CertificatePolicies

        try:

            self.cert = MyCertificate(logger=self.logger)
            self.cert.generateNewCSR(with_new_key=True,fqdn=domain['Domain'],san=domain['AlternativeName'], subject=domain['subject'])

            # Sign CSR with LocalCA
            self.cert.setIntermediateCert(self.caCert.cert)
            self.cert.generateNewCertFromCSRsignedByCA(self)

            return True
        except Exception as e:
            self.logger.error(e)
            return False

    def save_certificates_and_key(self, domain):
        # Save all
        self.logger.info('Saving recived LocalCA certificates and key')
        #self.cert.saveCSRasPEM(domain['save_path'] + domain['Domain']+'_'+self.cert.keytype.lower()+".csr")
        self.cert.saveKeyAsPEM(domain['save_path'] + domain['Domain']+'_'+self.cert.keytype.lower()+".key")
        self.cert.saveCrtAsPEM(domain['save_path'] + domain['Domain'] + '_' + self.cert.keytype.lower() + ".crt.pem")
        self.cert.saveIntermediateAsPEM(domain['save_path'] + domain['Domain'] + '_' + self.cert.keytype.lower() + ".intermediate.pem")
        self.cert.saveChainAsPEM(domain['save_path'] + domain['Domain'] + '_' + self.cert.keytype.lower() + ".chain.pem")
        return True

    def clean_up(self):
        self = None