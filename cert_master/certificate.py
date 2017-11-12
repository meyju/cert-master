#!/usr/bin/env python
# _*_ coding: utf-8

# See LICENSE for details.


import os
from datetime import datetime, timedelta
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.x509.general_name import GeneralName


class MyCertificate:
    def __init__(self, debug=False, logger=None, keyfile=None, keytype="RSA", bits=2048, passphrase=None ):
        self
        self.logger = logger
        # TODO: rename self.logging
        self.debug = debug
        self.status = None
        self.keyfile = keyfile
        self.key = None
        self.keytype = keytype
        self.keypass = None
        self.passphrase = passphrase
        self.BITS = bits
        self.csr = None
        self.cert = None
        self.intermediate = None
        self.backend=default_backend()

    def generateNewKey(self,keytype=None):
        if keytype:
            self._setKeyType(keytype)
        if self.keytype == "RSA":
            self.logger.debug("Generating new RSA Key")
            self.key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.BITS,
                backend=self.backend)
        elif self.keytype == "ECDSA":
            self.logger.debug("Generating new ECDSA Key with SECP256R1 curve")
            # TODO: Support other curves to
            self.key = ec.generate_private_key(ec.SECP256R1,backend=self.backend)
        else:
            self.logger.error("unkown keytype " + str(self.keytype) + " - error")

    def loadPrivateKEYfile(self, keyfile=None, passphrase=None):
        if keyfile:
            self._setKeyFile(keyfile)
        if passphrase:
            self._setPassphrase(passphrase)

        with open(self.keyfile, "rb") as key_file:
            if self.passphrase is not None:
                key = serialization.load_pem_private_key(key_file.read(),
                                                            password=bytes(self.passphrase, 'utf-8'),
                                                            backend=self.backend)
            else:
                key = serialization.load_pem_private_key(key_file.read(),
                                                            password=None,
                                                            backend=self.backend)
            self.key = key
            return True

        return False

    def loadCSRfile(self, csrfile=None):
        with open(csrfile, "rb") as csr_file:
           csr = x509.load_pem_x509_csr(csr_file.read(), backend=self.backend)
           self.csr = csr

           return True

        return False

    def returnKeyAsPEM(self):
        self.logger.error('Not IMPLEMENTET YET !!!')

    def saveKeyAsPEM(self,filename,passphrase=None):
        if self.key is None:
            raise 'no Key existing yet'

        if passphrase:
            self._setPassphrase(passphrase)

        if self.passphrase is None:
            with open(os.path.expanduser(filename), "wb") as f:
                f.write(self.key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,

                    encryption_algorithm=serialization.NoEncryption(),
                ))
            self.logger.info("Key saved at: " + str(os.path.expanduser(filename)))
        else:
            with open(os.path.expanduser(filename), "wb") as f:
                f.write(self.key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(bytes(self.passphrase, 'utf-8')),
                ))
            self.logger.info("Key saved at: " + str(os.path.expanduser(filename)) + " (with Passphrase)")

    def _setKeyType(self, value):
        self.keytype = value

    def _setKeyFile(self, value):
        self.keyfile = value

    def _setPassphrase(self, value):
        self.passphrase = value

    def generateNewCSR(self, fqdn, subject=None, san=None, with_new_key=False, KeyUsage=True, ExtendedKeyUsage=True):
        """ Create a new CSR

        This function creates a new Certifcate Signing Request with the given inforamtion.

        :param str fqdn: Domain (CN) of the certificate
        :param dict subject: Additional values of the CSR
                             Supported ITEMS: ORGANIZATION, ORGANIZATIONAL_UNIT, COUNTRY, STATE, LOCALITY, EMAIL
        :param bool with_new_key: Force creation of a new private key
        :param bool KeyUsage: Add KeyUsage Extension to the CSR (Default: True)
                              Will be: digitalSignature, keyEncipherment (critical)
        :param bool ExtendedKeyUsage: Add ExtendedKeyUsage Extension to the CSR (Default: True)
                                      Will be: TLS Web Server Authentication, TLS Web Client Authentication

        :returns: ``X.509 certificate signing request Object`
        :rtype: `obj`
        """
        if with_new_key:
            self.generateNewKey()

        self.logger.info("Creating CSR for '" + str(fqdn) + "' with SubjectAlternativeName's: " + str(san))

        csr_subject = []
        if fqdn:
            csr_subject.append(x509.NameAttribute(x509.OID_COMMON_NAME, str(fqdn)))
        if subject is not None:
            if subject.organization is not None:
                csr_subject.append(x509.NameAttribute(x509.OID_ORGANIZATION_NAME, str(subject.organization)))
            if subject.organizational_unit is not None:
                csr_subject.append(x509.NameAttribute(x509.OID_ORGANIZATIONAL_UNIT_NAME, str(subject.organizational_unit)))
            if subject.country is not None:
                csr_subject.append(x509.NameAttribute(x509.OID_COUNTRY_NAME, str(subject.country.upper())))
            if subject.state is not None:
                csr_subject.append(x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, str(subject.state) ))
            if subject.locality is not None:
                csr_subject.append(x509.NameAttribute(x509.OID_LOCALITY_NAME, str(subject.locality)))
            if subject.email is not None:
                csr_subject.append(x509.NameAttribute(x509.OID_EMAIL_ADDRESS, str(subject.email)))

        # Generate a CSR
        csr = x509.CertificateSigningRequestBuilder()
        csr = csr.subject_name(x509.Name(csr_subject))
        csr = csr.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        # Adding SubjectAlternativeName
        adding_san = []
        if san is not None:
            for s in san:
                adding_san.append(x509.DNSName(s))
        csr = csr.add_extension(
            x509.SubjectAlternativeName(adding_san),
            critical=False,
        )

        # Key Usage: digitalSignature, keyEncipherment (critical)
        if KeyUsage:
            csr = csr.add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False),
                                critical=True)
        # Extended Key Usage: TLS Web Server Authentication, TLS Web Client Authentication
        if ExtendedKeyUsage:
            csr = csr.add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH,x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
                )

        # Sign the CSR with our private key.
        self.csr = csr.sign(self.key, hashes.SHA256(), default_backend())

    def generateNewCertFromCSRsignedByCA(self, SigningCA, SubjectKeyIdentifier=True, AuthorityKeyIdentifier=True, validity_days=None, CaConfig=None):

        builder = x509.CertificateBuilder()

        # Add CA Details
        builder = builder.issuer_name(SigningCA.caCert.cert.subject)
        builder = builder.serial_number(x509.random_serial_number())

        # Valid Times
        if validity_days:
            if validity_days > CaConfig.cert_expire_days_min and validity_days < CaConfig.cert_expire_days_max:
                days=validity_days
            elif validity_days < CaConfig.cert_expire_days_min:
                days=CaConfig.cert_expire_days_min
            elif validity_days > CaConfig.cert_expire_days_max:
                days = CaConfig.cert_expire_days_max
        else:
            days=CaConfig.cert_expire_days_default
        builder = builder.not_valid_before(datetime.today().replace(hour=0, minute=0, second=0, microsecond=0))
        builder = builder.not_valid_after(datetime.utcnow().replace(second=0, microsecond=0) + timedelta(days=days))

        # Takeover Details from CSR:
        builder = builder.subject_name(self.csr.subject)
        builder = builder.public_key(self.key.public_key())

        # Takeover Extensions
        for extension in self.csr.extensions:
            # TODO: Improvement - Validate Extensions and the content of them
            if x509.oid.ExtensionOID.BASIC_CONSTRAINTS == extension.oid:
                builder = builder.add_extension(extension.value, critical=extension.critical)
                # TODO: Force BasicConstrains CA=False here

            if x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME == extension.oid:
                builder = builder.add_extension(extension.value, critical=extension.critical)

            if x509.oid.ExtensionOID.KEY_USAGE == extension.oid:
                builder = builder.add_extension(extension.value, critical=extension.critical)

            if x509.oid.ExtensionOID.EXTENDED_KEY_USAGE == extension.oid:
                builder = builder.add_extension(extension.value, critical=extension.critical)

        if SubjectKeyIdentifier == True:
            builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(self.csr.public_key()),
                                            critical=False
                                            )

        if AuthorityKeyIdentifier == True:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(SigningCA.caCert.cert.public_key()),
                critical=False
                )

        # Finally Sign the Certificate
        self.cert = builder.sign(
            private_key=SigningCA.caKey.key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        return True


    def saveCSRasPEM(self,filename):
        if self.csr is None:
            raise 'no CSR existing yet'
        with open(os.path.expanduser(filename), "wb") as f:
            f.write(self.csr.public_bytes(serialization.Encoding.PEM))
        self.logger.info("CSR saved at: " + str(os.path.expanduser(filename)))

    def _saveX509asPEM(self,cert,filename, filemode="wb"):
        if cert is None:
            raise 'no Cert to save'
        with open(os.path.expanduser(filename), filemode) as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def saveCrtAsPEM(self,filename):
        self._saveX509asPEM(self.cert, filename)
        self.logger.info("Certificate saved at: " + str(os.path.expanduser(filename)))

    def saveIntermediateAsPEM(self,filename):
        self._saveX509asPEM(self.intermediate, filename)
        self.logger.info("Intermediate Certificate saved at: " + str(os.path.expanduser(filename)))

    def setIntermediateCert(self,IntermediateCert):
        self.intermediate = IntermediateCert

    def saveChainAsPEM(self,filename):
        self._saveX509asPEM(self.cert, filename)
        self._saveX509asPEM(self.intermediate, filename, filemode="ab")
        self.logger.info("Certificate-Chain saved at: " + str(os.path.expanduser(filename)))

    def getComparableCSR(self):
        return OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_ASN1,
                                                       self.csr.public_bytes(serialization.Encoding.DER))

    def loadCertfromPEM(self,cert):
        self.cert = x509.load_pem_x509_certificate(bytes(cert,'ascii'),self.backend)

    def loadCertfromPEMfile(self,file):
        with open(file, "rb") as cert:
            self.cert = x509.load_pem_x509_certificate(cert.read(),self.backend)

    def loadIntermediateCertfromPEM(self,cert):
        self.intermediate = x509.load_pem_x509_certificate(bytes(cert,'ascii'),self.backend)


    def checkKeyMatchCert(self):
        if self.cert.public_key().public_numbers() == self.key.public_key().public_numbers():
            return True
        else:
            return False


    def checkCertIssuerContains(self,contains):
        issuer = ''
        for attribute in self.cert.issuer:
            if x509.oid.NameOID.COMMON_NAME == attribute.oid:
                issuer = attribute.value
                break
        if contains in issuer:
            return True
        else:
            return False


    def checkCertDomain(self,domain):
        cn = self.cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        if cn == domain:
            return True
        else:
            return False


    def checkCertTimeValid(self):
        not_valid_after = self.cert.not_valid_after
        now = datetime.utcnow()
        if not_valid_after > now:
            return True
        else:
            return False


    def checkCertDaysLeft(self, days=30):
        not_valid_after = self.cert.not_valid_after - timedelta(days = days)
        now = datetime.utcnow()
        if not_valid_after > now:
            return True
        else:
            return False


    def getCertDaysLeft(self):
        days_left = self.cert.not_valid_after - datetime.utcnow()
        return days_left.days


    def getCertValidity(self):
        validity = self.cert.not_valid_after - self.cert.not_valid_before
        return validity.days


    def checkCertLifetimeProceed(self, progress=0.33):
        diff = self.cert.not_valid_after - self.cert.not_valid_before
        days = int(float(diff.days * progress))
        return self.checkCertDaysLeft(days=days)


    def checkCertSAN(self,domain, san=[]):
        san_should = [domain]
        for s in san:
            san_should.append(s)
        san_is = []

        san_extension = False
        oid_subjectAltName = '2.5.29.17'
        for ext in self.cert.extensions:
            if ext.oid.dotted_string == oid_subjectAltName:
                san_extension = ext.value
                break

        if san_extension:
            for attribute in san_extension:
                san_is.append(attribute.value)

        san_added = list(set(san_should) - set(san_is))
        san_removed = list(set(san_is) - set(san_should))
        if len (san_added) == 0 and len (san_removed) == 0:
            return (True, '')
        else:
            san_msg = ''
            if len(san_added) > 0:
                san_msg += ' SAN Added: '+str(san_added)
            if len(san_removed) > 0:
                san_msg += ' SAN Removed: '+ str(san_removed)
            return (False, san_msg)


    def clean_up(self):
        self = None
