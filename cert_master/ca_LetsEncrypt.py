#!/usr/bin/env python
# _*_ coding: utf-8

# See LICENSE for details.

import hashlib
import base64
import requests
import time
import json
from OpenSSL import crypto
from acme import messages
from acme import challenges
from acme import client
from acme import errors
import josepy
from josepy.util import ComparableX509
from cert_master.certificate import MyCertificate

class CaLetsEncrypt:
    def __init__(self, logger=None, ca=None):
        self
        self.logger = logger
        self.conf = ca

        self.accountKey = None
        self.jwk_token = None
        self.acme = None

        self.account_uri = None

        self.authorization = {}
        self.challenge_authorization = {}
        self.cert_rsa = None
        self.cert_ec = None


        self.Route53 = None
        self.Route53Zone = None


        if self.conf.account_key is not None:
            self._loadAccountKey()


    def _loadAccountKey(self):
        self.logger.info('Loading {} Account Key {}'.format(self.conf.issuer_name, self.conf.account_key))

        leAccountKey = MyCertificate(logger=self.logger)
        if self.conf.account_key_passphrase:
            leAccountKey.loadPrivateKEYfile(keyfile=self.conf.account_key, passphrase=self.conf.account_key_passphrase)
        else:
            leAccountKey.loadPrivateKEYfile(keyfile=self.conf.account_key)

        self.accountKey = leAccountKey
        return True


    def loadJWKToken(self):
        if not self.accountKey:
            self.logger.error('No LetsEnrypt Account Key loaded to generate JWK')
        self.jwk_token = josepy.JWKRSA(key=self.accountKey.key)
        return True


    def acme_Connection(self):
        try:
            self.acme = client.Client(self.conf.directory_url, self.jwk_token)
            self.logger.info('LetsEnrypt ACME Connection established')
        except Exception as e:
            print(e)
            return False
        return True


    def acme_AccountInfo(self):
        self.logger.info("getting acme account info ...")

        if not self.account_uri:
            try:
                regr = self.acme.register()
            except errors.ConflictError as e:
                self.account_uri = e.location

        if self.account_uri:
            self.logger.info('Account URI: {}'.format(self.account_uri))
            try:
                info = self.acme.query_registration(messages.RegistrationResource(uri=self.account_uri))
                self.logger.info('Account contact: {}'.format(info.body.contact))
                self.logger.info('Account emails: {}'.format(info.body.emails))
                self.logger.info('Account phones: {}'.format(info.body.phones))
                self.logger.info('Account agreement: {}'.format(info.body.agreement))
                #self.logger.debug('Account object: {}'.format(info))
            except Exception as e:
                self.logger.error(e)


    def acme_AccountRegister(self):
        self.logger.info("Registering account...")
        try:
            regr = self.acme.register()
            self.logger.info('Auto-accepting TOS: %s', regr.terms_of_service)
            self.acme.agree_to_tos(regr)
            self.logger.debug(regr)
        except errors.ConflictError as e:
            self.account_uri = e.location
        except Exception as e:
            print(e)

        if self.account_uri:
            self.logger.info('Account was already registerd')
            self.logger.info('Account URI: {}'.format(self.account_uri))


    def acme_AccountDeactivate(self):
        self.logger.info("Deactivating account...")
        try:
            regr = self.acme.register()
        except errors.ConflictError as e:
            self.account_uri = e.location
        except Exception as e:
            print(e)

        if self.account_uri:
            try:
                self.acme.deactivate_registration(messages.RegistrationResource(uri=self.account_uri))
            except Exception as e:
                self.logger.error(e)
            self.logger.info('Account has bin deactivated')


    def acme_AccountUpdateRegistration(self):
        self.logger.info("UpdateRegistration of ACME account...")
        self.logger.error("Not yet implemented")
        # contact = (
        #     'mailto:foo@example.com'
        # )
        # agreement = 'https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf'
        # update_regestration = messages.UpdateRegistration(uri=self.account_uri,contact=contact,agreement=agreement)
        # regr = self.acme.update_registration(messages.RegistrationResource(),update_regestration)


    def get_acme_authorization(self, domain, san=[]):
        acme_authorizations=[domain]
        acme_authorizations += san
        acme_authorizations = list(set(acme_authorizations))
        all_success = True
        for fqdn in acme_authorizations:
            try:
                self.authorization[fqdn] = self.acme.request_challenges(
                    identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=fqdn))
                self.logger.debug('Request ACME authorization for {}'.format(fqdn))
            except Exception as e:
                print(e)
                self.logger.error('Request ACME authorization for {} failed: {}'.format(fqdn,e))
                all_success = False

        return all_success


    def challenge_acme_authorizations(self, force_renew_authorizations=False, dns_client="Route53"):
        ''' Challenge all existing ACME Authorizations

        :Args:
            force_renew (bool): Force Renew of the challenge, if it is already vailid

        :return:
            True: if all Authorizations are successfull
            False: if one or more Authorizations are failed
        '''

        all_success = True
        for fqdn, a in self.authorization.items():
            if a.body.status.name == 'valid' and force_renew_authorizations == False:
                self.logger.info("ACME authorization for Domain {} is still vailid".format(fqdn))
            else:
                if a.body.status.name == 'valid' and force_renew_authorizations == True:
                    self.logger.info("ACME authorization for Domain {} is forced to renew".format(fqdn))
                else:
                    self.logger.info("ACME authorization for Domain {} has to be done/challenged".format(fqdn))

                # Doing the challenge
                if dns_client == "Route53":
                    if self.Route53Zone == None:
                        self.Route53Zone = self.Route53.get_zone_by_fqdn(fqdn)['DNSName']
                    res = self.answer_dns_challenge(zone=self.Route53Zone, fqdn=fqdn,dns_client=dns_client)
                    if res is not True:
                        self.logger.error("An error occurred while answering the DNS challenge. Skipping domain '{0}'.".format(fqdn))
                        all_success = False
                        continue
                    else:
                        self.remove_dns_challenge(zone=self.Route53Zone, fqdn=fqdn)

                else:
                    self.logger.error("No other DNS Providers Implementet yet")

        return all_success


    def get_dns_challenge(self, fqdn):
        # Now let's look for a DNS challenge
        dns_challenges = filter(lambda x: isinstance(x.chall, challenges.DNS01), self.authorization[fqdn].body.challenges)
        return list(dns_challenges)[0]


    def get_dns_response(self,fqdn,dns_challenge):
        """
            Compute the required answer
        """

        self.challenge_authorization[fqdn] = "{}.{}".format(
            base64.urlsafe_b64encode(dns_challenge.get("token")).decode("ascii").replace("=", ""),
            base64.urlsafe_b64encode(self.acme.key.thumbprint()).decode("ascii").replace("=", "")
        )

        return base64.urlsafe_b64encode(hashlib.sha256(self.challenge_authorization[fqdn].encode()).digest()).decode(
            "ascii").replace("=", "")


    def answer_dns_challenge(self,dns_client="Route53", zone=None, fqdn=None):
        dns_challenge = self.get_dns_challenge(fqdn)
        dns_response = self.get_dns_response(fqdn,dns_challenge)
        self.logger.info("DNS Challenge for Domain '{}' is: {}".format(fqdn, dns_response))

        if dns_client == "Route53":
            self.Route53.deploy_acme_challenge(zone, fqdn, dns_response)
            try:
                #self.Route53.wait(fqdn, sleeptime=15)
                self.Route53.sleep_and_wait(fqdn, sleeptime=15)
            except Exception as e:
                # Wait some time, so that Route53 can sync
                self.logger.warning("Waiting for Route53 failed: {}".format(e))
                self.logger.warning("waiting 60 Seconds...")
                time.sleep(60)
        else:
            self.logger.error("No other DNS Providers Implementet yet")

        ## Now, let's tell the ACME server that we are ready
        challenge_response = challenges.DNS01Response(key_authorization=self.challenge_authorization[fqdn])
        challenge_resource = self.acme.answer_challenge(dns_challenge, challenge_response)

        if challenge_resource.body.error != None:
            self.logger.error(
                "Error Answering the DNS challenge for domain '{}': {}".format(fqdn, challenge_resource.body.error))
            return False
        self.logger.debug("Answering the DNS challenge for domain '{}' successful".format(fqdn))
        return True


    def remove_dns_challenge(self,dns_client="Route53", zone=None, fqdn=None):
        if dns_client == "Route53":
            self.Route53.clean_acme_challenge(zone, fqdn)
        else:
            self.logger.error("No other DNS Providers Implementet yet")


    def request_certificate(self,domain):
        for keytype in domain.key_type:
            if keytype == 'RSA':
                self.cert_rsa = MyCertificate(logger=self.logger, keytype=keytype)
                self.cert_rsa.generateNewCSR(with_new_key=True,fqdn=domain.cert,san=domain.san)
                ComparableCSR = self.cert_rsa.getComparableCSR()
            elif keytype == 'ECDSA':
                self.cert_ec = MyCertificate(logger=self.logger, keytype=keytype)
                self.cert_ec.generateNewCSR(with_new_key=True, fqdn=domain.cert, san=domain.san)
                ComparableCSR = self.cert_ec.getComparableCSR()

            all_authorizations = []
            for fqdn, a in self.authorization.items():
                all_authorizations.append(a)

            try:
                (certificate, ar) = self.acme.poll_and_request_issuance(ComparableX509(ComparableCSR), all_authorizations)
            except errors.PollError as e:
                self.logger.error("Failed to get certificate issuance for '{0}'.".format(domain.cert))
                self.logger.error("Error: {0}".format(e))
                return False

            chain = requests.get(certificate.cert_chain_uri)

            if chain.status_code == 200:
                #chain_certificate = None
                chain_certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, chain.content)
                pem_chain_certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, chain_certificate).decode("ascii")
            else:
                self.logger.error("Failed to retrieve chain certificate. Status was '{0}'.".format(chain.status_code))
                pem_chain_certificate = False

            pem_certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, certificate.body.wrapped).decode("ascii")

            if keytype == 'RSA':
                self.cert_rsa.loadCertfromPEM(pem_certificate)
                if pem_chain_certificate:
                    self.cert_rsa.loadIntermediateCertfromPEM(pem_chain_certificate)
            elif keytype == 'ECDSA':
                self.cert_ec.loadCertfromPEM(pem_certificate)
                if pem_chain_certificate:
                    self.cert_ec.loadIntermediateCertfromPEM(pem_chain_certificate)

        return True


    def save_certificates_and_key(self, domain):
        # Save all
        self.logger.info('Saving received certificates and key signed by "{}"'.format(self.conf.issuer_name))
        for keytype in domain.key_type:
            if keytype == 'RSA':
                self.cert_rsa.saveKeyAsPEM(domain.file_save_path + domain.cert + '_rsa.key')
                self.cert_rsa.saveCrtAsPEM(domain.file_save_path + domain.cert + '_rsa.crt.pem')
                self.cert_rsa.saveIntermediateAsPEM(domain.file_save_path + domain.cert + '_rsa.intermediate.pem')
                self.cert_rsa.saveChainAsPEM(domain.file_save_path + domain.cert + '_rsa.chain.pem')
            elif keytype == 'ECDSA':
                self.cert_ec.saveKeyAsPEM(domain.file_save_path + domain.cert + '_ecdsa.key')
                self.cert_ec.saveCrtAsPEM(domain.file_save_path + domain.cert + '_ecdsa.crt.pem')
                self.cert_ec.saveIntermediateAsPEM(domain.file_save_path + domain.cert + '_ecdsa.intermediate.pem')
                self.cert_ec.saveChainAsPEM(domain.file_save_path + domain.cert + '_ecdsa.chain.pem')
        return True


    def setRoute53(self,obj):
        self.Route53 = obj


    def setRoute53Zone(self,zone):
        self.Route53Zone = zone


    def clean_up(self):
        self = None