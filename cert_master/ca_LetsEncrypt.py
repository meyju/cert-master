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
from acme import jose
from acme import challenges
from acme import client
from acme import errors
from acme.jose.util import ComparableX509
from cert_master.certificate import MyCertificate

class CaLetsEncrypt:
    def __init__(self, debug=False, logger=None, stageing=False, accountKeyFile=None, accountKeyPassphrase=None):
        self
        self.logger = logger
        self.accountKey = None
        self.accountKeyFile = accountKeyFile
        self.accountKeyPassphrase = accountKeyPassphrase
        self.jwk_token = None
        self.acme = None
        if stageing:
            self.DIRECTORY_URL = 'https://acme-v01.api.letsencrypt.org/directory'  # Production
        else:
            self.DIRECTORY_URL = 'https://acme-staging.api.letsencrypt.org/directory' # Staging
        self.authorization = {}
        self.challenge_authorization = {}
        self.Route53 = None
        self.Route53Zone = None
        self.cert = None



    def loadLEaccountKey(self,accountKeyFile=None, accountKeyPassphrase=None):
        if accountKeyFile:
            self.set_accountKeyFile(accountKeyFile)
        if accountKeyPassphrase:
            self.set_accountKeyPassphrase(accountKeyPassphrase)
        self.logger.info('Loading LetsEnrypt Account Key {}'.format(self.accountKeyFile))

        leAccountKey = MyCertificate(logger=self.logger)
        if self.accountKeyPassphrase:
            leAccountKey.loadPrivateKEYfile(keyfile=self.accountKeyFile, passphrase=self.accountKeyPassphrase)
        else:
            leAccountKey.loadPrivateKEYfile(keyfile=self.accountKeyFile)

        self.accountKey = leAccountKey
        return True


    def loadJWKToken(self):
        if not self.accountKey:
            self.logger.error('No LetsEnrypt Account Key loaded to generate JWK')
        self.jwk_token = jose.JWKRSA(key=self.accountKey.key)
        return True


    def set_accountKeyFile(self,accountKeyFile=None):
        self.accountKeyFile = accountKeyFile


    def set_accountKeyPassphrase(self,accountKeyPassphrase=None):
        self.accountKeyPassphrase = accountKeyPassphrase


    def acme_Connection(self):
        try:
            self.acme = client.Client(self.DIRECTORY_URL, self.jwk_token)
            self.logger.info('LetsEnrypt ACME Connection established')
        except Exception as e:
            print(e)
        return True

    def acme_AccountInfo(self):
        try:
            self.logger.info("Requesting account data...")
            # TODO: Get Account URI and Status
            self.logger.error("TODO: Get Account URI and Status")
        except Exception as e:
            print(e)
        return True


    def get_acme_authorization(self, domain, san=[]):
        acme_authorizations=[domain]
        acme_authorizations += san
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

    def challenge_acme_authorizations(self, force_renew=False, dns_client="Route53",):
        ''' Challenge all existing ACME Authorizations

        :Args:
            force_renew (bool): Force Renew of the challenge, if it is already vailid

        :return:
            True: if all Authorizations are successfull
            False: if one or more Authorizations are failed
        '''

        all_success = True
        for fqdn, a in self.authorization.items():
            if a.body.status.name == 'valid' and force_renew == False:
                self.logger.info("Challange for Domain {} is still vailid".format(fqdn))
            else:
                if a.body.status.name == 'valid' and force_renew == True:
                    self.logger.info("Challange for Domain {} is forced to renew".format(fqdn))
                else:
                    self.logger.info("Challange for Domain {} has to be done".format(fqdn))
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
        self.cert = MyCertificate(logger=self.logger)
        self.cert.generateNewCSR(with_new_key=True,fqdn=domain['Domain'],san=domain['AlternativeName'])

        ComparableCSR = self.cert.getComparableCSR()

        all_authorizations = []
        for fqdn, a in self.authorization.items():
            all_authorizations.append(a)

        try:
            (certificate, ar) = self.acme.poll_and_request_issuance(ComparableX509(ComparableCSR), all_authorizations)
        except errors.PollError as e:
            self.logger.error("Failed to get certificate issuance for '{0}'.".format(domain['name']))
            self.logger.error("Error: {0}".format(e))
            return False

        chain = requests.get(certificate.cert_chain_uri)
        chain_certificate = None

        if chain.status_code == 200:
            chain_certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, chain.content)
            pem_chain_certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, chain_certificate).decode("ascii")
        else:
            self.logger.error("Failed to retrieve chain certificate. Status was '{0}'.".format(chain.status_code))
            pem_chain_certificate = False

        pem_certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, certificate.body.wrapped).decode("ascii")

        self.cert.loadCertfromPEM(pem_certificate)
        if pem_chain_certificate:
            self.cert.loadIntermediateCertfromPEM(pem_chain_certificate)

        return True

    def save_certificates_and_key(self, domain):
        # Save all
        self.logger.info('Saving recived LetsEnrypt certificates and key')
        self.cert.saveKeyAsPEM(domain['save_path'] + domain['Domain']+'_'+self.cert.keytype.lower()+".key")
        self.cert.saveCrtAsPEM(domain['save_path'] + domain['Domain'] + '_' + self.cert.keytype.lower() + ".crt.pem")
        self.cert.saveIntermediateAsPEM(domain['save_path'] + domain['Domain'] + '_' + self.cert.keytype.lower() + ".intermediate.pem")
        self.cert.saveChainAsPEM(domain['save_path'] + domain['Domain'] + '_' + self.cert.keytype.lower() + ".chain.pem")
        return True

    def setRoute53(self,obj):
        self.Route53 = obj

    def setRoute53Zone(self,zone):
        self.Route53Zone = zone

    def clean_up(self):
        self = None