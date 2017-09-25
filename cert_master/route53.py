#!/usr/bin/env python3
# _*_ coding: utf-8

# See LICENSE for details.

import boto3
import time
from botocore.exceptions import ClientError

class r53:
    def __init__(self, aws_access_key_id=None, aws_secret_access_key=None, logger = None):
        self
        self.logger = logger
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.status = None
        self.change_id = None

    def setAuthKey(self,aws_access_key_id, aws_secret_access_key):
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key

    def enable_connection(self):
        if self.aws_access_key_id:
            try:
                self.connection = boto3.client('route53', aws_access_key_id=self.aws_access_key_id,
                                               aws_secret_access_key=self.aws_secret_access_key)
            except ClientError as e:
                print("Unexpected error: %s" % e)
        else:
            try:
                self.connection = boto3.client('route53')
            except ClientError as e:
                print("Unexpected error: %s" % e)

    def get_zone_by_fqdn(self,fqdn):
        '''Try to get the Zone from Route53'''

        # TODO: Can be obtimised
        #       By checking self.get_zones() and search there for the Domain.
        #       If ther are many sub sub domains in the fqdn it is not the best way currently...

        while True == True:
            if '.' in fqdn:
                zone = self._get_zone(fqdn)
                if len(zone['HostedZones']) == 1:
                    return zone
                fqdn = fqdn.partition('.')[2]
            else:
                break
                return False
        return False


    def _get_zone(self,zone):
        return self.connection.list_hosted_zones_by_name(DNSName=zone)

    def _get_zone_id(self,zone):
        return self._get_zone(zone)['HostedZones'][0]['Id']

    def get_zones(self):
        return self.connection.list_hosted_zones()


    def sleep_and_wait(self,fqdn=None, sleeptime=2, maxwait_count=30, firstsleep=60):
        time.sleep(firstsleep)
        self.wait(fqdn=fqdn, sleeptime=sleeptime, maxwait_count=maxwait_count)

    def wait(self, fqdn=None, sleeptime=2, maxwait_count=30):
        for y in range(1, maxwait_count+1):
            if fqdn:
                self.logger.debug('Get status of "{}" ChangeResourceRecordSets Id "{}" (Check #{}) '.format(fqdn, self.change_id, y))
            else:
                self.logger.debug('Get status of ChangeResourceRecordSets Id "{}" (Check #{}) '.format(self.change_id, y))
            get_change = self.connection.get_change(Id=self.change_id)
            self.status = get_change
            status_change = self.status['ChangeInfo']['Status']
            if status_change == 'INSYNC':
                self.logger.debug('Status of ChangeResourceRecordSets is "INSYNC"')
                break
            else:
                self.logger.debug('Status of ChangeResourceRecordSets still in "PENDING"')
                time.sleep(sleeptime)
        # return self.status
        return True

    def _create_record(self, zone_name, record_fqdn, record_type, record_value, record_ttl=60):
        if record_type == 'TXT':
            record_value = '"' + record_value + '"'
        self.logger.info("Deploying Record on Route53: '" + str(record_fqdn) + ". " + str(record_ttl) + " " + record_type + " " + str(record_value) + "'")
        zoneid = self._get_zone_id(zone_name)
        try:
            response = self.connection.change_resource_record_sets(
                HostedZoneId=zoneid,
                ChangeBatch={
                    'Comment': 'add %s (%s) -> %s' % (record_fqdn, record_type,record_value),
                    'Changes': [
                        {
                            'Action': 'UPSERT',
                            'ResourceRecordSet': {
                                'Name': record_fqdn,
                                'Type': record_type,
                                'TTL': record_ttl,
                                'ResourceRecords': [{'Value': record_value}]
                            }
                        }]
                })
            self.status = response['ChangeInfo']
            self.change_id = self.status['Id']
        except Exception as e:
            print(e)

        return True

    def _delete_record(self, zone_name, record_fqdn, record_type):
        zoneid = self._get_zone_id(zone_name)
        try:
            rr = self.connection.list_resource_record_sets(HostedZoneId=zoneid, StartRecordName=record_fqdn,
                                                           StartRecordType=record_type, MaxItems="1")
            old_record = rr['ResourceRecordSets'][0]
            self.logger.info(
                "Deleting Record on Route53: '" + str(record_fqdn) + ". " + str(old_record['TTL']) + " " + record_type +
                " " + str(old_record['ResourceRecords'])+"'")


            response = self.connection.change_resource_record_sets(
                HostedZoneId=zoneid,
                ChangeBatch={
                    'Comment': 'delete %s (%s) -> %s' % (record_fqdn, record_type, str(old_record['ResourceRecords'])),
                    'Changes': [
                        {
                            'Action': 'DELETE',
                            'ResourceRecordSet': {
                                'Name': record_fqdn,
                                'Type': record_type,
                                'TTL': old_record['TTL'],
                                'ResourceRecords': old_record['ResourceRecords']
                            }
                        }]
                })
            self.status = response['ChangeInfo']
            self.change_id = self.status['Id']
        except Exception as e:
            print(e)

        return True


    def deploy_acme_challenge(self,zone_name,record_fqdn,challenge):
        return self._create_record(zone_name,'_acme-challenge.'+record_fqdn,'TXT',challenge)

    def clean_acme_challenge(self,zone_name,record_fqdn):
        return self._delete_record(zone_name,'_acme-challenge.'+record_fqdn,'TXT')

    def clean_up(self):
        self = None