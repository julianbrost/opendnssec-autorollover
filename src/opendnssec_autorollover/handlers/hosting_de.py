import logging
import requests
import time

from opendnssec_autorollover.handlers import Handler, register_handler

logger = logging.getLogger(__name__)

API_BASE = 'https://secure.hosting.de/api'

API_DOMAIN_DNSSEC_KEYS_LIST = 'domain/v1/json/dnsSecKeysList'
API_DOMAIN_DNSSEC_KEYS_MODIFY = 'domain/v1/json/dnsSecKeyModify'
API_DOMAIN_JOBS_FIND = 'domain/v1/json/jobsFind'

def dnskey_to_api(key):
    flags, alg, pub = key
    return {
        'keyData': {
            'flags': flags,
            'protocol': 3,
            'algorithm': alg,
            'publicKey': pub,
        }
    }

def dnskey_from_api(key):
    flags = key['keyData']['flags']
    alg = key['keyData']['algorithm']
    pub = key['keyData']['publicKey']
    return (flags, alg, pub)

@register_handler('hosting.de')
class HostingDeHandler(Handler):

    @property
    def api_base(self):
        return self.config.get('api_base', API_BASE)

    def api_request(self, method, req=None, sync_wait=10):
        url = '{}/{}'.format(self.api_base, method)
        if req is None:
            req = dict()
        if not 'authToken' in req:
            req = dict(req, authToken=self.config['api_key'])
        res = requests.post(url, json=req)
        assert res.status_code == 200
        res = res.json()
        for w in res.get('warnings', []):
            logger.warning('hosting.de API: %s', w)
        for e in res.get('errors', []):
            logger.error('hosting.de API: %s', e)
        if sync_wait and res['status'] == 'pending':
            for t in range(1, sync_wait+1):
                logger.debug('waiting %d second(s) for background job to complete', t)
                time.sleep(t)
                state = self.get_job(res['metadata']['serverTransactionId'])['state']
                logger.debug('job state: %s', state)
                if state == 'successful':
                    return res
            raise Exception('background job did not finish in time')
        if res['status'] not in ['success', 'pending']:
            raise Exception('hosting.de API returned status "{}"'.format(res['status']), res)
        return res

    def get_dnskeys(self):
        req = {'domainName': self.zone}
        res = self.api_request(API_DOMAIN_DNSSEC_KEYS_LIST, req)
        return set(dnskey_from_api(k) for k in res['responses'])

    def get_job(self, server_transaction_id):
        req = {
            'filter': {
                'field': 'JobServerTransactionId',
                'value': server_transaction_id,
            }
        }
        res = self.api_request(API_DOMAIN_JOBS_FIND, req, sync_wait=False)
        assert res['response']['totalEntries'] == 1
        assert len(res['response']['data']) == 1
        return res['response']['data'][0]

    def update_dnskeys(self, add=None, remove=None):
        if not (add or remove):
            logger.debug('%s: nothing to update, skipping', self.zone)
            return

        req = {'domainName': self.zone}
        if add:
            req['add'] = [dnskey_to_api(k) for k in add]
        if remove:
            req['remove'] = [dnskey_to_api(k) for k in remove]
        return self.api_request(API_DOMAIN_DNSSEC_KEYS_MODIFY, req)

    def make_key_delta(self, current_dnskeys, changes):
        dnskey_add = []
        dnskey_remove = []

        for state, key in changes:
            if state == 'ready' and key not in current_dnskeys:
                logger.debug('add: %s', key)
                dnskey_add.append(key)
            if state == 'retire' and key in current_dnskeys:
                logger.debug('remove: %s', key)
                dnskey_remove.append(key)

        return dnskey_add, dnskey_remove

    def run(self, changes):
        current_dnskeys = self.get_dnskeys()
        logger.debug('%s: current: %s', self.zone, current_dnskeys)
        add, remove = self.make_key_delta(current_dnskeys, changes)
        logger.debug('%s: add: %s', self.zone, add)
        logger.debug('%s: remove: %s', self.zone, remove)
        self.update_dnskeys(add=add, remove=remove)
