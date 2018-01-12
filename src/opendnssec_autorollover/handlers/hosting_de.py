import logging
import requests

from opendnssec_autorollover.handlers import Handler

API_BASE = 'https://secure.hosting.de/api'

API_DOMAIN_DNSSEC_KEYS_LIST = 'domain/v1/json/dnsSecKeysList'
API_DOMAIN_DNSSEC_KEYS_MODIFY = 'domain/v1/json/dnsSecKeyModify'

def res_check(res):
    return res

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

class HostingDeHandler(Handler):

    def __init__(self, zone, config):
        super(HostingDeHandler, self).__init__(zone, config)
        self.domain = zone.rstrip('.')

    @property
    def api_base(self):
        return self.config.get('api_base', API_BASE)

    def api_request(self, method, req=None):
        url = '{}/{}'.format(self.api_base, method)
        if req is None:
            req = dict()
        if not 'authToken' in req:
            req = dict(req, authToken=self.config['auth_token'])
        res = res_check(requests.post(url, json=req))
        assert res.status_code == 200
        res = res.json()
        for w in res.get('warnings', []):
            logging.warning('hosting.de API: %s', w)
        for e in res.get('errors', []):
            logging.error('hosting.de API: %s', e)
        if res['status'] not in ['success', 'pending']:
            raise Exception('hosting.de API returned status "{}"'.format(res['status']), res)
        return res

    def get_dnskeys(self):
        req = {'domainName': self.domain}
        res = self.api_request(API_DOMAIN_DNSSEC_KEYS_LIST, req)
        return set(dnskey_from_api(k) for k in res['responses'])

    def update_dnskeys(self, add=None, remove=None):
        if not (add or remove):
            logging.debug('%s: nothing to update, skipping', self.domain)
            return

        req = {'domainName': self.domain}
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
                logging.debug('add: %s', key)
                dnskey_add.append(key)
            if state == 'retire' and key in current_dnskeys:
                logging.debug('remove: %s', key)
                dnskey_remove.append(key)

        return dnskey_add, dnskey_remove

    def run(self, changes):
        current_dnskeys = self.get_dnskeys()
        logging.debug('%s: current: %s', self.domain, current_dnskeys)
        add, remove = self.make_key_delta(current_dnskeys, changes)
        logging.debug('%s: add: %s', self.domain, add)
        logging.debug('%s: remove: %s', self.domain, remove)
        self.update_dnskeys(add=add, remove=remove)
