import logging
import requests

API_DOMAIN_INFO = 'https://secure.hosting.de/api/domain/v1/json/domainInfo'
API_DOMAIN_UPDATE = 'https://secure.hosting.de/api/domain/v1/json/domainUpdate'

class HostingDeHandler:

    def res_check(self, res):
        assert res.status_code == 200
        res = res.json()
        for w in res.get('warnings', []):
            logging.warning('hosting.de API: %s', w)
        for e in res.get('errors', []):
            logging.error('hosting.de API: %s', e)
        assert res['status'] in ['success', 'pending']
        return res

    def get_domain(self, config, domain):
        req = {
            'authToken': config['auth_token'],
            'domainName': domain,
        }
        res = self.res_check(requests.post(API_DOMAIN_INFO, json=req))
        domain_obj = res['response']
        return domain_obj

    def make_key_delta(self, current_dnskeys, changes):
        dnskey_add = []
        dnskey_remove = []

        current = set() # (flags, alg, pubkey)
        for key in current_dnskeys:
            flags = key['keyData']['flags']
            alg = key['keyData']['algorithm']
            pub = key['keyData']['publicKey']
            current.add((flags, alg, pub))

        for state, key in changes:
            flags, alg, pub = key

            if state == 'ready' and key not in current:
                logging.debug('add: %s', key)
                dnskey_add.append({'keyData': {'flags': flags, 'protocol': 3, 'algorithm': alg, 'publicKey': pub}})

            if state == 'retire' and key in current:
                logging.debug('remove: %s', key)
                dnskey_remove.append({'keyData': {'flags': flags, 'protocol': 3, 'algorithm': alg, 'publicKey': pub}})

        return dnskey_add, dnskey_remove

    def update_domain(self, config, domain_obj, dnskey_add, dnskey_remove):
        change = False

        req = {
            'authToken': config['auth_token'],
            'domain': domain_obj,
        }

        if dnskey_add:
            req['dnsSecKeyAdd'] = dnskey_add
            change = True

        if dnskey_remove:
            req['dnsSecKeyRemove'] = dnskey_remove
            change = True

        if change:
            res = self.res_check(requests.post(API_DOMAIN_UPDATE, json=req))
            logging.debug('updated domain: %s', res)

    def handle(self, zone, config, changes):
        domain = zone.rstrip('.')
        domain_obj = self.get_domain(config, domain)
        current_dnskeys = domain_obj['dnsSecEntries']
        dnskey_add, dnskey_remove = self.make_key_delta(current_dnskeys, changes)
        self.update_domain(config, domain_obj, dnskey_add, dnskey_remove)
