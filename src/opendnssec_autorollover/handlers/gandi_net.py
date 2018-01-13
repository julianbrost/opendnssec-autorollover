import logging
import xmlrpc.client

from opendnssec_autorollover.handlers import Handler, register_handler

logger = logging.getLogger(__name__)

API_ENDPOINT = 'https://rpc.gandi.net/xmlrpc/'

@register_handler('gandi.net')
class GandiNetHandler(Handler):

    def get_dnskeys(self, config, domain):
        with xmlrpc.client.ServerProxy(API_ENDPOINT) as api:
            return api.domain.dnssec.list(config['api_key'], domain)

    def make_key_delta(self, current_dnskeys, changes):
        dnskey_add = []
        dnskey_remove = []

        current = {} # (flags, alg, pubkey) -> id
        for key in current_dnskeys:
            flags = key['flags']
            alg = key['algorithm']
            pub = key['public_key']
            current[(flags, alg, pub)] = key['id']

        for state, key in changes:
            if state == 'ready' and key not in current:
                flags, alg, pub = key
                dnskey_add.append({'flags': flags, 'algorithm': alg, 'public_key': pub})

            if state == 'retire' and key in current:
                dnskey_remove.append(current[key])

        return dnskey_add, dnskey_remove

    def update_dnskeys(self, config, domain, dnskey_add, dnskey_remove):
        if not (dnskey_add or dnskey_remove):
            # nothing to do
            return

        with xmlrpc.client.ServerProxy(API_ENDPOINT) as api:
            for key in dnskey_add:
                logger.debug('%s: adding key %s', domain, key)
                api.domain.dnssec.create(config['api_key'], domain, key)

            for key in dnskey_remove:
                logger.debug('%s: removing key %s', domain, key)
                api.domain.dnssec.delete(config['api_key'], key)

    def handle(self, zone, config, changes):
        current_dnskeys = self.get_dnskeys(config, zone)
        dnskey_add, dnskey_remove = self.make_key_delta(current_dnskeys, changes)
        self.update_dnskeys(config, zone, dnskey_add, dnskey_remove)

    # TODO: remove
    def run(self, changes):
        self.handle(self.zone, self.config, changes)
