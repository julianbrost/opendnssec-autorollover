from configparser import ConfigParser
import logging

logging.basicConfig(level=logging.DEBUG)

from opendnssec_autorollover.opendnssec import get_pending_dnskey_changes, get_pending_ds_changes, notify_ds
from opendnssec_autorollover.ds_lookup import get_ds_sets

class AutoRollover:
    def __init__(self):
        self.handlers = dict()
        self.register_handlers()
        self.read_config()

    def register_handler(self, name, handler):
        self.handlers[name] = handler

    def register_handlers(self):
        from opendnssec_autorollover.handlers.null import NullHandler
        self.register_handler('null', NullHandler())
        from opendnssec_autorollover.handlers.hosting_de import HostingDeHandler
        self.register_handler('hosting.de', HostingDeHandler())

    def get_handler(self, name):
        return self.handlers[name]

    def get_zone_config(self, zone):
        if self.config.has_section(zone):
            return self.config[zone]
        else:
            return self.config['*']

    def read_config(self):
        self.config = ConfigParser()
        self.config.read('config.ini')

    def handle_zone_dnskey(self, zone, changes):
        logging.debug('Handling zone %s', zone)
        zone_config = self.get_zone_config(zone)
        handler = self.get_handler(zone_config['handler'])
        logging.debug('Using handler %s', repr(handler))
        handler.handle(zone, zone_config, changes)

    def handle_zone_ds(self, zone, changes):
        logging.debug('Looking up DS records for %s in its parent', zone)
        ds_sets = get_ds_sets(zone)
        union = set.union(*ds_sets)
        intersection = set.intersection(*ds_sets)

        logging.debug('DS present on some parent nameserver: %s', union)
        logging.debug('DS present on all parent nameservers: %s', intersection)

        for state, ds in changes:
            keytag, key_alg, hash_alg, hash_value = ds

            if state == 'ready' and ds in intersection:
                logging.debug('Issuing ds-seen for %s/%d', zone, keytag)
                notify_ds(zone, keytag, 'seen')

            if state == 'retire' and ds not in union:
                logging.debug('Issuing ds-gone for %s/%d', zone, keytag)
                notify_ds(zone, keytag, 'gone')

    def run(self):
        # push out changed DNSKEYs
        for zone, changes in get_pending_dnskey_changes().items():
            self.handle_zone_dnskey(zone, changes)

        # update OpenDNSSEC internal state using ds-seen and ds-gone
        for zone, changes in get_pending_ds_changes().items():
            self.handle_zone_ds(zone, changes)

def main():
    AutoRollover().run()
