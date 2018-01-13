from configparser import ConfigParser
from argparse import ArgumentParser
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

from opendnssec_autorollover.opendnssec import get_pending_dnskey_changes, get_pending_ds_changes, notify_ds
from opendnssec_autorollover.ds_lookup import get_ds_sets

class AutoRollover:
    def __init__(self):
        self.handlers = dict()
        self.register_handlers()
        self.parse_args()
        self.read_config()

    def register_handler(self, name, handler):
        self.handlers[name] = handler

    def register_handlers(self):
        # TODO: build some import magic for this?
        import opendnssec_autorollover.handlers.null
        import opendnssec_autorollover.handlers.hosting_de
        import opendnssec_autorollover.handlers.gandi_net

        # The above imports all use a @register_handler decorator which adds
        # the handlers to the following all_handlers dict.
        from opendnssec_autorollover.handlers import all_handlers
        for name, handler in all_handlers.items():
            self.register_handler(name, handler)

    def call_handler_hooks(self, name):
        method = '{}_hook'.format(name)
        for handler in self.handlers.values():
            hook = getattr(handler, method)
            hook()

    def get_handler(self, name):
        return self.handlers[name]

    def parse_args(self):
        parser = ArgumentParser(prog='opendnssec-autorollover', description='Automate parent zone updates with OpenDNSSEC')
        parser.add_argument('--config', metavar='CONFIG', default='config.ini', help='path to the config file to load')
        self.args = parser.parse_args()

    def read_config(self):
        self.config = ConfigParser()
        self.config.read(self.args.config)

    def get_zone_config(self, zone):
        if self.config.has_section(zone):
            return self.config[zone]
        else:
            return self.config['*']

    def handle_zone_dnskey(self, zone, changes):
        logger.debug('Handling zone %s', zone)
        zone_config = self.get_zone_config(zone)
        handler = self.get_handler(zone_config['handler'])
        logger.debug('Using handler %s', repr(handler))
        handler(zone, zone_config).run(changes)

    def handle_zone_ds(self, zone, changes):
        logger.debug('Looking up DS records for %s in its parent', zone)
        ds_sets = get_ds_sets(zone)
        union = set.union(*ds_sets)
        intersection = set.intersection(*ds_sets)

        logger.debug('DS present on some parent nameserver: %s', union)
        logger.debug('DS present on all parent nameservers: %s', intersection)

        for state, ds in changes:
            keytag, key_alg, hash_alg, hash_value = ds

            if state == 'ready' and ds in intersection:
                logger.debug('Issuing ds-seen for %s/%d', zone, keytag)
                notify_ds(zone, keytag, 'seen')

            if state == 'retire' and ds not in union:
                logger.debug('Issuing ds-gone for %s/%d', zone, keytag)
                notify_ds(zone, keytag, 'gone')

    def run(self):
        # push out changed DNSKEYs
        self.call_handler_hooks('pre')
        for zone, changes in get_pending_dnskey_changes().items():
            self.handle_zone_dnskey(zone, changes)
        self.call_handler_hooks('post')

        # update OpenDNSSEC internal state using ds-seen and ds-gone
        for zone, changes in get_pending_ds_changes().items():
            self.handle_zone_ds(zone, changes)

def main():
    AutoRollover().run()
