import logging

from opendnssec_autorollover.handlers import Handler

class NullHandler(Handler):
    def run(self, changes):
        logging.debug('ignoring changes for zone %s', self.zone)
