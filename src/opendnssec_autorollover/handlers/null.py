import logging

from opendnssec_autorollover.handlers import HandlerBase

class NullHandler(HandlerBase):
    def run(self, changes):
        logging.debug('ignoring changes for zone %s', self.zone)
