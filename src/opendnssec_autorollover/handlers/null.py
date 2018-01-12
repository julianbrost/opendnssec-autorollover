import logging

from opendnssec_autorollover.handlers import Handler

logger = logging.getLogger(__name__)

class NullHandler(Handler):
    def run(self, changes):
        logger.debug('ignoring changes for zone %s', self.zone)
