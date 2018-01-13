import logging

from opendnssec_autorollover.handlers import Handler, register_handler

logger = logging.getLogger(__name__)

@register_handler('null')
class NullHandler(Handler):
    def run(self, changes):
        logger.debug('ignoring changes for zone %s', self.zone)
