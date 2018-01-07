import logging

class NullHandler:
    def handle(self, zone, config, changes):
        logging.debug('ignoring changes for zone %s', zone)
