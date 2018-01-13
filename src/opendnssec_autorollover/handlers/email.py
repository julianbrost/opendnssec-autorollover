import logging
import re
from collections import defaultdict

from opendnssec_autorollover.handlers import Handler, register_handler

logger = logging.getLogger(__name__)

# regex to match "to" and "to[*]"
RE_TO_OPT = re.compile(r'^to(\[.*\])?$')

@register_handler('email')
class EmailHandler(Handler):
    """
    Handler for sending changes via e-mail

    Configuration example for a single recipient:
    
        [example.org]
        handler = email
        to = julian@example.com

    Configuration example for multiple recipients, the handler doesn't care for
    the string within the brackets, it just has to be unique:
    
        [example.org]
        handler = email
        to[a] = julian@example.com
        to[b] = john@example.com
    """

    @classmethod
    def pre_hook(cls):
        cls.changes = defaultdict(lambda: defaultdict(list))

    @classmethod
    def post_hook(cls):
        for recipient, zones in cls.changes.items():
            logger.debug('TODO: send e-mail to %s', recipient)
            for zone, changes in zones.items():
                logger.debug('  %s', zone)
                for change in changes:
                    logger.debug('    %s', change)

    def run(self, changes):
        recipients = [v for k, v in self.config.items() if RE_TO_OPT.match(k)]
        for change in changes:
            for recipient in recipients:
                self.changes[recipient][self.zone].append(change)

# TODO: This handler is not functional yet. It is more like a proof of concept
# showing pre_hook and post_hook.
