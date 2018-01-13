import logging

class Handler:
    zone = None
    config = None

    @classmethod
    def pre_hook(cls):
        pass

    @classmethod
    def post_hook(cls):
        pass

    def __init__(self, zone, config):
        self.zone = zone
        self.config = config

    def run(self, changes):
        raise NotImplementedError

all_handlers = dict()

def register_handler(name):
    def decorator(cls):
        assert name not in all_handlers
        all_handlers[name] = cls
        return cls
    return decorator
