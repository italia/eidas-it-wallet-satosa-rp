from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.tools.base_logger import BaseLogger

class FederationHandler(TrustHandlerInterface, BaseLogger):
    def __init__(self, **kargs):
        pass

    def extract(self, issuer, trust_source):
        return trust_source

    def get_metadata(self, issuer, trust_source):
        return trust_source

    def verify():
        pass