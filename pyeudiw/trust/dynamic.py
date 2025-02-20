import logging
from typing import Any, Callable, Optional

import satosa.context
import satosa.response

from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.storage.exceptions import EntryNotFound
from pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.tools.utils import dynamic_class_loader
from pyeudiw.trust.exceptions import NoCriptographicMaterial, TrustConfigurationError
from pyeudiw.trust.handler.direct_trust_jar import DirectTrustJar
from pyeudiw.trust.handler.direct_trust_sd_jwt_vc import DirectTrustSdJwtVc
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData

logger = logging.getLogger(__name__)


class CombinedTrustEvaluator(BaseLogger):
    """
    A trust evaluator that combines multiple trust models.
    """

    def __init__(
        self, handlers: list[TrustHandlerInterface], db_engine: DBEngine
    ) -> None:
        """
        Initialize the CombinedTrustEvaluator.

        :param handlers: The trust handlers
        :type handlers: list[TrustHandlerInterface]
        :param db_engine: The database engine
        :type db_engine: DBEngine
        """
        self.db_engine: DBEngine = db_engine
        self.handlers: list[TrustHandlerInterface] = handlers
        self.handlers_names: list[str] = [e.name for e in self.handlers]

    def _retrieve_trust_source(self, issuer: str) -> Optional[TrustSourceData]:
        """
        Retrieve the trust source from the database.

        :param issuer: The issuer
        :type issuer: str

        :returns: The trust source
        :rtype: Optional[TrustSourceData]
        """
        try:
            trust_source = self.db_engine.get_trust_source(issuer)
            return TrustSourceData.from_dict(trust_source)
        except EntryNotFound:
            return None

    def _upsert_source_trust_materials(
        self, issuer: str, trust_source: Optional[TrustSourceData]
    ) -> TrustSourceData:
        """
        Extract the trust material of a certain issuer from all the trust handlers.
        If the trust material is not found for a certain issuer the structure remain unchanged.

        :param issuer: The issuer
        :type issuer: str

        :returns: The trust source
        :rtype: Optional[TrustSourceData]
        """

        if not trust_source:
            trust_source = TrustSourceData.empty(issuer)

        for handler in self.handlers:
            trust_source = handler.extract_and_update_trust_materials(
                issuer, trust_source
            )

        self.db_engine.add_trust_source(trust_source.serialize())

        return trust_source

    def _get_trust_source(self, issuer: str) -> TrustSourceData:
        """
        Retrieve the trust source from the database or extract it from the trust handlers.

        :param issuer: The issuer
        :type issuer: str

        :returns: The trust source
        :rtype: TrustSourceData
        """
        trust_source = self._retrieve_trust_source(issuer)

        if not trust_source or len(trust_source.trust_params.values()) == 0:
            trust_source = self._upsert_source_trust_materials(issuer, trust_source)

        return trust_source

    def get_public_keys(self, issuer: str) -> list[dict]:
        """
        Yields a list of public keys for an issuer, according to some trust model.

        :param issuer: The issuer
        :type issuer: str

        :returns: The public keys
        :rtype: list[dict]
        """
        trust_source = self._get_trust_source(issuer)

        if not trust_source.keys:
            raise NoCriptographicMaterial(
                f"no trust evaluator can provide cyptographic material "
                f"for {issuer}: searched among: {self.handlers_names}"
            )

        return trust_source.public_keys

    def get_metadata(self, issuer: str) -> dict:
        """
        Yields a dictionary of metadata about an issuer, according to some trust model.
        """
        trust_source = self._get_trust_source(issuer)

        if not trust_source.metadata:
            raise Exception(
                f"no trust evaluator can provide metadata for {issuer}: "
                f"searched among: {self.handlers_names}"
            )

        return trust_source.metadata

    def is_revoked(self, issuer: str) -> bool:
        """
        Yield if the trust toward the issuer was revoked according to some trust model;
        This asusmed that  the isser exists, is valid, but is not trusted.

        :param issuer: The issuer
        :type issuer: str

        :returns: If the trust toward the issuer was revoked
        :rtype: bool
        """
        trust_source = self._get_trust_source(issuer)
        return trust_source.is_revoked

    def get_policies(self, issuer: str) -> dict[str, any]:
        """
        Get the policies of a certain issuer according to some trust model.

        :param issuer: The issuer
        :type issuer: str

        :returns: The policies
        :rtype: dict[str, any]
        """
        trust_source = self._get_trust_source(issuer)

        if not trust_source.policies:
            raise Exception(
                f"no trust evaluator can provide policies for {issuer}: "
                f"searched among: {self.handlers_names}"
            )

        return trust_source.policies

    def get_selfissued_jwt_header_trust_parameters(self, issuer: str) -> list[dict]:
        """
        Get the trust parameters of a certain issuer according to some trust model.

        :param issuer: The issuer
        :type issuer: str

        :returns: The trust parameters
        :rtype: list[dict]
        """
        trust_source = self._get_trust_source(issuer)

        return {
            _typ: param.trust_params
            for _typ, param in trust_source.trust_params.items()
        }

    def build_metadata_endpoints(
        self, backend_name: str, entity_uri: str
    ) -> list[
        tuple[str, Callable[[satosa.context.Context, Any], satosa.response.Response]]
    ]:
        endpoints = []
        for handler in self.handlers:
            endpoints += handler.build_metadata_endpoints(backend_name, entity_uri)
        # Partially check for collissions in managed paths: this might happen if multiple configured
        # trust frameworks want to handle the same endpoints (check is not 100% exhaustive as paths are actually regexps)
        all_paths = [path for path, *_ in endpoints]
        if len(all_paths) > len(set(all_paths)):
            self._log_warning(
                "build_metadata_endpoints",
                f"found collision in metadata endpoint: {all_paths}",
            )
        return endpoints

    @staticmethod
    def from_config(
        config: dict, db_engine: DBEngine, default_client_id: str
    ) -> "CombinedTrustEvaluator":
        """
        Create a CombinedTrustEvaluator from a configuration.

        :param config: The configuration
        :type config: dict
        :param db_engine: The database engine
        :type db_engine: DBEngine

        :returns: The CombinedTrustEvaluator
        :rtype: CombinedTrustEvaluator
        """
        handlers = []

        for handler_name, handler_config in config.items():
            try:
                # every trust evaluation method might use their own client id
                # but a default one always therefore required
                if not handler_config["config"].get("client_id"):
                    handler_config["config"]["client_id"] = default_client_id

                trust_handler = dynamic_class_loader(
                    handler_config["module"],
                    handler_config["class"],
                    handler_config["config"],
                )
            except Exception as e:
                raise TrustConfigurationError(
                    f"invalid configuration for {handler_name}: {e}", e
                )

            if not isinstance(trust_handler, TrustHandlerInterface):
                raise TrustConfigurationError(
                    f"class {trust_handler.__class__} does not satisfy the interface TrustEvaluator"
                )

            handlers.append(trust_handler)
            logger.debug(
                f"TrustHandlers loaded: [{', '.join([str(i.__class__) for i in handlers])}]."
            )

        if not handlers:
            logger.warning("No configured trust model, using direct trust model")
            handlers.append(DirectTrustSdJwtVc())
            handlers.append(DirectTrustJar())

        return CombinedTrustEvaluator(handlers, db_engine)
