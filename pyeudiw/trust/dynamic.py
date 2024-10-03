from typing import TypedDict

from pyeudiw.tools.utils import get_dynamic_class, satisfy_interface
from pyeudiw.trust.default import default_trust_evaluator
from pyeudiw.trust.exceptions import TrustConfigurationError
from pyeudiw.trust.interface import TrustEvaluator
from pyeudiw.trust._log import _package_logger


TrustModuleConfiguration_T = TypedDict("_DynamicTrustConfiguration", {"module": str, "class": str, "config": dict})


def dynamic_trust_evaluators_loader(trust_config: dict[str, TrustModuleConfiguration_T]) -> dict[str, TrustEvaluator]:
    """Load a dynamically importable/configurable set of TrustEvaluators,
    identified by the trust model they refer to.
    If not configurations a re given, a default is returned instead
    implementation of TrustEvaluator is returned instead.

    :return: a dictionary where the keys are common name identifiers
        for the trust mechanism ,a nd the keys are acqual class instances that satisfy
        the TrustEvaluator interface
    :rtype: dict[str, TrustEvaluator]
    """
    trust_instances: dict[str, TrustEvaluator] = {}
    if not trust_config:
        _package_logger.warning("no configured trust model, using direct trust model")
        trust_instances["direct_trust"] = default_trust_evaluator()
        return trust_instances

    for trust_model_name, trust_module_config in trust_config.items():
        try:
            uninstantiated_class: type[TrustEvaluator] = get_dynamic_class(trust_module_config["module"], trust_module_config["class"])
            class_config: dict = trust_module_config["config"]
            trust_evaluator_instance = uninstantiated_class(**class_config)
        except Exception as e:
            raise TrustConfigurationError(f"invalid configuration for {trust_model_name}: {e}", e)
        if not satisfy_interface(trust_evaluator_instance, TrustEvaluator):
            raise TrustConfigurationError(f"class {uninstantiated_class} does not satisfy the interface TrustEvaluator")
        trust_instances[trust_model_name] = trust_evaluator_instance
    return trust_instances


class CombinedTrustEvaluator(TrustEvaluator):
    """CombinedTrustEvaluator is a wrapper around multiple implementations of
    TrustEvaluator. It's primary purpose is to handle how multiple configured
    trust sources are queried when some metadata or key material is requested.
    """

    def __init__(self, trust_evaluators: dict[str, TrustEvaluator]):
        self.trust_evaluators: dict[str, TrustEvaluator] = trust_evaluators

    # def __iter__(self):
    #     for eval_identifier, eval_instance in self.trust_evaluators.items():
    #         yield (eval_identifier, eval_instance)

    def _get_trust_identifier_names(self) -> str:
        return '['+','.join(self.trust_evaluators.keys())+']'

    def get_public_keys(self, issuer: str) -> list[dict]:
        """
        yields the public cryptographic material of the issuer

        :returns: a list of jwk(s); note that those key are _not_ necessarely
            identified by a kid claim
        """
        pks: list[dict] = []
        for eval_identifier, eval_instance in self.trust_evaluators.items():
            pks = eval_instance.get_public_keys(issuer)
            if pks:
                return pks
        if not pks:
            raise Exception(f"no trust evaluator can provide cyptographic matrerial for {issuer}: searched among: {self._get_trust_identifier_names()}")

    def get_metadata(self, issuer: str) -> dict:
        """
        yields a dictionary of metadata about an issuer, according to some
        trust model.
        """
        md: dict = {}
        for eval_identifier, eval_instance in self.trust_evaluators.items():
            md = eval_instance.get_metadata(issuer)
            if md:
                return md
        if not md:
            raise Exception(f"no trust evaluator can provide metadata for {issuer}: searched among: {self._get_trust_identifier_names()}")

    def is_revoked(self, issuer: str) -> bool:
        """
        yield if the trust toward the issuer was revoked according to some trust model;
        this asusmed that  the isser exists, is valid, but is not trusted.
        """
        raise NotImplementedError("implementation details yet to be deifined for combined use")

    def get_policies(self, issuer: str) -> dict:
        raise NotImplementedError("reserved for future uses")
