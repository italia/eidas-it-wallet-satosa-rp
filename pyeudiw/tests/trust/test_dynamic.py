from uuid import uuid4

from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tests.settings import CONFIG
from pyeudiw.tests.trust import correct_config, not_conformant
from pyeudiw.tests.trust.mock_trust_handler import MockTrustHandler
from pyeudiw.trust.dynamic import CombinedTrustEvaluator
from pyeudiw.trust.exceptions import TrustConfigurationError
from pyeudiw.trust.handler.direct_trust_sd_jwt_vc import DirectTrustSdJwtVc


def test_trust_CombinedTrusstEvaluation_handler_loading():
    trust_ev = CombinedTrustEvaluator.from_config(
        correct_config,
        DBEngine(CONFIG["storage"]),
        default_client_id="default-client-id",
    )

    assert trust_ev
    assert len(trust_ev.handlers) == 2
    assert isinstance(trust_ev.handlers[0], MockTrustHandler)
    assert isinstance(trust_ev.handlers[1], DirectTrustSdJwtVc)


def test_not_conformant_CombinedTrusstEvaluation_handler_loading():
    try:
        CombinedTrustEvaluator.from_config(
            not_conformant,
            DBEngine(CONFIG["storage"]),
            default_client_id="default-client-id",
        )
        assert False
    except TrustConfigurationError:
        assert True


def test_if_no_conf_default_handler_instanciated():
    trust_ev = CombinedTrustEvaluator.from_config(
        {}, DBEngine(CONFIG["storage"]), default_client_id="default-client-id"
    )
    # both jar issuer and direct trust sd jwt vc are default if not trust handlers are configured
    assert len(trust_ev.handlers) == 2
    assert isinstance(trust_ev.handlers[0], DirectTrustSdJwtVc)


def test_public_key_and_metadata_retrive():
    db_engine = DBEngine(CONFIG["storage"])

    trust_ev = CombinedTrustEvaluator.from_config(
        {
            "mock": {
                "module": "pyeudiw.tests.trust.mock_trust_handler",
                "class": "MockTrustHandler",
                "config": {},
            },
                
        }, db_engine, default_client_id="default-client-id"
    )

    uuid_url = f"http://{uuid4()}.issuer.it"

    pub_keys = trust_ev.get_public_keys(uuid_url)
    trust_source = db_engine.get_trust_source(uuid_url)

    assert trust_source
    assert (
        trust_source["keys"][0]["kid"] == "qTo9RGpuU_CSolt6GZmndLyPXJJa48up5dH1YbxVDPs"
    )
    assert trust_source["metadata"] == {"json_key": "json_value"}

    assert pub_keys[0]["kid"] == "qTo9RGpuU_CSolt6GZmndLyPXJJa48up5dH1YbxVDPs"

    metadata = trust_ev.get_metadata(uuid_url)

    assert metadata == {"json_key": "json_value"}

    assert trust_ev.get_selfissued_jwt_header_trust_parameters(uuid_url) == {'trust_param': {'trust_param_key': 'trust_param_value'}}
