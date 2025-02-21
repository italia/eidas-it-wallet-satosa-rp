import uuid
import base64
import datetime
import json
import urllib.parse
from unittest.mock import Mock, patch

import pytest
from bs4 import BeautifulSoup
from cryptojwt.jws.jws import JWS
from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload
from pyeudiw.oauth2.dpop import DPoPIssuer
from pyeudiw.satosa.backend import OpenID4VPBackend
from pyeudiw.storage.base_storage import TrustType
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.jwt.jws_helper import DEFAULT_SIG_KTY_MAP
from pyeudiw.tests.federation.base import (
    EXP,
    NOW,
    leaf_cred_jwk_prot,
    leaf_wallet_jwk,
    ta_ec,
    ta_ec_signed,
    ta_jwk,
    trust_chain_wallet,
)
from pyeudiw.tests.settings import (
    BASE_URL,
    CONFIG,
    CREDENTIAL_ISSUER_CONF,
    CREDENTIAL_ISSUER_ENTITY_ID,
    INTERNAL_ATTRIBUTES,
    PRIVATE_JWK,
    WALLET_INSTANCE_ATTESTATION,
)
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData
from pyeudiw.jwk import JWK
from pyeudiw.sd_jwt.utils.yaml_specification import _yaml_load_specification
from pyeudiw.sd_jwt.issuer import SDJWTIssuer
from pyeudiw.sd_jwt.holder import SDJWTHolder
from pyeudiw.tools.utils import exp_from_now, iat_now
from pyeudiw.jwt.jwe_helper import JWEHelper


def issue_sd_jwt(specification: dict, settings: dict, issuer_key: JWK, holder_key: JWK) -> str:
    claims = {
        "iss": settings["issuer"],
        "iat": iat_now(),
        "exp": exp_from_now(settings["default_exp"])  # in seconds
    }

    specification.update(claims)
    use_decoys = specification.get("add_decoy_claims", True)
    #adapted_keys = _adapt_keys(issuer_key, holder_key)

    additional_headers = {}
    #additional_headers = {"trust_chain": trust_chain} if trust_chain else {}
    additional_headers['kid'] = issuer_key["kid"]

    sdjwt_at_issuer = SDJWTIssuer(
        user_claims=specification,
        issuer_keys=[issuer_key],
        holder_key=holder_key,
        add_decoy_claims=use_decoys,
        extra_header_parameters=additional_headers
    )

    return {"jws": sdjwt_at_issuer.serialized_sd_jwt, "issuance": sdjwt_at_issuer.sd_jwt_issuance}


class TestOpenID4VPBackend:

    @pytest.fixture(autouse=True)
    def create_backend(self):

        db_engine_inst = DBEngine(CONFIG["storage"])

        # TODO - not necessary if federation is not tested
        db_engine_inst.add_trust_anchor(
            entity_id=ta_ec["iss"],
            entity_configuration=ta_ec_signed,
            exp=EXP,
        )

        issuer_jwk = leaf_cred_jwk_prot.serialize(private=True)

        db_engine_inst.add_or_update_trust_attestation(
            entity_id=CREDENTIAL_ISSUER_ENTITY_ID,
            trust_type=TrustType.DIRECT_TRUST_SD_JWT_VC,
            jwks=[issuer_jwk],
        )

        tsd = TrustSourceData.empty(CREDENTIAL_ISSUER_ENTITY_ID)
        tsd.add_key(issuer_jwk)

        db_engine_inst.add_trust_source(tsd.serialize())

        self.backend = OpenID4VPBackend(
            Mock(), INTERNAL_ATTRIBUTES, CONFIG, BASE_URL, "name"
        )

        url_map = self.backend.register_endpoints()
        assert len(url_map) == 7

    @pytest.fixture
    def internal_attributes(self):
        return {
            "attributes": {
                "givenname": {"openid": ["given_name"]},
                "mail": {"openid": ["email"]},
                "edupersontargetedid": {"openid": ["sub"]},
                "surname": {"openid": ["family_name"]},
            }
        }

    @pytest.fixture
    def context(self):
        context = Context()
        context.target_frontend = "someFrontend"
        context.state = State()
        return context

    def test_backend_init(self):
        assert self.backend.name == "name"

    # TODO: Move to trust evaluation handlers tests
    def test_entity_configuration(self, context):
        context.qs_params = {}

        _fedback: TrustHandlerInterface = self.backend.get_trust_backend_by_class_name(
            "FederationHandler"
        )
        assert _fedback

        entity_config = _fedback.entity_configuration_endpoint(context)
        assert entity_config
        assert entity_config.status == "200"
        assert entity_config.message

        # TODO: decode EC jwt, validate signature and both header and payload schema validation

    def test_pre_request_without_frontend(self):
        context = Context()
        context.state = State()
        context.http_headers = dict(
            HTTP_USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36"
        )
        resp = self.backend.pre_request_endpoint(context, InternalData())
        assert resp is not None
        assert resp.status == "400"
        assert resp.message is not None

    def test_pre_request_endpoint(self, context):
        internal_data = InternalData()
        context.http_headers = dict(
            HTTP_USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36"
        )
        pre_request_endpoint = self.backend.pre_request_endpoint(context, internal_data)
        assert pre_request_endpoint
        assert pre_request_endpoint.status == "200"
        assert pre_request_endpoint.message

        assert "src='data:image/svg+xml;base64," in pre_request_endpoint.message

        soup = BeautifulSoup(pre_request_endpoint.message, "html.parser")
        # get the img tag with src attribute starting with data:image/svg+xml;base64,
        img_tag = soup.find(
            lambda tag: tag.name == "img"
            and tag.get("src", "").startswith("data:image/svg+xml;base64,")
        )
        assert img_tag
        # get the src attribute
        src = img_tag["src"]
        # remove the data:image/svg+xml;base64, part
        data = src.replace("data:image/svg+xml;base64,", "")
        # decode the base64 data
        base64.b64decode(data).decode("utf-8")

        # get the div with id "state"
        state_div = soup.find("div", {"id": "state"})
        assert state_div
        assert state_div["value"]

    def test_pre_request_endpoint_mobile(self, context):
        internal_data = InternalData()
        context.http_headers = dict(
            HTTP_USER_AGENT="Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.92 Mobile Safari/537.36"
        )
        pre_request_endpoint = self.backend.pre_request_endpoint(context, internal_data)
        assert pre_request_endpoint
        assert "302" in pre_request_endpoint.status

        assert (
            f"{CONFIG['authorization']['url_scheme']}://"
            in pre_request_endpoint.message
        )

        unquoted = urllib.parse.unquote(
            pre_request_endpoint.message, encoding="utf-8", errors="replace"
        )
        parsed = urllib.parse.urlparse(unquoted)

        assert parsed.scheme == CONFIG["authorization"]["url_scheme"]
        assert parsed.path == ""
        assert parsed.query

        qs = urllib.parse.parse_qs(parsed.query)
        assert qs["client_id"][0] == CONFIG["metadata"]["client_id"]
        assert qs["request_uri"][0].startswith(CONFIG["metadata"]["request_uris"][0])

    def test_vp_validation_in_response_endpoint(self, context):
        self.backend.register_endpoints()

        issuer_jwk = leaf_cred_jwk_prot.serialize(private=True)
        holder_jwk = leaf_wallet_jwk.serialize(private=True)

        settings = CREDENTIAL_ISSUER_CONF
        settings['issuer'] = CREDENTIAL_ISSUER_ENTITY_ID
        settings['default_exp'] = CONFIG['jwt']['default_exp']

        sd_specification = _yaml_load_specification(
            settings["sd_specification"])

        issued_jwt = issue_sd_jwt(
            sd_specification,
            settings,
            issuer_jwk,
            holder_jwk,
            #additional_headers={"typ": "vc+sd-jwt"}
        )

        sdjwt_at_holder = SDJWTHolder(
            issued_jwt["issuance"],
            serialization_format="compact",
        )

        nonce = str(uuid.uuid4())
        sdjwt_at_holder.create_presentation(
            {},
            nonce,
            self.backend.client_id,
            holder_key=holder_jwk,
            sign_alg=DEFAULT_SIG_KTY_MAP[holder_jwk["kty"]],
        )

        vp_token = sdjwt_at_holder.sd_jwt_presentation
        context.request_method = "POST"
        context.request_uri = CONFIG["metadata"]["response_uris"][0].removeprefix(
            CONFIG["base_url"])
        

        state = str(uuid.uuid4())
        response = {
            "state": state,
            "vp_token": vp_token,
            "presentation_submission": {
                "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "id": "04a98be3-7fb0-4cf5-af9a-31579c8b0e7d",
                "descriptor_map": [
                    {
                        "id": "pid-sd-jwt:unique_id+given_name+family_name",
                        "path": "$.vp_token.verified_claims.claims._sd[0]",
                        "format": "vc+sd-jwt"
                    }
                ]
            }
        }
        session_id = context.state["SESSION_ID"]
        self.backend.db_engine.init_session(
            state=state,
            session_id=session_id,
            remote_flow_typ="same_device"
        )
        doc_id = self.backend.db_engine.get_by_state(state)["document_id"]

        # Put a different nonce in the stored request object.
        # This will trigger a `VPInvalidNonce` error
        self.backend.db_engine.update_request_object(
            document_id=doc_id,
            request_object={"nonce": str(uuid.uuid4()), "state": state})

        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]).encrypt(response)
        
        context.request = {
            "response": encrypted_response
        }

        context.http_headers = {"HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}
        response_endpoint = self.backend.response_endpoint(context)
        assert response_endpoint.status == "400"
        msg = json.loads(response_endpoint.message)
        assert msg["error"] == "invalid_request"
        assert msg["error_description"]

        # This will trigger a `UnicodeDecodeError` which will be caught by the generic `Exception case`.
        response["vp_token"] = "asd.fgh.jkl"
        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]).encrypt(response)
        context.request = {
            "response": encrypted_response
        }
        response_endpoint = self.backend.response_endpoint(context)
        assert response_endpoint.status == "400"
        msg = json.loads(response_endpoint.message)
        assert msg["error"] == "invalid_request"
        assert msg["error_description"]

    def test_response_endpoint(self, context):
        self.backend.register_endpoints()

        issuer_jwk = leaf_cred_jwk_prot.serialize(private=True)
        holder_jwk = leaf_wallet_jwk.serialize(private=True)

        settings = CREDENTIAL_ISSUER_CONF
        settings['issuer'] = CREDENTIAL_ISSUER_ENTITY_ID
        settings['default_exp'] = CONFIG['jwt']['default_exp']

        sd_specification = _yaml_load_specification(
            settings["sd_specification"])
        
        issued_jwt = issue_sd_jwt(
            sd_specification,
            settings,
            issuer_jwk,
            holder_jwk,
            #additional_headers={"typ": "vc+sd-jwt"}
        )

        sdjwt_at_holder = SDJWTHolder(
            issued_jwt["issuance"],
            serialization_format="compact",
        )

        nonce = str(uuid.uuid4())
        state = str(uuid.uuid4())
        aud = self.backend.client_id

        session_id = context.state["SESSION_ID"]
        self.backend.db_engine.init_session(
            state=state,
            session_id=session_id,
            remote_flow_typ="same_device"
        )
        doc_id = self.backend.db_engine.get_by_state(state)["document_id"]

        self.backend.db_engine.update_request_object(
            document_id=doc_id,
            request_object={"nonce": nonce, "state": state})

        bad_nonce = str(uuid.uuid4())
        bad_state = str(uuid.uuid4())
        bad_aud = str(uuid.uuid4())

        # case (1): bad nonce
        sdjwt_at_holder.create_presentation(
            {},
            bad_nonce,
            self.backend.client_id,
            holder_key=holder_jwk,
            sign_alg=DEFAULT_SIG_KTY_MAP[holder_jwk["kty"]],
        )

        vp_token_bad_nonce = sdjwt_at_holder.sd_jwt_presentation

        context.request_method = "POST"
        context.request_uri = CONFIG["metadata"]["response_uris"][0].removeprefix(
            CONFIG["base_url"])

        response_with_bad_nonce = {
            "state": state,
            "vp_token": vp_token_bad_nonce,
            "presentation_submission": {
                "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "id": "04a98be3-7fb0-4cf5-af9a-31579c8b0e7d",
                "descriptor_map": [
                    {
                        "id": "pid-sd-jwt:unique_id+given_name+family_name",
                        "path": "$.vp_token.verified_claims.claims._sd[0]",
                        "format": "vc+sd-jwt"
                    }
                ]
            }
        }
        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]).encrypt(response_with_bad_nonce)
        context.request = {
            "response": encrypted_response
        }
        context.http_headers = {"HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}

        response_endpoint = self.backend.response_endpoint(context)
        msg = json.loads(response_endpoint.message)
        assert response_endpoint.status != "200"
        assert msg["error"] == "invalid_request"

        # case (2): bad state
        sdjwt_at_holder.create_presentation(
            {},
            nonce,
            self.backend.client_id,
            holder_key=holder_jwk,
            sign_alg=DEFAULT_SIG_KTY_MAP[holder_jwk["kty"]],
        )

        vp_token = sdjwt_at_holder.sd_jwt_presentation

        response_with_bad_state = {
            "state": bad_state,
            "vp_token": vp_token,
            "presentation_submission": {
                "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "id": "04a98be3-7fb0-4cf5-af9a-31579c8b0e7d",
                "descriptor_map": [
                    {
                        "id": "pid-sd-jwt:unique_id+given_name+family_name",
                        "path": "$.vp_token.verified_claims.claims._sd[0]",
                        "format": "vc+sd-jwt"
                    }
                ]
            }
        }

        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]).encrypt(response_with_bad_state)
        context.request = {
            "response": encrypted_response
        }
        context.http_headers = {"HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}

        response_endpoint = self.backend.response_endpoint(context)
        msg = json.loads(response_endpoint.message)
        assert response_endpoint.status != "200"
        assert msg["error"] == "invalid_request"

        # case (3): bad aud
        sdjwt_at_holder.create_presentation(
            {},
            nonce,
            bad_aud,
            holder_key=holder_jwk,
            sign_alg=DEFAULT_SIG_KTY_MAP[holder_jwk["kty"]],
        )

        vp_token_bad_aud = sdjwt_at_holder.sd_jwt_presentation

        response_with_bad_aud = {
            "state": state,
            "vp_token": vp_token_bad_aud,
            "presentation_submission": {
                "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "id": "04a98be3-7fb0-4cf5-af9a-31579c8b0e7d",
                "descriptor_map": [
                    {
                        "id": "pid-sd-jwt:unique_id+given_name+family_name",
                        "path": "$.vp_token.verified_claims.claims._sd[0]",
                        "format": "vc+sd-jwt"
                    }
                ]
            }
        }
        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]).encrypt(response_with_bad_aud)
        context.request = {
            "response": encrypted_response
        }
        context.http_headers = {"HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}

        response_endpoint = self.backend.response_endpoint(context)
        msg = json.loads(response_endpoint.message)
        assert response_endpoint.status != "200"
        assert msg["error"] == "invalid_request"

        # case (4): good aud, nonce and state
        sdjwt_at_holder.create_presentation(
            {},
            nonce,
            self.backend.client_id,
            holder_key=holder_jwk,
            sign_alg=DEFAULT_SIG_KTY_MAP[holder_jwk["kty"]],
        )

        vp_token = sdjwt_at_holder.sd_jwt_presentation

        response = {
            "state": state,
            "vp_token": vp_token,
            "presentation_submission": {
                "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "id": "04a98be3-7fb0-4cf5-af9a-31579c8b0e7d",
                "descriptor_map": [
                    {
                        "id": "pid-sd-jwt:unique_id+given_name+family_name",
                        "path": "$.vp_token.verified_claims.claims._sd[0]",
                        "format": "vc+sd-jwt"
                    }
                ]
            }
        }

        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]).encrypt(response)
        context.request = {
            "response": encrypted_response
        }
        context.http_headers = {"HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}

        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]).encrypt(response)
        context.request = {
            "response": encrypted_response
        }
        response_endpoint = self.backend.response_endpoint(context)
        assert response_endpoint.status == "200"

    def test_request_endpoint(self, context):
        # No session created
        state_endpoint_response = self.backend.status_endpoint(context)
        assert state_endpoint_response.status == "400"
        assert state_endpoint_response.message
        request_object_jwt = json.loads(state_endpoint_response.message)
        assert request_object_jwt["error"]

        internal_data = InternalData()
        context.http_headers = dict(
            HTTP_USER_AGENT="Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.92 Mobile Safari/537.36"
        )
        pre_request_endpoint = self.backend.pre_request_endpoint(context, internal_data)
        state = urllib.parse.unquote(pre_request_endpoint.message).split("=")[-1]

        jwshelper = JWSHelper(PRIVATE_JWK)

        wia = jwshelper.sign(
            plain_dict=WALLET_INSTANCE_ATTESTATION,
            protected={
                "trust_chain": trust_chain_wallet,
                "x5c": [],
            },
        )

        dpop_wia = wia

        dpop_proof = DPoPIssuer(
            htu=CONFIG["metadata"]["request_uris"][0],
            token=dpop_wia,
            private_jwk=PRIVATE_JWK,
        ).proof

        context.http_headers = dict(
            HTTP_AUTHORIZATION=f"DPoP {dpop_wia}", HTTP_DPOP=dpop_proof
        )

        context.qs_params = {"id": state}

        # put a trust attestation related itself into the storage
        # this then is used as trust_chain header parameter in the signed
        # request object
        db_engine_inst = DBEngine(CONFIG["storage"])

        _fedback: TrustHandlerInterface = self.backend.get_trust_backend_by_class_name(
            "FederationHandler"
        )
        assert _fedback

        _es = {
            "exp": EXP,
            "iat": NOW,
            "iss": "https://trust-anchor.example.org",
            "sub": self.backend.client_id,
            "jwks": _fedback.entity_configuration_as_dict["jwks"],
        }
        ta_signer = JWS(_es, alg="ES256", typ="application/entity-statement+jwt")

        its_trust_chain = [
            _fedback.entity_configuration,
            ta_signer.sign_compact([ta_jwk]),
        ]
        db_engine_inst.add_or_update_trust_attestation(
            entity_id=self.backend.client_id,
            attestation=its_trust_chain,
            exp=datetime.datetime.now().isoformat(),
        )
        # End RP trust chain

        state_endpoint_response = self.backend.status_endpoint(context)
        assert state_endpoint_response.status == "201"
        assert state_endpoint_response.message

        # Passing wrong state, hence no match state-session_id
        context.qs_params = {"id": "WRONG"}
        state_endpoint_response = self.backend.status_endpoint(context)
        assert state_endpoint_response.status == "401"
        assert state_endpoint_response.message

        context.request_method = "GET"
        context.qs_params = {"id": state}
        request_uri = CONFIG["metadata"]["request_uris"][0]
        context.request_uri = request_uri

        req_resp = self.backend.request_endpoint(context)
        req_resp_str = f"Response(status={req_resp.status}, message={req_resp.message}, headers={req_resp.headers})"
        obtained_content_types = list(
            map(
                lambda header_name_value_pair: header_name_value_pair[1],
                filter(
                    lambda header_name_value_pair: header_name_value_pair[0].lower()
                    == "content-type",
                    req_resp.headers,
                ),
            )
        )
        assert req_resp
        assert (
            req_resp.status == "200"
        ), f"invalid status in request object response {req_resp_str}"
        assert (
            len(obtained_content_types) > 0
        ), f"missing Content-Type in request object response {req_resp_str}"
        assert (
            obtained_content_types[0] == "application/oauth-authz-req+jwt"
        ), f"invalid Content-Type in request object response {req_resp_str}"
        assert (
            req_resp.message
        ), f"invalid message in request object response {req_resp_str}"
        request_object_jwt = req_resp.message

        header = decode_jwt_header(request_object_jwt)
        payload = decode_jwt_payload(request_object_jwt)
        assert header["alg"]
        assert header["kid"]
        assert header["typ"] == "oauth-authz-req+jwt"
        assert payload["scope"] == " ".join(CONFIG["authorization"]["scopes"])
        assert payload["client_id"] == CONFIG["metadata"]["client_id"]
        assert (
            payload["response_uri"] == CONFIG["metadata"]["response_uris"][0]
        )

        datetime_mock = Mock(wraps=datetime.datetime)
        datetime_mock.now.return_value = datetime.datetime(2999, 1, 1)
        with patch("datetime.datetime", new=datetime_mock):
            self.backend.status_endpoint(context)
            state_endpoint_response = self.backend.status_endpoint(context)
            assert state_endpoint_response.status == "403"
            assert state_endpoint_response.message
            err = json.loads(state_endpoint_response.message)
            assert err["error"] == "expired"

        # TODO - the authentication is successful ONLY if redirect_endpoints gets a valid presentation!
        # state_endpoint_response = self.backend.status_endpoint(context)
        # assert state_endpoint_response.status == "302"
        # assert state_endpoint_response.message
        # msg = json.loads(state_endpoint_response.message)
        # assert msg["response"] == "Authentication successful"

    def test_handle_error(self, context):
        error_message = "server_error"
        error_resp = self.backend._handle_500(context, error_message, Exception())
        assert error_resp.status == "500"
        assert error_resp.message
        err = json.loads(error_resp.message)
        assert err["error"] == error_message
