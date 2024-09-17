from copy import deepcopy
from dataclasses import dataclass
from typing import Callable, Optional, Union

from cryptojwt.jws.exception import JWSException
from jwcrypto.common import base64url_decode, json_decode
import jwcrypto.jwk
from sd_jwt.verifier import SDJWTVerifier

from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWSHelper
from pyeudiw.jwt.utils import unsafe_parse_jws
from pyeudiw.jwt.schemas.jwt import UnverfiedJwt
from pyeudiw.openid4vp.exceptions import InvalidVPKeyBinding, InvalidVPSignature, KIDNotFound, VPSchemaException
from pyeudiw.openid4vp.verifier import VpVerifier
from pyeudiw.sd_jwt.schema import KeyBindingJwtHeader, KeyBindingJwtPayload, VcSdJwtHeaderSchema, VcSdJwtPayloadSchema, is_sd_jwt_kb_format
from pyeudiw.tools.utils import iat_now


_SD_JWT_DELIMITER = '~'

_CLOCK_SKEW = 0


@dataclass
class VerifierChallenge:
    aud: str
    nonce: str


class VpVcSdJwtKbVerifier(VpVerifier):
    _DEFAULT_DISCLOSABLE_CLAIMS = (
        "given_name",
        "family_name",
        "birth_date",
        "unique_id",
        "tax_id_code"
    )

    def __init__(self, sdjwtkb: str, verifier_id: str, verifier_nonce: str, jwk_by_kid: dict[str, dict], accepted_claims: Optional[list[str]] = None):
        """
        VpVcSdJwtKbVerifier is a utility class for parsing and verifying sd-jwt.
        TODO: docs

        :param sdjwtkb: verifiable credential in sd-jwt with key binding format (raw encoded string)
        :type sdjwtkb: str
        :param jwks_by_kid: dictionary where the keys are kid(s) and the values are unmarshaled jwk
        :type jwks_by_kid: dict[str, dict]


        :raise VPSchemaException: if the input cannot be sucessfully parsed as sd-jwt.
        """
        self.sdjwtkb = sdjwtkb
        if not is_sd_jwt_kb_format(sdjwtkb):
            raise ValueError(f"input [sdjwtkb]={sdjwtkb} is not an sd-jwt with key binding: maybe it is a regular jwt or key binding jwt is missing?")
        self.verifier_id = verifier_id
        self.verifier_nonce = verifier_nonce
        self.jwk_by_kid = jwk_by_kid
        self.accepted_claims: list[str] = accepted_claims if accepted_claims is not None else deepcopy(VpVcSdJwtKbVerifier._DEFAULT_DISCLOSABLE_CLAIMS)
        # precomputed values
        self._issuer_jwt: UnverfiedJwt = UnverfiedJwt("", "", "", "")
        self._encoded_disclosures: list[str] = []
        self._disclosures: list[dict] = []
        self._kb_jwt: UnverfiedJwt = UnverfiedJwt("", "", "", "")
        self._post_init_evaluate_precomputed_values()

    def _post_init_evaluate_precomputed_values(self):
        iss_jwt, *disclosures, kb_jwt = self.sdjwtkb.split(_SD_JWT_DELIMITER)
        self._encoded_disclosures = disclosures
        self._disclosures = [json_decode(base64url_decode(disc)) for disc in disclosures]
        self._issuer_jwt = unsafe_parse_jws(iss_jwt)
        self._kb_jwt = unsafe_parse_jws(kb_jwt)

    def _get_issuer_jwk(self) -> JWK:
        issuer_jwk_kid: str | None = self._issuer_jwt.header.get("kid", None)
        if issuer_jwk_kid is None:
            raise ValueError("missing mandatory parameter [kid] in issuer jwt header")
        issuer_jwk_d: dict | None = self.jwk_by_kid.get(issuer_jwk_kid, None)
        if issuer_jwk_kid is None:
            raise KIDNotFound(f"issuer jwt signed with kid={issuer_jwk_kid} not found in key store slice")
        _jwk = JWK(issuer_jwk_d)
        return _jwk

    def validate_schema(self):
        try:
            VcSdJwtHeaderSchema(**self._issuer_jwt.header)
            VcSdJwtPayloadSchema(**self._issuer_jwt.payload)
            KeyBindingJwtHeader(**self._kb_jwt.header)
            KeyBindingJwtPayload(**self._kb_jwt.payload)
        except Exception as e:
            raise VPSchemaException(f"failed to decode sd-jwt: {e}")

    def _get_confirmation_jwk(self) -> JWK:
        """Utility method that extracts the claim "cnf" from the issuer jwt.
        If not such claims exists, a ValueError is returned.
        """
        cnf_keys: dict | None = self._issuer_jwt.payload.get("cnf", None)
        if not isinstance(cnf_keys, dict):
            raise ValueError("missing of invalid claim [cnf] in issuer jwt payload")
        jwk_d: dict | None = cnf_keys.get("jwk", None)
        if not isinstance(jwk_d, dict):
            raise ValueError("missing or invalid claim [cnf.jwk] in issuer jwt payload")
        return JWK(key=jwk_d)

    def verify(self) -> None:
        """TODO: docs"""
        cnf_jwk = self._get_confirmation_jwk()
        _verify_kb_jwt(self._kb_jwt, cnf_jwk, VerifierChallenge(self.verifier_id, self.verifier_nonce))
        _verify_jws_with_key(self._issuer_jwt.jwt, self._get_issuer_jwk())

    def check_revocation_status():
        raise NotImplementedError

    def parse_digital_credential(self) -> dict:
        _jwk = jwcrypto.jwk.JWK(**self._get_issuer_jwk().as_dict())
        # currently we wrap SDJWTVerifier from library https://github.com/openwallet-foundation-labs/sd-jwt-python
        #  but this library _also_ re-does verification, while i would like to decouple verification from credential parsing
        sdjwt_verifier = SDJWTVerifier(
            sd_jwt_presentation=self.sdjwtkb,
            cb_get_issuer_key=wrap_jwk_to_callable_keystore(_jwk),
            serialization_format="compact"
        )
        payload_claims: dict = sdjwt_verifier.get_verified_payload()
        # NOTE: if acceptance list is empty, accept everything
        #  this assumes that an empy acceptance list means nothing, which is an invariant that might not hold in the future
        if len(self.accepted_claims) == 0:
            return payload_claims
        filtered_claims_result = {}
        for claim_name in self.accepted_claims:
            if claim_name in payload_claims.keys():
                filtered_claims_result.update({claim_name: payload_claims[claim_name]})
        return filtered_claims_result

    def __str__(self) -> str:
        return "VpVcSdJwtKb(" \
            f"sdjwt={self.sdjwtkb}" \
            ")"


def _verify_jws_with_key(issuer_jwt: str, issuer_key: JWK):
    verifier = JWSHelper(issuer_key)
    verifier.verify(issuer_jwt)
    try:
        pass
    except JWSException as e:
        raise InvalidVPSignature(f"failed signature verification of issuer-jwt: {e}")
    return


def _verify_kb_jwt(kbjwt: UnverfiedJwt, cnf_jwk: JWK, challenge: VerifierChallenge) -> None:
    _verify_kb_jwt_payload_challenge(kbjwt.payload, challenge)
    _verify_kb_jwt_payload_iat(kbjwt.payload)
    # _verify_kb_jwt_payload_sd_hash(sdjwt)
    _verify_kb_jwt_signature(kbjwt.jwt, cnf_jwk)


# def _verify_kb_jwt_payload_sd_hash(sdjwt: VpVcSdJwtKbVerifier):
#     hash_alg: str | None = sdjwt._issuer_jwt.payload.get("_sd_alg", None)
#     if hash_alg is None:
#         raise ValueError("missing parameter [_sd_alg] in issuer signet JWT payload")
#     *parts, _ = sdjwt.sdjwtkb.split(_SD_JWT_DELIMITER)
#     iss_jwt_disclosed = ''.join(parts)
#     # TODO
#     pass


def _verify_kb_jwt_payload_challenge(kb_jwt_payload: dict, challenge: VerifierChallenge):
    aud = kb_jwt_payload.get("aud", None)
    nonce = kb_jwt_payload.get("nonce", None)
    if aud is None or nonce is None:
        raise ValueError("missing parameter [aud] or [nonce] in kbjwt")
    if aud != challenge.aud:
        raise InvalidVPKeyBinding("obtained kb-jwt parameter [aud] does not match verifier audience")
    if nonce != challenge.nonce:
        raise InvalidVPKeyBinding("obtained kb-jwt parameter [nonce] does not match verifier nonce")
    return


def _verify_kb_jwt_payload_iat(kb_jwt_payload: dict) -> None:
    iat: int | None = kb_jwt_payload.get("iat", None)
    if not isinstance(iat, int):
        raise ValueError("missing or invalid parameter [iat] in kbjwt")
    now = iat_now()
    if iat > (now + _CLOCK_SKEW):
        raise InvalidVPKeyBinding("invalid parameter [iat] in kbjwt: issuance after present time")
    return


def _verify_kb_jwt_signature(kbjwt: str, verification_jwk: JWK) -> None:
    verifier = JWSHelper(verification_jwk)
    try:
        verifier.verify(kbjwt)
    except JWSException as e:
        raise InvalidVPKeyBinding(f"failed signature verification of kb-jwt: {e}")
    return


_CB_KetStore_T = Callable[[str, dict], Union[jwcrypto.jwk.JWK, jwcrypto.jwk.JWKSet]]


def wrap_jwk_to_callable_keystore(fixed_jwk: jwcrypto.jwk.JWK) -> _CB_KetStore_T:
    """wrap a jwk to a trivial keystore where the input `fixed_jwk` is always returned
    """
    return lambda iss, header: fixed_jwk
