import base64
import json
from dataclasses import dataclass

from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload, is_jwt_format

@dataclass(frozen=True)
class DecodedJwt:
    """
    Schema class for a decoded jwt.
    This class is not meant to be instantiated directly. Use instead
    the static method parse(str) -> DecodedJwt.
    """

    jwt: str
    header: dict
    payload: dict
    signature: str

    @staticmethod
    def parse(jws: str) -> "DecodedJwt":
        return unsafe_parse_jws(jws)


def unsafe_parse_jws(token: str) -> DecodedJwt:
    """
    Parse a token into its components.
    Correctness of this function is not guaranteed when the token is in a
    derived format, such as sd-jwt and jwe.
    """
    if not is_jwt_format(token):
        raise ValueError(f"unable to parse {token}: not a jwt")

    try:
        head = decode_jwt_header(token)
        payload = decode_jwt_payload(token)
        signature = token.split(".")[2]
    except Exception as e:
        raise ValueError(f"unable to decode JWS part: {e}")
    return DecodedJwt(token, head, payload, signature=signature)
