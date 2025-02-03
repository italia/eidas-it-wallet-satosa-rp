from typing import Optional

from pydantic import BaseModel, field_validator

from pyeudiw.jwt.utils import is_jwt_format
from pyeudiw.openid4vp.presentation_submission.schemas import PresentationSubmissionSchema

class ResponseSchema(BaseModel):
    state: Optional[str]
    nonce: str
    vp_token: str
    presentation_submission: PresentationSubmissionSchema

    @field_validator("vp_token")
    @classmethod
    def _check_vp_token(cls, vp_token):
        if is_jwt_format(vp_token):
            return vp_token
        else:
            raise ValueError("vp_token is not in a JWT format.")
