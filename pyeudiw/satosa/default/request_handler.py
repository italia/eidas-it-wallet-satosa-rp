from satosa.context import Context

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.openid4vp.authorization_request import build_authorization_request_claims
from pyeudiw.satosa.exceptions import HTTPError
from pyeudiw.satosa.interfaces.request_handler import RequestHandlerInterface
from pyeudiw.satosa.utils.response import Response
from pyeudiw.tools.base_logger import BaseLogger


class RequestHandler(RequestHandlerInterface, BaseLogger):

    _REQUEST_OBJECT_TYP = "oauth-authz-req+jwt"
    _RESP_CONTENT_TYPE = f"application/{_REQUEST_OBJECT_TYP}"

    def request_endpoint(self, context: Context, *args) -> Response:
        self._log_function_debug("request_endpoint", context, "args", args)

        try:
            state = context.qs_params["id"]
        except Exception as e:
            _msg = (
                "Error while retrieving id from qs_params: "
                f"{e.__class__.__name__}: {e}"
            )
            return self._handle_400(
                context, _msg, HTTPError(f"{e} with {context.__dict__}")
            )

        data = build_authorization_request_claims(
            self.client_id,
            state,
            self.absolute_response_url,
            self.config["authorization"],
        )

        if _aud := self.config["authorization"].get("aud"):
            data["aud"] = _aud
        # take the session created in the pre-request authz endpoint
        try:
            document = self.db_engine.get_by_state(state)
            document_id = document["document_id"]
            self.db_engine.update_request_object(document_id, data)

        except ValueError as e:
            _msg = "Error while retrieving request object from database."
            return self._handle_500(
                context, _msg, HTTPError(f"{e} with {context.__dict__}")
            )

        except (Exception, BaseException) as e:
            _msg = f"Error while updating request object: {e}"
            return self._handle_500(context, _msg, e)

        _protected_jwt_headers = {
            "typ": RequestHandler._REQUEST_OBJECT_TYP,
        }

        # load all the trust handlers request jwt header parameters, if any

        _protected_jwt_headers.update(
            self.trust_evaluator.get_selfissued_jwt_header_trust_parameters(issuer=self.client_id)
        )

        #  federation_trust_handler_backend_class: TrustHandlerInterface = (
        #  self.get_trust_backend_by_class_name("FederationHandler")
        #  )

        helper = JWSHelper(self.default_metadata_private_jwk)
        request_object_jwt = helper.sign(
            data,
            protected=_protected_jwt_headers,
        )
        return Response(
            message=request_object_jwt,
            status="200",
            content=RequestHandler._RESP_CONTENT_TYPE,
        )
