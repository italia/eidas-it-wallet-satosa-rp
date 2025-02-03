from unittest.mock import patch, MagicMock
from pydantic import ValidationError
from pytest import raises
from pyeudiw.openid4vp.presentation_submission.presentation_submission import PresentationSubmission
from pyeudiw.openid4vp.presentation_submission.base_vp_parser import BaseVPParser


# Mock data for testing
mock_format_config = {
    "formats": [
        {"name": "ldp_vp", "module": "mock.module", "class": "MockLdpVpHandler"},
        {"name": "jwt_vp_json", "module": "mock.module", "class": "MockJwtVpJsonHandler"}
    ],
    "MAX_SUBMISSION_SIZE": 10 * 1024  # 10 KB
}

valid_submission = {
    "id": "submission_id",
    "definition_id": "definition_id",
    "descriptor_map": [
        {"id": "descriptor_1", "format": "ldp_vp", "path": "$"},
        {"id": "descriptor_2", "format": "jwt_vp_json", "path": "$"}
    ]
}


# Mock classes that inherit from BaseVPParser and implement required methods
class MockLdpVpHandler(BaseVPParser):
    def __init__(self, *args, config=None, **kwargs):
        self.args = args
        self.config = config
        self.kwargs = kwargs

    def parse(self, data):
        return {"parsed": data}

    def validate(self, data):
        return True


class MockJwtVpJsonHandler(BaseVPParser):
    def __init__(self, *args, config=None, **kwargs):
        self.args = args
        self.config = config
        self.kwargs = kwargs

    def parse(self, data):
        return {"parsed": data}

    def validate(self, data):
        return True


def test_presentation_submission_initialization_with_schema_validation():
    """
    Test that the PresentationSubmission class initializes correctly,
    validates against the Pydantic schema, and properly instantiates handlers.
    """
    # Simuliamo il modulo contenente le classi
    mock_module = MagicMock()
    setattr(mock_module, "MockLdpVpHandler", MockLdpVpHandler)
    setattr(mock_module, "MockJwtVpJsonHandler", MockJwtVpJsonHandler)

    test_args = ("arg1", "arg2")
    test_kwargs = {"kwarg1": "value1", "kwarg2": "value2"}

    with patch("importlib.import_module", return_value=mock_module):
        # Corretto: passiamo prima gli argomenti posizionali, poi config, infine kwargs
        ps = PresentationSubmission(valid_submission, *test_args, config=mock_format_config, **test_kwargs)

        # Assert that handlers were created for all formats in descriptor_map
        assert len(ps.handlers) == len(valid_submission["descriptor_map"]), "Not all handlers were created."

        # Verifica che i gestori siano effettivamente delle istanze delle classi corrette
        assert isinstance(ps.handlers[0], MockLdpVpHandler), "Handler for 'ldp_vp' format is incorrect."
        assert isinstance(ps.handlers[1], MockJwtVpJsonHandler), "Handler for 'jwt_vp_json' format is incorrect."

        # Verifica che gli argomenti siano stati passati correttamente
        assert ps.handlers[0].args == test_args, "Args not passed correctly to 'MockLdpVpHandler'"
        assert ps.handlers[0].config == mock_format_config, "Config not passed correctly to 'MockLdpVpHandler'"
        assert ps.handlers[0].kwargs == test_kwargs, "Kwargs not passed correctly to 'MockLdpVpHandler'"

        assert ps.handlers[1].args == test_args, "Args not passed correctly to 'MockJwtVpJsonHandler'"
        assert ps.handlers[1].config == mock_format_config, "Config not passed correctly to 'MockJwtVpJsonHandler'"
        assert ps.handlers[1].kwargs == test_kwargs, "Kwargs not passed correctly to 'MockJwtVpJsonHandler'"
