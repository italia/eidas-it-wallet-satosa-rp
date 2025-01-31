from pyeudiw.federation.schemas.entity_configuration import (
    EntityConfigurationPayload, EntityStatementPayload)

from .exceptions import InvalidEntityConfiguration, InvalidEntityStatement


def is_es(payload: dict) -> None:
    """
    Determines if payload dict is a Subordinate Entity Statement

    :param payload: the object to determine if is a Subordinate Entity Statement
    :type payload: dict
    """

    try:
        EntityStatementPayload(**payload)
        if payload["iss"] == payload["sub"]:
            _msg = "Invalid Entity Statement: iss and sub cannot be the same"
            raise InvalidEntityStatement(_msg)
    except ValueError as e:
        _msg = f"Invalid Entity Statement: {e}"
        raise InvalidEntityStatement(_msg)


def is_ec(payload: dict) -> None:
    """
    Determines if payload dict is an Entity Configuration

    :param payload: the object to determine if is an Entity Configuration
    :type payload: dict
    """

    try:
        EntityConfigurationPayload(**payload)
    except ValueError as e:
        _msg = f"Invalid Entity Configuration: {e}"
        raise InvalidEntityConfiguration(_msg)
