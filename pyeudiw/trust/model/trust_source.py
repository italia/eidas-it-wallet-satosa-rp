from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from typing import Union

from cryptojwt.jwk.jwk import key_from_jwk_dict


@dataclass
class TrustParameterData:
    """
    TrustParameterData is a dataclass that holds one of the trust parameters for a trust source.
    """

    def __init__(
        self,
        type: str,
        trust_params: Union[dict, str],
        expiration_date: datetime,
    ) -> None:
        """
        Initialize the trust parameter data.

        :param type: The type of the trust parameter
        :type type: str
        :param trust_params: The trust parameters
        :type trust_params: dict
        :param expiration_date: The expiration date of the trust parameter data
        :type expiration_date: datetime
        """

        self.type = type
        self.trust_params = trust_params
        self.expiration_date = expiration_date

    def selfissued_jwt_header_trust_parameters(self) -> dict[str, any]:
        """
        Return the trust parameters for the self-issued jwt header.

        :returns: The trust parameters for the self-issued jwt header
        :rtype: dict[str, any]
        """
        return {self.type: self.trust_params}

    def serialize(self) -> dict[str, any]:
        """
        Serialize the trust parameter data.

        :returns: The serialized trust parameter data
        :rtype: dict[str, any]
        """
        return {
            "type": self.type,
            "trust_params": self.trust_params,
            "expiration_date": self.expiration_date,
        }

    @property
    def expired(self) -> bool:
        """
        Return whether the trust parameter data has expired.

        :returns: Whether the trust parameter data has expired
        :rtype: bool
        """
        return datetime.now() > self.expiration_date


@dataclass
class TrustSourceData:
    """
    TrustSourceData is a dataclass that holds the trust data of a trust source.
    """

    def __init__(
        self,
        entity_id: str,
        policies: dict = {},
        metadata: dict = {},
        revoked: bool = False,
        keys: list[dict] = [],
        trust_params: dict[str, dict[str, any]] = {},
        **kwargs
    ) -> None:
        """
        Initialize the trust source data.

        :param entity_id: The entity id of the trust source
        :type entity_id: str
        :param policies: The policies of the trust source
        :type policies: dict, optional
        :param metadata: The metadata of the trust source
        :type metadata: dict, optional
        :param revoked: Whether the trust source is revoked
        :type revoked: bool, optional
        :param keys: The keys of the trust source
        :type keys: list[dict], optional
        :param trust_params: The trust parameters of the trust source
        :type trust_params: dict[str, dict[str, any]], optional
        """
        self.entity_id = entity_id
        self.policies = policies
        self.metadata = metadata
        self.revoked = revoked
        self.keys = keys

        self.additional_data = kwargs

        self.trust_params = {
            type: TrustParameterData(**tp) for type, tp in trust_params.items()
        }

    def add_key(self, key: dict) -> None:
        """
        Add a key to the trust source.

        :param key: The key to add
        :type key: dict
        """
        self.keys.append(key)

    def add_keys(self, keys: list[dict]) -> None:
        """
        Add keys to the trust source.

        :param keys: The keys to add
        :type keys: list[dict]
        """
        self.keys.extend(keys)

    def add_trust_param(self, type: str, trust_params: TrustParameterData) -> None:
        """
        Add a trust source to the trust source.

        :param type: The type of the trust source
        :type type: str
        :param trust_params: The trust parameters of the trust source
        :type trust_params: TrustParameterData
        """
        self.trust_params[type] = trust_params

    def has_trust_param(self, type: str) -> bool:
        """
        Return whether the trust source has a trust source of the given type.

        :param type: The type of the trust source
        :type type: str
        :returns: Whether the trust source has a trust source of the given type
        :rtype: bool
        """
        return type in self.trust_params

    def get_trust_param(self, type: str) -> Optional[TrustParameterData]:
        """
        Return the trust source of the given type.

        :param type: The type of the trust source
        :type type: str
        :returns: The trust source of the given type
        :rtype: TrustParameterData
        """
        if not self.has_trust_param(type):
            return None
        return TrustParameterData(type, self.trust_params[type])

    def serialize(self) -> dict[str, any]:
        """
        Serialize the trust source data.

        :returns: The serialized trust source data
        :rtype: dict[str, any]
        """
        return {
            "entity_id": self.entity_id,
            "policies": self.policies,
            "metadata": self.metadata,
            "revoked": self.revoked,
            "keys": self.keys,
            "trust_params": {
                type: param.serialize() for type, param in self.trust_params.items()
            },
        }

    @staticmethod
    def empty(entity_id: str) -> "TrustSourceData":
        """
        Return the empty trust source data.

        :param entity_id: The entity id of the trust source
        :type entity_id: str
        :returns: The empty trust source data
        :rtype: TrustSourceData
        """
        return TrustSourceData(
            entity_id, policies={}, metadata={}, revoked=False, keys=[], trust_params={}
        )

    @staticmethod
    def from_dict(data: dict) -> "TrustSourceData":
        """
        Return the trust source data from the given dictionary.

        :param data: The dictionary to create the trust source data from
        :type data: dict
        :returns: The trust source data from the given dictionary
        :rtype: TrustSourceData
        """
        return TrustSourceData(**data)

    @property
    def public_keys(self) -> list[dict[str, any]]:
        """
        Return the public keys of the trust source.

        :returns: The public keys of the trust source
        :rtype: list[dict[str, any]]
        """
        return [key_from_jwk_dict(k, private=False).serialize() for k in self.keys]
