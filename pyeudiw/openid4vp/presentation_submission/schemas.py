from typing import Any
from pydantic import BaseModel, field_validator


class DescriptorSchema(BaseModel):
    id: str
    format: str
    path: str
    path_nested: dict[str, Any] = None


class PresentationSubmissionSchema(BaseModel):
    id: str
    definition_id: str
    descriptor_map: list[DescriptorSchema]

    @field_validator("descriptor_map")
    @classmethod
    def check_descriptor_map_size(cls, value):
        max_descriptors = 100  # TODO: Define a reasonable limit
        if len(value) > max_descriptors:
            raise ValueError(f"descriptor_map exceeds maximum allowed size of {max_descriptors} items.")
        return value