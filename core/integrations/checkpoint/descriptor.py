"""Check Point integration descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

CHECKPOINT = register_descriptor(
    IntegrationDescriptor(
        id="checkpoint",
        category="Network Security",
        fields=(IntegrationField("feed_token", secret=True),),
    )
)
