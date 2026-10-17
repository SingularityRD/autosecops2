"""FortiGate integration descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

FORTIGATE = register_descriptor(
    IntegrationDescriptor(
        id="fortigate",
        category="Network Security",
        fields=(
            IntegrationField("hostname"),
            IntegrationField("api_token", secret=True),
            IntegrationField("vdom"),
            IntegrationField("verify_ssl", value_type="bool"),
            IntegrationField("ca_cert_path"),
        ),
    )
)
