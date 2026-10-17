"""QRadar integration descriptor — source of truth for its registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

QRADAR = register_descriptor(
    IntegrationDescriptor(
        id="qradar",
        category="SIEM",
        mcp_server_names=("qradar",),
        fields=(
            IntegrationField("console_url"),
            IntegrationField("api_token", secret=True),
            IntegrationField("api_version"),
            IntegrationField("offense_filter"),
            IntegrationField("verify_ssl", value_type="bool"),
            IntegrationField("ca_cert_path"),
        ),
    )
)
