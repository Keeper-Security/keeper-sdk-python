from enum import StrEnum

# This should the relationship between Keeper Vault record
RECORD_LINK_GRAPH_ID = 0

#  The rules
DIS_RULES_GRAPH_ID = 10

# The discovery job history
DIS_JOBS_GRAPH_ID = 11

# Discovery infrastructure
DIS_INFRA_GRAPH_ID = 12

# The user-to-services graph
USER_SERVICE_GRAPH_ID = 13

PAM_DIRECTORY = "pamDirectory"
PAM_DATABASE = "pamDatabase"
PAM_MACHINE = "pamMachine"
PAM_USER = "pamUser"
LOCAL_USER = "local"

PAM_RESOURCES = [
    PAM_DIRECTORY,
    PAM_DATABASE,
    PAM_MACHINE
]

class PamConfigurationRecordType(StrEnum):
    AWS = "pamAwsConfiguration"
    AZURE = "pamAzureConfiguration"
    GCP = "pamGcpConfiguration"
    DOMAIN = "pamDomainConfiguration"
    NETWORK = "pamNetworkConfiguration"
    OCI = "pamOciConfiguration"


PAM_AWS_CONFIGURATION = PamConfigurationRecordType.AWS
PAM_AZURE_CONFIGURATION = PamConfigurationRecordType.AZURE
PAM_GCP_CONFIGURATION = PamConfigurationRecordType.GCP
PAM_DOMAIN_CONFIGURATION = PamConfigurationRecordType.DOMAIN
PAM_NETWORK_CONFIGURATION = PamConfigurationRecordType.NETWORK
PAM_OCI_CONFIGURATION = PamConfigurationRecordType.OCI

PAM_CONFIGURATIONS = (
    PamConfigurationRecordType.AWS,
    PamConfigurationRecordType.AZURE,
    PamConfigurationRecordType.GCP,
    PamConfigurationRecordType.DOMAIN,
    PamConfigurationRecordType.NETWORK,
    PamConfigurationRecordType.OCI,
)

DOMAIN_USER_CONFIGS = (
    PamConfigurationRecordType.DOMAIN,
    PamConfigurationRecordType.AZURE,
)

VERTICES_SORT_MAP = {
    PAM_USER: {"order": 1, "sort": "sort_infra_name", "item": "DiscoveryUser", "key": "user"},
    PAM_DIRECTORY: {"order": 1, "sort": "sort_infra_name", "item": "DiscoveryDirectory", "key": "host_port"},
    PAM_MACHINE: {"order": 2, "sort": "sort_infra_host", "item": "DiscoveryMachine", "key": "host"},
    PAM_DATABASE: {"order": 3, "sort": "sort_infra_host", "item": "DiscoveryDatabase", "key": "host_port"},
}
