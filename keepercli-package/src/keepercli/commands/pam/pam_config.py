import argparse
import json
import re

from .. import base
from ... import api
from ...helpers import report_utils, gateway_utils, folder_utils
from ...params import KeeperParams
from ..record_edit import RecordEditMixin


from keepersdk import utils
from keepersdk.proto import pam_pb2, record_pb2
from keepersdk.helpers import config_utils
from keepersdk.vault import vault_online, vault_utils, vault_record, record_management
from keepersdk.helpers.pam_config_facade import PamConfigurationRecordFacade
from keepersdk.helpers.tunnel.tunnel_graph import TunnelDAG, tunnel_utils
from keepersdk.helpers.keeper_dag import dag_utils
from .. import record_edit


logger = api.get_logger()


# PAM Configuration record types
PAM_CONFIG_RECORD_TYPES = (
    'pamAwsConfiguration', 'pamAzureConfiguration', 'pamGcpConfiguration',
    'pamDomainConfiguration', 'pamNetworkConfiguration', 'pamOciConfiguration'
)


class PAMConfigListCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam config list')
        PAMConfigListCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--config', '-c', required=False, dest='pam_configuration', action='store',
                            help='Specific PAM Configuration UID')
        parser.add_argument('--verbose', '-v', required=False, dest='verbose', action='store_true', help='Verbose')
        parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], default='table',
                            help='Output format (table, json)')

    def execute(self, context: KeeperParams, **kwargs):
        self._validate_vault_and_permissions(context)
        
        vault = context.vault
        pam_configuration_uid = kwargs.get('pam_configuration')
        is_verbose = kwargs.get('verbose')
        format_type = kwargs.get('format', 'table')

        if not pam_configuration_uid:
            result = self._list_all_configurations(vault, is_verbose, format_type)
            if format_type == 'json' and result:
                return result
        else:
            result = self._list_single_configuration(vault, pam_configuration_uid, is_verbose, format_type)
            if format_type == 'json' and result:
                return result

            if format_type == 'table':
                self._print_tunneling_config(vault, pam_configuration_uid)

    def _validate_vault_and_permissions(self, context: KeeperParams):
        """Validates that vault is initialized and user has enterprise admin permissions."""
        if not context.vault:
            raise ValueError("Vault is not initialized, login to initialize the vault.")
        base.require_enterprise_admin(context)

    def _print_tunneling_config(self, vault: vault_online.VaultOnline, config_uid: str):
        """Prints tunneling configuration for a specific PAM configuration."""
        encrypted_session_token, encrypted_transmission_key, transmission_key = tunnel_utils.get_keeper_tokens(vault)
        tmp_dag = TunnelDAG(vault, encrypted_session_token, encrypted_transmission_key, config_uid,
                            is_config=True, transmission_key=transmission_key)
        tmp_dag.print_tunneling_config(config_uid, None)

    def _list_single_configuration(self, vault: vault_online.VaultOnline, config_uid: str,
                                   is_verbose: bool, format_type: str):
        """Lists details for a single PAM configuration."""
        configuration = self._load_and_validate_configuration(vault, config_uid, format_type)
        if format_type == 'json' and isinstance(configuration, str):
            return configuration
        facade = self._create_facade(configuration)
        shared_folder = self._load_shared_folder(vault, facade.folder_uid)
        
        if format_type == 'json':
            return self._format_single_config_json(configuration, facade, shared_folder)
        else:
            self._format_single_config_table(configuration, facade, shared_folder)

    def _list_all_configurations(self, vault: vault_online.VaultOnline, is_verbose: bool, format_type: str):
        """Lists all PAM configurations."""
        configs_data = []
        table = []
        headers = self._build_list_headers(is_verbose, format_type)
        
        for config_record in self._find_pam_configurations(vault):
            full_record = vault.vault_data.load_record(config_record.record_uid)
            if not full_record or not isinstance(full_record, vault_record.TypedRecord):
                logger.warning(
                    'Skipping PAM configuration that could not be loaded as a typed record: UID: %s, Title: %s',
                    config_record.record_uid, config_record.title)
                continue

            facade = self._create_facade(full_record)
            shared_folder_parents = vault_utils.get_folders_for_record(vault.vault_data, config_record.record_uid)

            if not shared_folder_parents:
                logger.warning(f'Following configuration is not in the shared folder: UID: %s, Title: %s',
                              config_record.record_uid, config_record.title)
                continue

            shared_folder = shared_folder_parents[0]
            
            if format_type == 'json':
                config_data = self._build_config_json_data(config_record, facade, shared_folder, full_record, is_verbose)
                configs_data.append(config_data)
            else:
                row = self._build_config_table_row(config_record, facade, shared_folder, full_record, is_verbose)
                table.append(row)

        return self._format_output(configs_data, table, headers, format_type)

    def _load_and_validate_configuration(self, vault: vault_online.VaultOnline, config_uid: str, format_type: str):
        """Loads and validates a PAM configuration record."""
        info = vault.vault_data.get_record(config_uid)
        if not info or info.version != 6 or info.record_type not in PAM_CONFIG_RECORD_TYPES:
            return self._handle_error(format_type, f'Configuration {config_uid} not found')

        configuration = vault.vault_data.load_record(config_uid)
        if not configuration or not isinstance(configuration, vault_record.TypedRecord):
            return self._handle_error(format_type, f'Configuration {config_uid} not found')

        return configuration

    def _handle_error(self, format_type: str, error_message: str):
        """Handles errors based on output format."""
        if format_type == 'json':
            return json.dumps({"error": error_message})
        else:
            raise Exception(error_message)

    def _create_facade(self, configuration):
        """Creates a PAM configuration facade for the given record."""
        facade = PamConfigurationRecordFacade()
        facade.record = configuration
        return facade

    def _load_shared_folder(self, vault: vault_online.VaultOnline, folder_uid: str):
        """Loads shared folder if it exists."""
        if folder_uid and folder_uid in vault.vault_data._shared_folders:
            return vault.vault_data.load_shared_folder(folder_uid)
        return None

    def _find_pam_configurations(self, vault: vault_online.VaultOnline):
        """Finds all PAM configuration records."""
        for record in vault.vault_data.find_records(criteria='', record_type=None, record_version=6):
            if record.record_type in PAM_CONFIG_RECORD_TYPES:
                yield record
            else:
                logger.warning(f'Following configuration has unsupported type: UID: %s, Title: %s',
                              record.record_uid, record.title)

    def _build_list_headers(self, is_verbose: bool, format_type: str):
        """Builds headers for the configuration list output."""
        if format_type == 'json':
            headers = ['uid', 'config_name', 'config_type', 'shared_folder', 'gateway_uid', 'resource_record_uids']
            if is_verbose:
                headers.append('fields')
        else:
            headers = ['UID', 'Config Name', 'Config Type', 'Shared Folder', 'Gateway UID', 'Resource Record UIDs']
            if is_verbose:
                headers.append('Fields')
        return headers

    @staticmethod
    def _field_values_for_display(field):
        """Normalize TypedField.get_external_value() to display strings."""
        raw = field.get_external_value()
        if raw is None:
            raw = field.value if isinstance(field.value, list) else None
        if raw is None:
            return []
        items = raw if isinstance(raw, list) else [raw]
        values = []
        for item in items:
            if item is None or item == '':
                continue
            if isinstance(item, (dict, list)):
                values.append(json.dumps(item))
            else:
                values.append(str(item))
        return values

    def _extract_config_fields(self, record, is_verbose: bool):
        """Extracts field data from a configuration record."""
        fields_data = {} if is_verbose else []
        
        for field in record.fields:
            if field.type in ('pamResources', 'fileRef'):
                continue
            
            values = self._field_values_for_display(field)
            if not values:
                continue
            
            field_name = field.external_name()
            if field.type == 'schedule':
                field_name = 'Default Schedule'
            
            value_str = ', '.join(values)
            if is_verbose:
                fields_data[field_name] = value_str
            else:
                fields_data.append(f'{field_name}: {value_str}')
        
        return fields_data

    def _build_config_json_data(self, config_record, facade, shared_folder, full_record, is_verbose: bool):
        """Builds JSON data structure for a configuration."""
        config_data = {
            "uid": config_record.record_uid,
            "config_name": config_record.title,
            "config_type": config_record.record_type,
            "shared_folder": {
                "name": shared_folder.name,
                "uid": shared_folder.folder_uid
            },
            "gateway_uid": facade.controller_uid,
            "resource_record_uids": facade.resource_ref
        }
        
        if is_verbose:
            config_data["fields"] = self._extract_config_fields(full_record, is_verbose=True)
        
        return config_data

    def _build_config_table_row(self, config_record, facade, shared_folder, full_record, is_verbose: bool):
        """Builds a table row for a configuration."""
        row = [
            config_record.record_uid,
            config_record.title,
            config_record.record_type,
            f'{shared_folder.name} ({shared_folder.folder_uid})',
            facade.controller_uid,
            facade.resource_ref
        ]
        
        if is_verbose:
            fields = self._extract_config_fields(full_record, is_verbose=False)
            row.append(fields)
        
        return row

    def _format_output(self, configs_data, table, headers, format_type: str):
        """Formats and outputs the final result."""
        if format_type == 'json':
            configs_data.sort(key=lambda x: x['config_name'] or '')
            return json.dumps({"configurations": configs_data}, indent=2)
        else:
            table.sort(key=lambda x: (x[1] or ''))
            report_utils.dump_report_data(table, headers, fmt='table', filename="", row_number=False, column_width=None)

    def _format_single_config_json(self, configuration, facade, shared_folder):
        """Formats a single configuration as JSON."""
        config_data = {
            "uid": configuration.record_uid,
            "name": configuration.title,
            "config_type": configuration.record_type,
            "shared_folder": {
                "name": shared_folder.name if shared_folder else None,
                "uid": shared_folder.shared_folder_uid if shared_folder else None
            } if shared_folder else None,
            "gateway_uid": facade.controller_uid,
            "resource_record_uids": facade.resource_ref,
            "fields": {}
        }
        
        for field in configuration.fields:
            if field.type in ('pamResources', 'fileRef'):
                continue
            
            values = self._field_values_for_display(field)
            if not values:
                continue
            
            field_name = field.external_name()
            if field.type == 'schedule':
                field_name = 'Default Schedule'
            
            config_data["fields"][field_name] = values
        
        return json.dumps(config_data, indent=2)

    def _format_single_config_table(self, configuration, facade, shared_folder):
        """Formats a single configuration as a table."""
        table = []
        header = ['name', 'value']
        
        table.append(['UID', configuration.record_uid])
        table.append(['Name', configuration.title])
        table.append(['Config Type', configuration.record_type])
        table.append(['Shared Folder', f'{shared_folder.name} ({shared_folder.shared_folder_uid})' if shared_folder else ''])
        table.append(['Gateway UID', facade.controller_uid])
        table.append(['Resource Record UIDs', facade.resource_ref])

        for field in configuration.fields:
            if field.type in ('pamResources', 'fileRef'):
                continue
            
            values = self._field_values_for_display(field)
            if not values:
                continue
            
            field_name = field.external_name()
            if field.type == 'schedule':
                field_name = 'Default Schedule'
            
            table.append([field_name, ', '.join(values)])
        
        report_utils.dump_report_data(table, header, no_header=True, right_align=(0,))


class PamConfigurationEditMixin(record_edit.RecordEditMixin):
    pam_record_types = None

    def __init__(self):
        super().__init__()

    @staticmethod
    def get_pam_record_types(vault: vault_online.VaultOnline):
        """Gets cached list of PAM record types."""
        if PamConfigurationEditMixin.pam_record_types is None:
            rts = [x for x in vault.vault_data._custom_record_types if x.scope // 1000000 == record_pb2.RT_PAM]
            PamConfigurationEditMixin.pam_record_types = [rt.id for rt in rts]
        return PamConfigurationEditMixin.pam_record_types

    def parse_pam_configuration(self, vault: vault_online.VaultOnline, record: vault_record.TypedRecord, **kwargs):
        """Parses PAM configuration fields: gateway, shared folder, and resource records."""
        field = self._get_or_create_pam_resources_field(record)
        value = self._ensure_pam_resources_value(field)
        
        self._parse_gateway_uid(vault, value, kwargs)
        self._parse_shared_folder_uid(vault, record, value, kwargs)
        self._parse_resource_records(vault, value, kwargs)

    def _get_or_create_pam_resources_field(self, record: vault_record.TypedRecord):
        """Gets or creates the pamResources field."""
        field = record.get_typed_field('pamResources')
        if not field:
            field = vault_record.TypedField.create_field('pamResources', '', required=False)
            record.fields.append(field)
        return field

    def _ensure_pam_resources_value(self, field):
        """Ensures the pamResources field has a value dictionary."""
        if len(field.value) == 0:
            field.value.append({})
        return field.value[0]

    def _parse_gateway_uid(self, vault: vault_online.VaultOnline, value: dict, kwargs: dict):
        """Resolves and sets the gateway UID from kwargs."""
        gateway = kwargs.get('gateway_uid')
        if not gateway:
            return
        
        gateways = gateway_utils.get_all_gateways(vault)
        gateway_uid = next(
            (utils.base64_url_encode(x.controllerUid) for x in gateways
             if utils.base64_url_encode(x.controllerUid) == gateway
             or x.controllerName.casefold() == gateway.casefold()),
            None
        )
        
        if gateway_uid:
            value['controllerUid'] = gateway_uid

    def _parse_shared_folder_uid(self, vault: vault_online.VaultOnline, record: vault_record.TypedRecord,
                                   value: dict, kwargs: dict):
        """Resolves and sets the shared folder UID from kwargs or existing record."""
        folder_name = kwargs.get('shared_folder_uid')
        shared_folder_uid = None
        
        if folder_name:
            shared_folder_uid = self._find_shared_folder_by_name_or_uid(vault, folder_name)
        
        if not shared_folder_uid:
            shared_folder_uid = self._get_existing_shared_folder_uid(record)
        
        if shared_folder_uid:
            value['folderUid'] = shared_folder_uid
        else:
            raise base.CommandError('Shared Folder not found')

    def _find_shared_folder_by_name_or_uid(self, vault: vault_online.VaultOnline, folder_name: str):
        """Finds a shared folder by UID or name."""
        shared_folder_cache = vault.vault_data._shared_folders
        
        if folder_name in shared_folder_cache:
            return folder_name
        
        for sf_uid in shared_folder_cache:
            sf = vault.vault_data.load_shared_folder(sf_uid)
            if sf and sf.name.casefold() == folder_name.casefold():
                return sf_uid
        
        return None

    def _get_existing_shared_folder_uid(self, record: vault_record.TypedRecord):
        """Gets the existing shared folder UID from the record."""
        for f in record.fields:
            if f.type == 'pamResources' and f.value and len(f.value) > 0:
                return f.value[0].get('folderUid')
        return None

    def _parse_resource_records(self, vault: vault_online.VaultOnline, value: dict, kwargs: dict):
        """Removes resource records from the configuration."""
        remove_records = kwargs.get('remove_records')
        if not remove_records:
            return
        
        pam_record_lookup = self._build_pam_record_lookup(vault)
        record_uids = set(value.get('resourceRef', []))
        
        if isinstance(remove_records, list):
            for r in remove_records:
                record_uid = pam_record_lookup.get(r) or pam_record_lookup.get(r.lower())
                if record_uid:
                    record_uids.discard(record_uid)
                else:
                    logger.warning(f'Failed to find PAM record: {r}')
        
        value['resourceRef'] = list(record_uids)

    def _build_pam_record_lookup(self, vault: vault_online.VaultOnline):
        """Builds a lookup dictionary for PAM records by UID and title."""
        pam_record_lookup = {}
        rti = PamConfigurationEditMixin.get_pam_record_types(vault)
        
        for r in vault.vault_data.records():
            if r.record_type in rti:
                pam_record_lookup[r.record_uid] = r.record_uid
                pam_record_lookup[r.title.lower()] = r.record_uid
        
        return pam_record_lookup

    @staticmethod
    def resolve_single_record(vault: vault_online.VaultOnline, record_name: str, rec_type: str = ''):
        """Resolves a single record by name and optional type."""
        for r in vault.vault_data.records():
            if r.title == record_name and (not rec_type or rec_type == r.record_type):
                return r
        return None

    def parse_properties(self, vault: vault_online.VaultOnline, record: vault_record.TypedRecord, **kwargs):
        """Parses all configuration properties based on record type."""
        self.parse_pam_configuration(vault, record, **kwargs)
        
        extra_properties = []
        self._parse_common_properties(extra_properties, kwargs)
        self._parse_type_specific_properties(vault, record, extra_properties, kwargs)
        
        if extra_properties:
            parsed_fields = [record_edit.RecordEditMixin.parse_field(x) for x in extra_properties]
            self.assign_typed_fields(record, parsed_fields)

    def _parse_common_properties(self, extra_properties: list, kwargs: dict):
        """Parses properties common to all PAM configuration types."""
        port_mapping = kwargs.get('port_mapping')
        if isinstance(port_mapping, list) and len(port_mapping) > 0:
            pm = "\n".join(port_mapping)
            extra_properties.append(f'multiline.portMapping={pm}')
        
        schedule = kwargs.get('default_schedule')
        if schedule:
            valid, err = validate_cron_expression(schedule, for_rotation=True)
            if not valid:
                raise base.CommandError(f'Invalid CRON "{schedule}" Error: {err}')
            extra_properties.append(f'schedule.defaultRotationSchedule=$JSON:{{"type": "CRON", "cron": "{schedule}", "tz": "Etc/UTC"}}')
        else:
            extra_properties.append('schedule.defaultRotationSchedule=On-Demand')

    def _parse_type_specific_properties(self, vault: vault_online.VaultOnline, record: vault_record.TypedRecord,
                                         extra_properties: list, kwargs: dict):
        """Parses properties specific to each configuration type."""
        record_type = record.record_type
        
        if record_type == 'pamNetworkConfiguration':
            self._parse_network_properties(extra_properties, kwargs)
        elif record_type == 'pamAwsConfiguration':
            self._parse_aws_properties(extra_properties, kwargs)
        elif record_type == 'pamGcpConfiguration':
            self._parse_gcp_properties(extra_properties, kwargs)
        elif record_type == 'pamAzureConfiguration':
            self._parse_azure_properties(extra_properties, kwargs)
        elif record_type == 'pamDomainConfiguration':
            self._parse_domain_properties(vault, record, extra_properties, kwargs)
        elif record_type == 'pamOciConfiguration':
            self._parse_oci_properties(extra_properties, kwargs)

    def _parse_network_properties(self, extra_properties: list, kwargs: dict):
        """Parses network configuration properties."""
        network_id = kwargs.get('network_id')
        if network_id:
            extra_properties.append(f'text.networkId={network_id}')
        
        network_cidr = kwargs.get('network_cidr')
        if network_cidr:
            extra_properties.append(f'text.networkCIDR={network_cidr}')

    def _parse_aws_properties(self, extra_properties: list, kwargs: dict):
        """Parses AWS configuration properties."""
        aws_id = kwargs.get('aws_id')
        if aws_id:
            extra_properties.append(f'text.awsId={aws_id}')
        
        access_key_id = kwargs.get('access_key_id')
        if access_key_id:
            extra_properties.append(f'secret.accessKeyId={access_key_id}')
        
        access_secret_key = kwargs.get('access_secret_key')
        if access_secret_key:
            extra_properties.append(f'secret.accessSecretKey={access_secret_key}')
        
        region_names = kwargs.get('region_names')
        if region_names:
            regions = '\n'.join(region_names)
            extra_properties.append(f'multiline.regionNames={regions}')

    def _parse_gcp_properties(self, extra_properties: list, kwargs: dict):
        """Parses GCP configuration properties."""
        gcp_id = kwargs.get('gcp_id')
        if gcp_id:
            extra_properties.append(f'text.pamGcpId={gcp_id}')
        
        service_account_key = kwargs.get('service_account_key')
        if service_account_key:
            extra_properties.append(f'json.pamServiceAccountKey={service_account_key}')
        
        google_admin_email = kwargs.get('google_admin_email')
        if google_admin_email:
            extra_properties.append(f'email.pamGoogleAdminEmail={google_admin_email}')
        
        gcp_region = kwargs.get('region_names')
        if gcp_region:
            regions = '\n'.join(gcp_region)
            extra_properties.append(f'multiline.pamGcpRegionName={regions}')

    def _parse_azure_properties(self, extra_properties: list, kwargs: dict):
        """Parses Azure configuration properties."""
        azure_id = kwargs.get('azure_id')
        if azure_id:
            extra_properties.append(f'text.azureId={azure_id}')
        
        client_id = kwargs.get('client_id')
        if client_id:
            extra_properties.append(f'secret.clientId={client_id}')
        
        client_secret = kwargs.get('client_secret')
        if client_secret:
            extra_properties.append(f'secret.clientSecret={client_secret}')
        
        subscription_id = kwargs.get('subscription_id')
        if subscription_id:
            extra_properties.append(f'secret.subscriptionId={subscription_id}')
        
        tenant_id = kwargs.get('tenant_id')
        if tenant_id:
            extra_properties.append(f'secret.tenantId={tenant_id}')
        
        resource_groups = kwargs.get('resource_groups')
        if isinstance(resource_groups, list) and len(resource_groups) > 0:
            rg = '\n'.join(resource_groups)
            extra_properties.append(f'multiline.resourceGroups={rg}')

    def _parse_domain_properties(self, vault: vault_online.VaultOnline, record: vault_record.TypedRecord,
                                  extra_properties: list, kwargs: dict):
        """Parses domain configuration properties."""
        domain_id = kwargs.get('domain_id')
        if domain_id:
            extra_properties.append(f'text.pamDomainId={domain_id}')
        
        self._parse_domain_hostname(extra_properties, kwargs)
        self._parse_domain_ssl_settings(extra_properties, kwargs)
        self._parse_domain_network_settings(extra_properties, kwargs)
        self._parse_domain_admin_credential(vault, record, kwargs)

    def _parse_domain_hostname(self, extra_properties: list, kwargs: dict):
        """Parses domain hostname and port settings."""
        host = str(kwargs.get('domain_hostname') or '').strip()
        port = str(kwargs.get('domain_port') or '').strip()
        if host or port:
            val = json.dumps({"hostName": host, "port": port})
            extra_properties.append(f"f.pamHostname=$JSON:{val}")

    def _parse_domain_ssl_settings(self, extra_properties: list, kwargs: dict):
        """Parses domain SSL and scan settings."""
        domain_use_ssl = dag_utils.value_to_boolean(kwargs.get('domain_use_ssl'))
        if domain_use_ssl is not None:
            val = 'true' if domain_use_ssl else 'false'
            extra_properties.append(f'checkbox.useSSL={val}')
        
        domain_scan_dc_cidr = dag_utils.value_to_boolean(kwargs.get('domain_scan_dc_cidr'))
        if domain_scan_dc_cidr is not None:
            val = 'true' if domain_scan_dc_cidr else 'false'
            extra_properties.append(f'checkbox.scanDCCIDR={val}')

    def _parse_domain_network_settings(self, extra_properties: list, kwargs: dict):
        """Parses domain network CIDR settings."""
        domain_network_cidr = kwargs.get('domain_network_cidr')
        if domain_network_cidr:
            extra_properties.append(f'text.networkCIDR={domain_network_cidr}')

    def _parse_domain_admin_credential(self, vault: vault_online.VaultOnline, record: vault_record.TypedRecord,
                                        kwargs: dict):
        """Parses and validates domain administrative credential."""
        domain_administrative_credential = kwargs.get('domain_administrative_credential')
        dac = str(domain_administrative_credential or '')
        
        if not dac:
            return
        
        if kwargs.get('force_domain_admin', False) is True:
            if not re.search('^[A-Za-z0-9-_]{22}$', dac):
                logger.warning(f'Invalid Domain Admin User UID: "{dac}" (skipped)')
                dac = ''
        else:
            adm_rec = PamConfigurationEditMixin.resolve_single_record(vault, dac, 'pamUser')
            if adm_rec and isinstance(adm_rec, vault_record.TypedRecord) and adm_rec.record_type == 'pamUser':
                dac = adm_rec.record_uid
            else:
                logger.warning(f'Domain Admin User UID: "{dac}" not found (skipped).')
                dac = ''
        
        if dac:
            prf = record.get_typed_field('pamResources')
            prf.value = prf.value or [{}]
            prf.value[0]["adminCredentialRef"] = dac

    def _parse_oci_properties(self, extra_properties: list, kwargs: dict):
        """Parses OCI configuration properties."""
        oci_id = kwargs.get('oci_id')
        if oci_id:
            extra_properties.append(f'text.pamOciId={oci_id}')
        
        oci_admin_id = kwargs.get('oci_admin_id')
        if oci_admin_id:
            extra_properties.append(f'secret.adminOcid={oci_admin_id}')
        
        oci_admin_public_key = kwargs.get('oci_admin_public_key')
        if oci_admin_public_key:
            extra_properties.append(f'secret.adminPublicKey={oci_admin_public_key}')
        
        oci_admin_private_key = kwargs.get('oci_admin_private_key')
        if oci_admin_private_key:
            extra_properties.append(f'secret.adminPrivateKey={oci_admin_private_key}')
        
        oci_tenancy = kwargs.get('oci_tenancy')
        if oci_tenancy:
            extra_properties.append(f'text.tenancyOci={oci_tenancy}')
        
        oci_region = kwargs.get('oci_region')
        if oci_region:
            extra_properties.append(f'text.regionOci={oci_region}')

    def verify_required(self, record: vault_record.TypedRecord):
        """Verifies and sets default values for required fields."""
        for field in record.fields:
            if field.required and len(field.value) == 0:
                if field.type == 'schedule':
                    field.value = [{'type': 'ON_DEMAND'}]
                else:
                    self.warnings.append(f'Empty required field: "{field.external_name()}"')
        
        for custom in record.custom:
            if custom.required:
                custom.required = False

    def _configure_tunneling(self, vault: vault_online.VaultOnline, record: vault_record.TypedRecord,
                              admin_cred_ref: str, kwargs: dict):
        """Configures tunneling settings for the configuration."""
        encrypted_session_token, encrypted_transmission_key, transmission_key = tunnel_utils.get_keeper_tokens(vault)
        tmp_dag = TunnelDAG(vault, encrypted_session_token, encrypted_transmission_key,
                           record_uid=record.record_uid, is_config=True, transmission_key=transmission_key)

        tmp_dag.edit_tunneling_config(
            kwargs.get('connections'),
            kwargs.get('tunneling'),
            kwargs.get('rotation'),
            kwargs.get('recording'),
            kwargs.get('typescriptrecording'),
            kwargs.get('remotebrowserisolation')
        )

        if admin_cred_ref:
            tmp_dag.link_user_to_config_with_options(admin_cred_ref, is_admin='on')

        tmp_dag.print_tunneling_config(record.record_uid, None)


# Configuration type mapping
CONFIG_TYPE_TO_RECORD_TYPE = {
    'aws': 'pamAwsConfiguration',
    'azure': 'pamAzureConfiguration',
    'local': 'pamNetworkConfiguration',
    'network': 'pamNetworkConfiguration',
    'gcp': 'pamGcpConfiguration',
    'domain': 'pamDomainConfiguration',
    'oci': 'pamOciConfiguration'
}

common_parser = argparse.ArgumentParser(add_help=False)
common_parser.add_argument('--environment', '-env', dest='config_type', action='store',
                        choices=['local', 'aws', 'azure', 'gcp', 'domain', 'oci'], help='PAM Configuration Type')
common_parser.add_argument('--title', '-t', dest='title', action='store', help='Title of the PAM Configuration')
common_parser.add_argument('--gateway', '-g', dest='gateway_uid', action='store', help='Gateway UID or Name')
common_parser.add_argument('--shared-folder', '-sf', dest='shared_folder_uid', action='store',
                        help='Share Folder where this PAM Configuration is stored. Should be one of the folders to '
                                'which the gateway has access to.')
common_parser.add_argument('--schedule', '-sc', dest='default_schedule', action='store',
                        help='Default Schedule: Use CRON syntax')
common_parser.add_argument('--port-mapping', '-pm', dest='port_mapping', action='append', help='Port Mapping')
common_parser.add_argument('--identity-provider', '-idp', dest='identity_provider_uid',
                        action='store', help='Identity Provider UID')
network_group = common_parser.add_argument_group('network', 'Local network configuration')
network_group.add_argument('--network-id', dest='network_id', action='store', help='Network ID')
network_group.add_argument('--network-cidr', dest='network_cidr', action='store', help='Network CIDR')
aws_group = common_parser.add_argument_group('aws', 'AWS configuration')
aws_group.add_argument('--aws-id', dest='aws_id', action='store', help='AWS ID')
aws_group.add_argument('--access-key-id', dest='access_key_id', action='store', help='Access Key Id')
aws_group.add_argument('--access-secret-key', dest='access_secret_key', action='store', help='Access Secret Key')
aws_group.add_argument('--region-name', dest='region_names', action='append', help='Region Names')
azure_group = common_parser.add_argument_group('azure', 'Azure configuration')
azure_group.add_argument('--azure-id', dest='azure_id', action='store', help='Azure Id')
azure_group.add_argument('--client-id', dest='client_id', action='store', help='Client Id')
azure_group.add_argument('--client-secret', dest='client_secret', action='store', help='Client Secret')
azure_group.add_argument('--subscription_id', dest='subscription_id', action='store',
                        help='Subscription Id')
azure_group.add_argument('--tenant-id', dest='tenant_id', action='store', help='Tenant Id')
azure_group.add_argument('--resource-group', dest='resource_groups', action='append', help='Resource Group')
domain_group = common_parser.add_argument_group('domain', 'Domain configuration')
domain_group.add_argument('--domain-id', dest='domain_id', action='store', help='Domain ID')
domain_group.add_argument('--domain-hostname', dest='domain_hostname', action='store', help='Domain hostname')
domain_group.add_argument('--domain-port', dest='domain_port', action='store', help='Domain port')
domain_group.add_argument('--domain-use-ssl', dest='domain_use_ssl', choices=['true', 'false'],
                        help='Domain use SSL flag')
domain_group.add_argument('--domain-scan-dc-cidr', dest='domain_scan_dc_cidr', choices=['true', 'false'],
                        help='Domain scan DC CIDR flag')
domain_group.add_argument('--domain-network-cidr', dest='domain_network_cidr', action='store',
                        help='Domain Network CIDR')
domain_group.add_argument('--domain-admin', dest='domain_administrative_credential', action='store',
                        help='Domain administrative credential')
oci_group = common_parser.add_argument_group('oci', 'OCI configuration')
oci_group.add_argument('--oci-id', dest='oci_id', action='store', help='OCI ID')
oci_group.add_argument('--oci-admin-id', dest='oci_admin_id', action='store', help='OCI Admin ID')
oci_group.add_argument('--oci-admin-public-key', dest='oci_admin_public_key', action='store',
                    help='OCI admin public key')
oci_group.add_argument('--oci-admin-private-key', dest='oci_admin_private_key', action='store',
                    help='OCI admin private key')
oci_group.add_argument('--oci-tenancy', dest='oci_tenancy', action='store', help='OCI tenancy')
oci_group.add_argument('--oci-region', dest='oci_region', action='store', help='OCI region')

gcp_group = common_parser.add_argument_group('gcp', 'GCP configuration')
gcp_group.add_argument('--gcp-id', dest='gcp_id', action='store', help='GCP Id')
gcp_group.add_argument('--service-account-key', dest='service_account_key', action='store',
                    help='Service Account Key (JSON format)')
gcp_group.add_argument('--google-admin-email', dest='google_admin_email', action='store',
                    help='Google Workspace Administrator Email Address')
gcp_group.add_argument('--gcp-region', dest='region_names', action='append', help='GCP Region Names')


class PAMConfigNewCommand(base.ArgparseCommand, PamConfigurationEditMixin):

    def __init__(self):
        self.choices = ['on', 'off', 'default']
        parser = argparse.ArgumentParser(prog='pam config new', parents=[common_parser])
        PAMConfigNewCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        choices = ['on', 'off', 'default']
        parser.add_argument('--connections', '-c', dest='connections', choices=choices,
                            help='Set connections permissions')
        parser.add_argument('--tunneling', '-u', dest='tunneling', choices=choices,
                            help='Set tunneling permissions')
        parser.add_argument('--rotation', '-r', dest='rotation', choices=choices,
                            help='Set rotation permissions')
        parser.add_argument('--remote-browser-isolation', '-rbi', dest='remotebrowserisolation', choices=choices,
                            help='Set remote browser isolation permissions')
        parser.add_argument('--connections-recording', '-cr', dest='recording', choices=choices,
                            help='Set recording connections permissions for the resource')
        parser.add_argument('--typescript-recording', '-tr', dest='typescriptrecording', choices=choices,
                            help='Set TypeScript recording permissions for the resource')
        parser.add_argument('--ai-threat-detection', dest='ai_threat_detection', choices=choices,
                            help='Set AI threat detection permissions')
        parser.add_argument('--ai-terminate-session-on-detection', dest='ai_terminate_session_on_detection',
                        choices=choices,
                        help='Set AI session termination on threat detection permissions')

    def execute(self, context: KeeperParams, **kwargs):
        self.warnings.clear()
        self._validate_vault(context)
        
        vault = context.vault
        record_type = self._resolve_record_type(kwargs)
        title = self._validate_title(kwargs)
        
        record = self._create_record(vault, record_type, title)
        self._resolve_shared_folder_path(context, kwargs)
        self.parse_properties(vault, record, **kwargs)
        
        gateway_uid, shared_folder_uid, admin_cred_ref = self._extract_pam_resources(record, kwargs)
        self._validate_shared_folder(shared_folder_uid, kwargs)
        self._warn_if_gateway_missing(gateway_uid, kwargs)
        
        self.verify_required(record)
        self._create_and_configure_record(vault, record, shared_folder_uid, gateway_uid, admin_cred_ref, kwargs)
        
        self._log_warnings()
        return record.record_uid

    def _validate_vault(self, context: KeeperParams):
        """Validates that vault is initialized."""
        if not context.vault:
            raise base.CommandError('Vault is not initialized. Login to initialize the vault.')

    def _resolve_record_type(self, kwargs: dict) -> str:
        """Resolves the record type from config type parameter."""
        config_type = kwargs.get('config_type')
        if not config_type:
            raise base.CommandError('--config-type parameter is required')
        
        record_type = CONFIG_TYPE_TO_RECORD_TYPE.get(config_type)
        if not record_type:
            supported = ', '.join(CONFIG_TYPE_TO_RECORD_TYPE.keys())
            raise base.CommandError(f'--config-type {config_type} is not supported - supported options: {supported}')
        
        return record_type

    def _validate_title(self, kwargs: dict) -> str:
        """Validates that title is provided."""
        title = kwargs.get('title')
        if not title:
            raise base.CommandError('--title parameter is required')
        return title

    def _create_record(self, vault: vault_online.VaultOnline, record_type: str, title: str):
        """Creates a new typed record with the specified type and title."""
        record = vault_record.TypedRecord()
        record.record_type = record_type
        record.title = title
        record.record_version = 6
        
        record_type_def = vault.vault_data.get_record_type_by_name(record_type)
        if record_type_def and record_type_def.fields:
            RecordEditMixin.adjust_typed_record_fields(record, record_type_def.fields)
        
        return record

    def _resolve_shared_folder_path(self, context: KeeperParams, kwargs: dict):
        """Resolves shared folder path to UID."""
        sf_name = kwargs.get('shared_folder_uid', '')
        if not sf_name:
            return
        
        fpath = folder_utils.try_resolve_path(context, sf_name)
        if fpath and len(fpath) >= 2 and fpath[-1] == '':
            sfuid = fpath[-2].folder_uid
            if sfuid:
                kwargs['shared_folder_uid'] = sfuid

    def _extract_pam_resources(self, record: vault_record.TypedRecord, kwargs: dict):
        """Extracts gateway UID, shared folder UID, and admin credential ref from record."""
        field = record.get_typed_field('pamResources')
        if not field:
            raise base.CommandError('PAM configuration record does not contain resource field')
        
        value = field.get_default_value(dict)
        if not value:
            return None, None, None
        
        gateway_uid = value.get('controllerUid')
        shared_folder_uid = value.get('folderUid')
        admin_cred_ref = None
        
        if record.record_type == 'pamDomainConfiguration' and not kwargs.get('force_domain_admin', False):
            admin_cred_ref = value.get('adminCredentialRef')
        
        return gateway_uid, shared_folder_uid, admin_cred_ref

    def _validate_shared_folder(self, shared_folder_uid: str, kwargs: dict):
        """Validates that shared folder UID is present."""
        if not shared_folder_uid:
            raise base.CommandError('--shared-folder parameter is required to create a PAM configuration')

    def _warn_if_gateway_missing(self, gateway_uid: str, kwargs: dict):
        """Warns if gateway is not found."""
        if not gateway_uid:
            gw_name = kwargs.get('gateway_uid') or ''
            logger.warning(f'Gateway "{gw_name}" not found.')

    def _create_and_configure_record(self, vault: vault_online.VaultOnline, record: vault_record.TypedRecord,
                                      shared_folder_uid: str, gateway_uid: str, admin_cred_ref: str, kwargs: dict):
        """Creates the record and configures tunneling, DAG, and controller."""
        config_utils.pam_configuration_create_record_v6(vault, record, shared_folder_uid)
        
        self._configure_tunneling(vault, record, admin_cred_ref, kwargs)
        
        vault.sync_down()
        record_management.move_vault_objects(vault, [record.record_uid], shared_folder_uid)
        vault.sync_down()
        
        if gateway_uid:
            self._set_configuration_controller(vault, record.record_uid, gateway_uid)

    def _set_configuration_controller(self, vault: vault_online.VaultOnline, config_uid: str, gateway_uid: str):
        """Sets the controller for the PAM configuration."""
        pcc = pam_pb2.PAMConfigurationController()
        pcc.configurationUid = utils.base64_url_decode(config_uid)
        pcc.controllerUid = utils.base64_url_decode(gateway_uid)
        vault.keeper_auth.execute_auth_rest('pam/set_configuration_controller', pcc)

    def _log_warnings(self):
        """Logs all warnings."""
        for w in self.warnings:
            logger.warning(w)


class PAMConfigEditCommand(base.ArgparseCommand, PamConfigurationEditMixin):

    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam config edit', parents=[common_parser])
        PAMConfigEditCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        choices = ['on', 'off', 'default']
        parser.add_argument('uid', type=str, action='store', help='The Config UID to edit')
        parser.add_argument('--remove-resource-record', '-rrr', dest='remove_records', action='append',
                            help='Resource Record UID to remove')
        parser.add_argument('--connections', '-c', dest='connections', choices=choices,
                            help='Set connections permissions')
        parser.add_argument('--tunneling', '-u', dest='tunneling', choices=choices,
                            help='Set tunneling permissions')
        parser.add_argument('--rotation', '-r', dest='rotation', choices=choices,
                            help='Set rotation permissions')
        parser.add_argument('--remote-browser-isolation', '-rbi', dest='remotebrowserisolation', choices=choices,
                            help='Set remote browser isolation permissions')
        parser.add_argument('--connections-recording', '-cr', dest='recording', choices=choices,
                            help='Set recording connections permissions for the resource')
        parser.add_argument('--typescript-recording', '-tr', dest='typescriptrecording', choices=choices,
                            help='Set TypeScript recording permissions for the resource')
    
    def execute(self, context: KeeperParams, **kwargs):
        self.warnings.clear()
        self._validate_vault(context)
        
        vault = context.vault
        configuration = self._find_configuration(vault, kwargs.get('uid'))
        self._validate_configuration(vault, configuration, kwargs.get('uid'))
        
        self._update_record_type_if_needed(vault, configuration, kwargs)
        self._update_title_if_provided(configuration, kwargs)
        
        orig_gateway_uid, orig_shared_folder_uid = self._get_original_values(configuration)
        self.parse_properties(vault, configuration, **kwargs)
        self.verify_required(configuration)
        
        record_management.update_record(vault, configuration)
        self._update_controller_and_folder_if_changed(vault, configuration, orig_gateway_uid, orig_shared_folder_uid)

        if any(kwargs.get(k) is not None for k in (
                'connections', 'tunneling', 'rotation', 'recording', 'typescriptrecording', 'remotebrowserisolation')):
            admin_cred_ref = None
            if configuration.record_type == 'pamDomainConfiguration' and not kwargs.get('force_domain_admin'):
                pam_field = configuration.get_typed_field('pamResources')
                if pam_field:
                    value = pam_field.get_default_value(dict)
                    if isinstance(value, dict):
                        admin_cred_ref = value.get('adminCredentialRef')
            self._configure_tunneling(vault, configuration, admin_cred_ref, kwargs)
        
        self._log_warnings()
        vault.sync_down()

    def _validate_vault(self, context: KeeperParams):
        """Validates that vault is initialized."""
        if not context.vault:
            raise base.CommandError('Vault is not initialized. Login to initialize the vault.')

    def _find_configuration(self, vault: vault_online.VaultOnline, config_name: str):
        """Finds a PAM configuration by UID or name."""
        if not config_name:
            return None
        info = vault.vault_data.get_record(config_name)
        if info and info.version == 6 and info.record_type in PAM_CONFIG_RECORD_TYPES:
            loaded = vault.vault_data.load_record(config_name)
            if loaded and isinstance(loaded, vault_record.TypedRecord):
                return loaded
        name_lower = config_name.casefold()
        for record in vault.vault_data.find_records(
                criteria=None,
                record_type=PAM_CONFIG_RECORD_TYPES,
                record_version=6):
            if record.record_uid == config_name or record.title.casefold() == name_lower:
                loaded = vault.vault_data.load_record(record.record_uid)
                if loaded and isinstance(loaded, vault_record.TypedRecord):
                    return loaded
        return None

    def _validate_configuration(self, vault: vault_online.VaultOnline, configuration, config_name: str):
        """Validates that the configuration exists and is a v6 PAM config in the vault index."""
        if not configuration:
            raise base.CommandError(f'PAM configuration "{config_name}" not found')
        if not isinstance(configuration, vault_record.TypedRecord):
            raise base.CommandError(f'PAM configuration "{config_name}" not found')
        # Storage format is on KeeperRecordInfo, not TypedRecord.version() (that method returns 3).
        info = vault.vault_data.get_record(configuration.record_uid)
        if not info or info.version != 6 or info.record_type not in PAM_CONFIG_RECORD_TYPES:
            raise base.CommandError(f'PAM configuration "{config_name}" not found')

    def _update_record_type_if_needed(self, vault: vault_online.VaultOnline, configuration: vault_record.TypedRecord,
                                       kwargs: dict):
        """Updates the record type if config_type is provided and different."""
        config_type = kwargs.get('config_type')
        if not config_type:
            return
        
        record_type = CONFIG_TYPE_TO_RECORD_TYPE.get(config_type, configuration.record_type)
        
        if record_type != configuration.record_type:
            configuration.record_type = record_type
            record_type_def = vault.vault_data.get_record_type_by_name(record_type)
            if record_type_def and record_type_def.fields:
                RecordEditMixin.adjust_typed_record_fields(configuration, record_type_def.fields)

    def _update_title_if_provided(self, configuration: vault_record.TypedRecord, kwargs: dict):
        """Updates the title if provided."""
        title = kwargs.get('title')
        if title:
            configuration.title = title

    def _get_original_values(self, configuration: vault_record.TypedRecord):
        """Gets the original gateway and shared folder UIDs before updates."""
        field = configuration.get_typed_field('pamResources')
        if not field:
            raise base.CommandError('PAM configuration record does not contain resource field')
        
        value = field.get_default_value(dict)
        if value:
            return value.get('controllerUid') or '', value.get('folderUid') or ''
        
        return '', ''

    def _update_controller_and_folder_if_changed(self, vault: vault_online.VaultOnline,
                                                    configuration: vault_record.TypedRecord,
                                                    orig_gateway_uid: str, orig_shared_folder_uid: str):
        """Updates controller and shared folder if they changed."""
        field = configuration.get_typed_field('pamResources')
        value = field.get_default_value(dict)
        if not value:
            return
        
        gateway_uid = value.get('controllerUid') or ''
        if gateway_uid != orig_gateway_uid:
            self._set_configuration_controller(vault, configuration.record_uid, gateway_uid)
        
        shared_folder_uid = value.get('folderUid') or ''
        if shared_folder_uid != orig_shared_folder_uid:
            record_management.move_vault_objects(vault, [configuration.record_uid], shared_folder_uid)

    def _set_configuration_controller(self, vault: vault_online.VaultOnline, config_uid: str, gateway_uid: str):
        """Sets the controller for the PAM configuration."""
        pcc = pam_pb2.PAMConfigurationController()
        pcc.configurationUid = utils.base64_url_decode(config_uid)
        pcc.controllerUid = utils.base64_url_decode(gateway_uid)
        vault.keeper_auth.execute_auth_rest('pam/set_configuration_controller', pcc)

    def _log_warnings(self):
        """Logs all warnings."""
        for w in self.warnings:
            logger.warning(w)


class PAMConfigRemoveCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam config remove')
        PAMConfigRemoveCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('config', type=str, action='store', 
            help='PAM Configuration UID. To view all rotation settings with their UIDs, use command `pam config list`')
    
    def execute(self, context: KeeperParams, **kwargs):
        self._validate_vault(context)
        
        vault = context.vault
        pam_config_name = kwargs.get('config')
        pam_config_uid = self._find_configuration_uid(vault, pam_config_name)
        
        if not pam_config_uid:
            raise base.CommandError(f'Configuration "{pam_config_name}" not found')

        record_management.delete_vault_objects(vault, [pam_config_uid])
        vault.sync_down()

    def _validate_vault(self, context: KeeperParams):
        """Validates that vault is initialized."""
        if not context.vault:
            raise base.CommandError('Vault is not initialized. Login to initialize the vault.')

    def _find_configuration_uid(self, vault: vault_online.VaultOnline, config_name: str) -> str:
        """Finds a PAM configuration UID by UID or name."""
        if not config_name:
            return None
        info = vault.vault_data.get_record(config_name)
        if info and info.version == 6 and info.record_type in PAM_CONFIG_RECORD_TYPES:
            return config_name
        name_lower = config_name.casefold()
        for record in vault.vault_data.find_records(
                criteria=None,
                record_type=PAM_CONFIG_RECORD_TYPES,
                record_version=6):
            if record.record_uid == config_name or record.title.casefold() == name_lower:
                return record.record_uid
        return None


def validate_cron_field(field: str, min_val: int, max_val: int) -> bool:
    # Accept *, single number, range, step, list, and L suffix for last day/week
    pattern = r'^(\*|\d+L?|L[W]?|\d+-\d+|\*/\d+|\d+(,\d+)*|\d+-\d+/\d+)$'
    if not re.match(pattern, field):
        return False

    def is_valid_number(n: str) -> bool:
        # Strip L and W suffix if present (for last day/week expressions)
        n_stripped = n.rstrip('LW')
        return n_stripped and n_stripped.isdigit() and min_val <= int(n_stripped) <= max_val

    parts = re.split(r'[,\-/]', field)
    return all(part == '*' or part in ('L', 'LW') or is_valid_number(part) for part in parts if part != '*')


def validate_cron_expression(expr: str, for_rotation: bool = False) -> tuple[bool, str]:
    parts = expr.strip().split()

    if for_rotation is True:
        if len(parts) != 6:
            return False, f"CRON: Rotation schedules require all 6 parts incl. seconds - ex. Daily at 04:00:00 cron: 0 0 4 * * ? got {len(parts)} parts"
        if not(parts[3] == '?' or parts[5] == "?"):
            logger.warning("CRON: Rotation schedule CRON format - must use ? character in one of these fields: day-of-week, day-of-month")
        parts[3] = '*' if parts[3] == '?' else parts[3]
        parts[5] = '*' if parts[5] == '?' else parts[5]
        logger.debug("WARNING! Validating CRON expression for rotation - if you get 500 type errors make sure to validate your CRON using web vault UI")

    if len(parts) not in [5, 6]:
        return False, f"CRON: Expected 5 or 6 fields, got {len(parts)}"

    if len(parts) == 6:
        seconds, minute, hour, dom, month, dow = parts
        if not validate_cron_field(seconds, 0, 59):
            return False, "CRON: Invalid seconds field"
    else:
        minute, hour, dom, month, dow = parts

    validators = [
        (minute, 0, 59, "minute"),
        (hour, 0, 23, "hour"),
        (dom, 1, 31, "day of month"),
        (month, 1, 12, "month"),
        (dow, 0, 7, "day of week")
    ]

    for field, min_val, max_val, name in validators:
        if not validate_cron_field(field, min_val, max_val):
            return False, f"CRON: Invalid {name} field"

    return True, "Valid cron expression"

