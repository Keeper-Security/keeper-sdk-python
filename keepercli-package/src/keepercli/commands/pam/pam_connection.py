import os
import argparse

from keepersdk import utils
from keepersdk.helpers.keeper_dag import dag_utils
from keepersdk.helpers.tunnel.tunnel_graph import TunnelDAG
from keepersdk.helpers.tunnel.tunnel_utils import get_keeper_tokens, get_config_uid
from keepersdk.vault import record_management, vault_record

from .. import base
from ... import api
from ...params import KeeperParams


logger = api.get_logger()


protocols = ['', 'http', 'kubernetes', 'mysql', 'postgresql', 'rdp', 'sql-server', 'ssh', 'telnet', 'vnc']
choices = ['on', 'off', 'default']


class PAMConnectionEditCommand(base.ArgparseCommand):
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam connection edit')
        PAMConnectionEditCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('record', type=str, action='store', help='The record UID or path of the PAM '
                            'resource record with network information to use for connections')
        parser.add_argument('--configuration', '-c', required=False, dest='config', action='store',
                            help='The PAM Configuration UID or path to use for connections. '
                            'Use command `pam config list` to view available PAM Configurations.')

        parser.add_argument('--admin-user', '-a', required=False, dest='admin', action='store',
                            help='The record path or UID of the PAM User record to configure the admin '
                            'credential on the PAM Resource')
        parser.add_argument('--launch-user', '-lu', required=False, dest='launch_user', action='store',
                            help='The record path or UID of the PAM User record to configure as the launch '
                            'credential on the PAM Resource')
        parser.add_argument('--protocol', '-p', dest='protocol', choices=protocols,
                            help='Set connection protocol')
        parser.add_argument('--connections', '-cn', dest='connections', choices=choices,
                            help='Set connections permissions')
        parser.add_argument('--connections-recording', '-cr', dest='recording', choices=choices,
                            help='Set recording connections permissions for the resource')
        parser.add_argument('--typescript-recording', '-tr', dest='typescriptrecording', choices=choices,
                            help='Set TypeScript recording permissions for the resource')
        parser.add_argument('--connections-override-port', '-cop', required=False, dest='connections_override_port',
                            action='store', help='Port to use for connections. If not provided, '
                            'the port from the record will be used.')
        parser.add_argument('--key-events', '-k', dest='key_events', choices=choices,
                            help='Toggle Key Events settings')
        parser.add_argument('--silent', '-s', required=False, dest='silent', action='store_true',
                            help='Silent mode - don\'t print PAM User, PAM Config etc.')

    def execute(self, context: KeeperParams, **kwargs):
        connection_override_port = kwargs.get('connections_override_port', None)

        # Convert on/off/default to True/False/None
        _connections = TunnelDAG._convert_allowed_setting(kwargs.get('connections', None))
        _recording = TunnelDAG._convert_allowed_setting(kwargs.get('recording', None))
        _typescript_recording = TunnelDAG._convert_allowed_setting(kwargs.get('typescriptrecording', None))

        vault = context.vault

        if connection_override_port:
            try:
                connection_override_port = int(connection_override_port)
            except ValueError:
                raise base.CommandError(f'--connections-override-port must be an integer')

        record_name = kwargs.get('record')
        if not record_name:
            raise base.CommandError(f'Record parameter is required.')
        record = vault.vault_data.load_record(record_name)
        if not record:
            raise base.CommandError(f'Record \"{record_name}\" not found.')
        if not isinstance(record, vault_record.TypedRecord):
            raise base.CommandError(f'Record \"{record_name}\" can not be edited.')

        config_name = kwargs.get('config', None)
        cfg_rec = vault.vault_data.load_record(config_name)
        if not cfg_rec and record.version == 6:
            cfg_rec = record
        config_uid = cfg_rec.record_uid if cfg_rec else None

        record_uid = record.record_uid
        record_type = record.record_type
        if record_type not in ("pamMachine pamDatabase pamDirectory pamNetworkConfiguration pamAwsConfiguration "
                               "pamRemoteBrowser pamAzureConfiguration").split():
            raise base.CommandError(f"This record's type is not supported for connections. "
                                   f"Connections are only supported on pamMachine, pamDatabase, pamDirectory, "
                                   f"pamRemoteBrowser, pamNetworkConfiguration pamAwsConfiguration, and "
                                   f"pamAzureConfiguration records")

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(vault)
        if record_type in "pamNetworkConfiguration pamAwsConfiguration pamAzureConfiguration".split():
            tdag = TunnelDAG(vault, encrypted_session_token, encrypted_transmission_key, record_uid, is_config=True)
            tdag.edit_tunneling_config(connections=_connections, session_recording=_recording, typescript_recording=_typescript_recording)
            if not kwargs.get("silent", False): tdag.print_tunneling_config(record_uid, None)
        else:
            traffic_encryption_key = record.get_typed_field('trafficEncryptionSeed')

            seed = os.urandom(32)
            dirty = False
            if not traffic_encryption_key or not traffic_encryption_key.value:
                base64_seed = utils.base64_url_encode(seed)
                record_seed = vault_record.TypedField.create_field('trafficEncryptionSeed', base64_seed, required=False)

                record_types_with_seed = ("pamDatabase", "pamDirectory", "pamMachine", "pamRemoteBrowser")
                if traffic_encryption_key:
                    traffic_encryption_key.value = [base64_seed]
                elif record.record_type in record_types_with_seed:
                    record.fields.append(record_seed)
                else:
                    record.custom.append(record_seed)
                dirty = True

            protocol = kwargs.get("protocol", None)
            pam_settings = record.get_typed_field('pamSettings')
            if not pam_settings:
                pre_settings = {"connection": {}, "portForward": {}}
                if _connections:
                    if connection_override_port:
                        pre_settings["connection"]["port"] = connection_override_port
                    if protocol:
                        pre_settings["connection"]["protocol"] = protocol
                elif protocol or connection_override_port:
                    logger.warning(f'Connection override port and protocol can be set only when connections are enabled '
                            f'with --connections=on option')
                if pre_settings:
                    pam_settings = vault_record.TypedField.create_field('pamSettings', required=False)
                    pam_settings.value = [pre_settings]
                    record.custom.append(pam_settings)
                    dirty = True
            else:
                if not pam_settings.value:
                    pam_settings.value.append({"connection": {}, "portForward": {}})
                if not pam_settings.value[0]:
                    pam_settings.value[0] = {"connection": {}, "portForward": {}}
                if _connections:
                    if connection_override_port:
                        pam_settings.value[0]["connection"]["port"] = connection_override_port
                    elif connection_override_port is not None:
                        pam_settings.value[0]["connection"].pop("port", None)
                    if protocol:
                        pam_settings.value[0]["connection"]["protocol"] = protocol
                    elif protocol is not None:
                        pam_settings.value[0]["connection"].pop("protocol", None)
                    dirty = True
                elif protocol or connection_override_port:
                    logger.warning(f'Connection override port and protocol can be set only when connections are enabled '
                            f'with --connections=on option')

            key_events = kwargs.get('key_events')  # on/off/default
            if key_events:
                psv = pam_settings.value[0] if pam_settings and pam_settings.value else {}
                vcon = psv.get('connection', {}) if isinstance(psv, dict) else {}
                rik = vcon.get('recordingIncludeKeys') if isinstance(vcon, dict) else None
                if key_events == 'default':
                    if rik is not None:
                        pam_settings.value[0]["connection"].pop('recordingIncludeKeys', None)
                        dirty = True
                    else:
                        logger.debug(f'recordingIncludeKeys is already set to "default" on record={record_uid}')
                elif key_events == 'on':
                    if dag_utils.value_to_boolean(key_events) != dag_utils.value_to_boolean(rik):
                        pam_settings.value[0]["connection"]["recordingIncludeKeys"] = True
                        dirty = True
                    else:
                        logger.debug(f'recordingIncludeKeys is already enabled on record={record_uid}')
                elif key_events == 'off':
                    if dag_utils.value_to_boolean(key_events) != dag_utils.value_to_boolean(rik):
                        pam_settings.value[0]["connection"]["recordingIncludeKeys"] = False
                        dirty = True
                    else:
                        logger.debug(f'recordingIncludeKeys is already disabled on record={record_uid}')
                else:
                    logger.debug(f'Unexpected value for --key-events {key_events} (ignored)')

            if dirty:
                record_management.update_record(vault, record)
                vault.sync_down()

                traffic_encryption_key = record.get_typed_field('trafficEncryptionSeed')
                if not traffic_encryption_key:
                    raise base.CommandError(f"Unable to add Seed to record {record_uid}. "
                                       f"Please make sure you have edit rights to record {record_uid}")
            dirty = False

            existing_config_uid = get_config_uid(vault, encrypted_session_token, encrypted_transmission_key, record_uid)

            tdag = TunnelDAG(vault, encrypted_session_token, encrypted_transmission_key, config_uid)
            old_dag = TunnelDAG(vault, encrypted_session_token, encrypted_transmission_key, existing_config_uid)

            if config_uid and existing_config_uid != config_uid:
                old_dag.remove_from_dag(record_uid)
                tdag.link_resource_to_config(record_uid)

            if tdag is None or not tdag.linking_dag.has_graph:
                raise base.CommandError(f"No PAM Configuration UID set. "
                                   f"This must be set or supplied for connections to work. This can be done by adding "
                                   f"' --config [ConfigUID] "
                                   f" The ConfigUID can be found by running "
                                   f"'pam config list'")

            if not tdag.check_tunneling_enabled_config(enable_connections=_connections,
                                                       enable_session_recording=_recording,
                                                       enable_typescript_recording=_typescript_recording):
                if not kwargs.get("silent", False): tdag.print_tunneling_config(config_uid, None)
                command = f"'pam connection edit {config_uid}"
                if _connections and not tdag.check_tunneling_enabled_config(enable_connections=_connections):
                    command += f" --connections=on" if _connections else ""
                if _recording and not tdag.check_tunneling_enabled_config(enable_session_recording=_recording):
                    command += f" --connections-recording=on" if _recording else ""
                if _typescript_recording and not tdag.check_tunneling_enabled_config(enable_typescript_recording=_typescript_recording):
                    command += f" --typescript-recording=on" if _typescript_recording else ""

                logger.info(f"The settings are denied by PAM Configuration: {config_uid}. "
                      f"Please enable settings for the configuration by running\n"
                      f"{command}'")
                return

            if not tdag.is_tunneling_config_set_up(record_uid):
                tdag.link_resource_to_config(record_uid)

            if not tdag.is_tunneling_config_set_up(record_uid):
                logger.info(f"No PAM Configuration UID set. This must be set for connections to work. "
                      f"This can be done by running "
                      f"'pam connection edit {record_uid} --config [ConfigUID] --enable-connections' "
                      f"The ConfigUID can be found by running 'pam config list'")
                return
            allowed_settings_name = "allowedSettings"
            if record.record_type == "pamRemoteBrowser":
                allowed_settings_name = "pamRemoteBrowserSettings"

            if _connections is not None and tdag.check_if_resource_allowed(record_uid, "connections") != _connections:
                dirty = True
            if _recording is not None and tdag.check_if_resource_allowed(record_uid, "sessionRecording") != _recording:
                dirty = True
            if _typescript_recording is not None and tdag.check_if_resource_allowed(record_uid, "typescriptRecording") != _typescript_recording:
                dirty = True

            if dirty:
                tdag.set_resource_allowed(resource_uid=record_uid,
                                          allowed_settings_name=allowed_settings_name,
                                          connections=kwargs.get('connections', None),
                                          session_recording=kwargs.get('recording', None),
                                          typescript_recording=kwargs.get('typescriptrecording', None))

            admin_name = kwargs.get('admin')
            adm_rec = vault.vault_data.load_record(admin_name)
            admin_uid = adm_rec.record_uid if adm_rec else None
            if admin_uid and record_type in ("pamDatabase", "pamDirectory", "pamMachine"):
                tdag.link_user_to_resource(admin_uid, record_uid, is_admin=True, belongs_to=True)

            launch_user_name = kwargs.get('launch_user')
            if launch_user_name:
                launch_rec = vault.vault_data.load_record(launch_user_name)
                if not launch_rec:
                    raise base.CommandError(f'Launch user record "{launch_user_name}" not found.')
                if not isinstance(launch_rec, vault_record.TypedRecord) or launch_rec.record_type != 'pamUser':
                    raise base.CommandError(f'Launch user record must be a pamUser record type.')
                launch_uid = launch_rec.record_uid
                if record_type in ("pamDatabase", "pamDirectory", "pamMachine"):
                    tdag.clear_launch_credential_for_resource(record_uid, exclude_user_uid=launch_uid)
                    tdag.link_user_to_resource(launch_uid, record_uid, is_admin=True, belongs_to=True)
                    tdag.upgrade_resource_meta_to_v1(record_uid)

            # Print out PAM Settings
            if not kwargs.get("silent", False): tdag.print_tunneling_config(record_uid, record.get_typed_field('pamSettings'), config_uid)
