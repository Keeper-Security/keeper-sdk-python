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

choices = ['on', 'off', 'default']

logger = api.get_logger()


class PAMRbiEditCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam rbi edit')
        PAMRbiEditCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        # Record and Configuration
        parser.add_argument('--record', '-r', type=str, required=True, dest='record', action='store',
                            help='The record UID or path of the RBI record.')
        parser.add_argument('--configuration', '-c', required=False, dest='config', action='store',
                            help='The PAM Configuration UID or path to use for connections. '
                            'Use command `pam config list` to view available PAM Configurations.')

        # RBI and Recording Settings
        parser.add_argument('--remote-browser-isolation', '-rbi', dest='rbi', choices=choices,
                            help='Set RBI permissions')
        parser.add_argument('--connections-recording', '-cr', dest='recording', choices=choices,
                            help='Set recording connections permissions for the resource')
        parser.add_argument('--key-events', '-k', dest='key_events', choices=choices,
                            help='Toggle Key Events settings')

        # Browser Settings
        parser.add_argument('--allow-url-navigation', '-nav', dest='allow_url_navigation', choices=choices,
                            help='Allow navigation via direct URL manipulation (on/off/default)')
        parser.add_argument('--ignore-server-cert', '-isc', dest='ignore_server_cert', choices=choices,
                            help='Ignore server certificate errors (on/off/default)')

        # URL Filtering
        parser.add_argument('--allowed-urls', '-au', dest='allowed_urls', action='append',
                            help='Allowed URL patterns (can specify multiple times)')
        parser.add_argument('--allowed-resource-urls', '-aru', dest='allowed_resource_urls', action='append',
                            help='Allowed resource URL patterns (can specify multiple times)')

        # Autofill Settings
        parser.add_argument('--autofill-credentials', '-a', type=str, required=False, dest='autofill', action='store',
                            help='The record UID or path of the RBI Autofill Credentials record.')
        parser.add_argument('--autofill-targets', '-at', dest='autofill_targets', action='append',
                            help='Autofill target selectors (can specify multiple times)')

        # Clipboard Settings
        parser.add_argument('--allow-copy', '-cpy', dest='allow_copy', choices=choices,
                            help='Allow copying to clipboard (on/off/default)')
        parser.add_argument('--allow-paste', '-p', dest='allow_paste', choices=choices,
                            help='Allow pasting from clipboard (on/off/default)')

        # Audio Settings
        parser.add_argument('--disable-audio', '-da', dest='disable_audio', choices=choices,
                            help='Disable audio for RBI sessions (on/off/default)')
        parser.add_argument('--audio-channels', '-ac', dest='audio_channels', type=int,
                            help='Number of audio channels (e.g., 1 for mono, 2 for stereo)')
        parser.add_argument('--audio-bit-depth', '-bd', dest='audio_bit_depth', type=int, choices=[8, 16],
                            help='Audio bit depth (8 or 16)')
        parser.add_argument('--audio-sample-rate', '-sr', dest='audio_sample_rate', type=int,
                            help='Audio sample rate in Hz (e.g., 44100, 48000)')

        # Utility
        parser.add_argument('--silent', '-s', required=False, dest='silent', action='store_true',
                            help='Silent mode - don\'t print PAM User, PAM Config etc.')

    def execute(self, context: KeeperParams, **kwargs):
        record_name = kwargs.get('record') or ''
        config_name = kwargs.get('config') or ''
        autofill = kwargs.get('autofill') or ''
        key_events = kwargs.get('key_events')  # on/off/default
        rbi = kwargs.get('rbi')  # on/off/default
        recording = kwargs.get('recording')  # on/off/default
        silent = kwargs.get('silent') or False

        # New RBI settings (Phase 1 - KC-1034)
        allow_url_navigation = kwargs.get('allow_url_navigation')  # on/off/default/None
        ignore_server_cert = kwargs.get('ignore_server_cert')  # on/off/default/None
        allowed_urls = kwargs.get('allowed_urls')  # list or None
        allowed_resource_urls = kwargs.get('allowed_resource_urls')  # list or None
        autofill_targets = kwargs.get('autofill_targets')  # list or None
        allow_copy = kwargs.get('allow_copy')  # on/off/default/None
        allow_paste = kwargs.get('allow_paste')  # on/off/default/None
        disable_audio = kwargs.get('disable_audio')  # on/off/default/None
        audio_channels = kwargs.get('audio_channels')  # int or None
        audio_bit_depth = kwargs.get('audio_bit_depth')  # int or None
        audio_sample_rate = kwargs.get('audio_sample_rate')  # int or None

        if not record_name:
            raise base.CommandError('Record parameter is required.')

        # Check if any setting argument is provided
        has_new_settings = any([
            allow_url_navigation is not None,
            ignore_server_cert is not None,
            allowed_urls is not None,
            allowed_resource_urls is not None,
            autofill_targets is not None,
            allow_copy is not None,
            allow_paste is not None,
            disable_audio is not None,
            audio_channels is not None,
            audio_bit_depth is not None,
            audio_sample_rate is not None
        ])

        if not (autofill or key_events or config_name or rbi or recording or has_new_settings):
            raise base.CommandError('At least one parameter is required. '
                               'If the record is not linked to PAM Config, -c option is required.')

        vault = context.vault

        record = vault.vault_data.load_record(record_name)
        if not record:
            raise base.CommandError(f'Record \"{record_name}\" not found.')
        if not isinstance(record, vault_record.TypedRecord):
            raise base.CommandError(f'Record \"{record_name}\" can not be edited.')

        record_uid = record.record_uid
        record_type = record.record_type
        if record_type != "pamRemoteBrowser":
            raise base.CommandError(f"Record {record_uid} of type {record_type} "
                               "cannot be set up for RBI connections. "
                               f"RBI connection records must be of type: pamRemoteBrowser")

        # record data (JSON) manipulations: autofill, key_events
        dirty = False
        traffic_encryption_key = record.get_typed_field('trafficEncryptionSeed')
        if not traffic_encryption_key or not traffic_encryption_key.value:
            seed = os.urandom(32)
            base64_seed = utils.base64_url_encode(seed)
            record_seed = vault_record.TypedField.create_field('trafficEncryptionSeed', base64_seed, "", required=False)
            if traffic_encryption_key:
                traffic_encryption_key.value = [base64_seed]
            else:
                record.fields.append(record_seed)
            dirty = True

        rbs_fld = record.get_typed_field('pamRemoteBrowserSettings')
        if not rbs_fld:
            rbsettings = {'connection': {'protocol': 'http', 'httpCredentialsUid': ''}}
            pam_rbsettings = vault_record.TypedField.create_field('pamRemoteBrowserSettings', rbsettings, "", required=False)
            record.fields.append(pam_rbsettings)
            dirty = True
        elif not rbs_fld.value:
            rbs_fld.value.append({'connection': {'protocol': 'http'}}) # type: ignore
            dirty = True

        if autofill:
            af_rec = vault.vault_data.load_record(autofill)
            if not af_rec:
                raise base.CommandError(f'Record \"{autofill}\" not found.')
            if not isinstance(af_rec, vault_record.TypedRecord) or af_rec.version != 3 or af_rec.record_type not in ("login", "pamUser"):
                raise base.CommandError(f'Autofill credentials record \"{af_rec.record_uid}\" can not be linked. '
                                ' RBI autofill credential records must be of type "login" or "pamUser"')

            rbs_fld = record.get_typed_field('pamRemoteBrowserSettings')
            val1 = rbs_fld.value[0] if isinstance(rbs_fld, vault_record.TypedField) and rbs_fld.value else {}
            hcuid = val1.get('connection', {}).get('httpCredentialsUid') or '' if isinstance(val1, dict) else ''
            if af_rec.record_uid == hcuid:
                logger.debug(f'httpCredentialsUid={af_rec.record_uid} is already set up on record={record_uid}')
            elif rbs_fld and rbs_fld.value and isinstance(rbs_fld.value[0], dict):
                rbs_fld.value[0]["connection"]["httpCredentialsUid"] = af_rec.record_uid
                dirty = True
                if hcuid:
                    logger.debug(f'Updated existing httpCredentialsUid from: {hcuid} to: {af_rec.record_uid}')
            else:
                raise base.CommandError(f'Failed to set httpCredentialsUid={af_rec.record_uid}')

        if key_events:
            rbs_fld = record.get_typed_field('pamRemoteBrowserSettings')
            val1 = rbs_fld.value[0] if isinstance(rbs_fld, vault_record.TypedField) and rbs_fld.value else {}
            vcon = val1.get('connection', {}) if isinstance(val1, dict) else {}
            rik = vcon.get('recordingIncludeKeys') if isinstance(vcon, dict) else None
            if key_events == 'default':
                if rik is not None:
                    rbs_fld.value[0]["connection"].pop('recordingIncludeKeys', None)
                    dirty = True
                else:
                    logger.debug(f'recordingIncludeKeys is already set to "default" on record={record_uid}')
            elif key_events == 'on':
                if dag_utils.value_to_boolean(key_events) != dag_utils.value_to_boolean(rik):
                    rbs_fld.value[0]["connection"]["recordingIncludeKeys"] = True
                    dirty = True
                else:
                    logger.debug(f'recordingIncludeKeys is already enabled on record={record_uid}')
            elif key_events == 'off':
                if dag_utils.value_to_boolean(key_events) != dag_utils.value_to_boolean(rik):
                    rbs_fld.value[0]["connection"]["recordingIncludeKeys"] = False
                    dirty = True
                else:
                    logger.debug(f'recordingIncludeKeys is already disabled on record={record_uid}')
            else:
                logger.debug(f'Unexpected value for --key-events {key_events} (ignored)')

        # Handle new RBI settings (KC-1034)
        # Helper function to update connection settings with on/off/default pattern
        def update_connection_toggle(field_name, setting_value, invert=False):
            """Update a connection field using on/off/default pattern.

            Args:
                field_name: The field name in the connection dict
                setting_value: 'on', 'off', or 'default'
                invert: If True, 'on' sets False and 'off' sets True (for disableCopy/disablePaste)
            """
            nonlocal dirty
            rbs_fld = record.get_typed_field('pamRemoteBrowserSettings')
            if rbs_fld and rbs_fld.value and isinstance(rbs_fld.value[0], dict):
                connection = rbs_fld.value[0].get('connection', {})
                current_value = connection.get(field_name)

                if setting_value == 'default':
                    if current_value is not None:
                        rbs_fld.value[0]['connection'].pop(field_name, None)
                        dirty = True
                        logger.debug(f'Removed {field_name} (set to default) on record={record_uid}')
                    else:
                        logger.debug(f'{field_name} is already set to default on record={record_uid}')
                elif setting_value == 'on':
                    target_value = False if invert else True
                    if current_value != target_value:
                        rbs_fld.value[0]['connection'][field_name] = target_value
                        dirty = True
                        logger.debug(f'Set {field_name}={target_value} on record={record_uid}')
                    else:
                        logger.debug(f'{field_name} is already set to {target_value} on record={record_uid}')
                elif setting_value == 'off':
                    target_value = True if invert else False
                    if current_value != target_value:
                        rbs_fld.value[0]['connection'][field_name] = target_value
                        dirty = True
                        logger.debug(f'Set {field_name}={target_value} on record={record_uid}')
                    else:
                        logger.debug(f'{field_name} is already set to {target_value} on record={record_uid}')
                else:
                    logger.debug(f'Unexpected value for {field_name}: {setting_value} (ignored)')

        # Helper function for multi-value string fields
        def update_connection_string(field_name, values):
            nonlocal dirty
            rbs_fld = record.get_typed_field('pamRemoteBrowserSettings')
            if rbs_fld and rbs_fld.value and isinstance(rbs_fld.value[0], dict):
                connection = rbs_fld.value[0].get('connection', {})
                new_value = '\n'.join(values) if values else ''
                if connection.get(field_name) != new_value:
                    rbs_fld.value[0]['connection'][field_name] = new_value
                    dirty = True
                    logger.debug(f'Set {field_name}={new_value!r} on record={record_uid}')
                else:
                    logger.debug(f'{field_name} is already set to {new_value!r} on record={record_uid}')

        # Helper function for integer fields
        def update_connection_int(field_name, value):
            nonlocal dirty
            rbs_fld = record.get_typed_field('pamRemoteBrowserSettings')
            if rbs_fld and rbs_fld.value and isinstance(rbs_fld.value[0], dict):
                connection = rbs_fld.value[0].get('connection', {})
                if connection.get(field_name) != value:
                    rbs_fld.value[0]['connection'][field_name] = value
                    dirty = True
                    logger.debug(f'Set {field_name}={value} on record={record_uid}')
                else:
                    logger.debug(f'{field_name} is already set to {value} on record={record_uid}')

        # Browser Settings - allowUrlManipulation (on/off/default)
        if allow_url_navigation:
            update_connection_toggle('allowUrlManipulation', allow_url_navigation)

        # Browser Settings - ignoreInitialSslCert (on/off/default)
        if ignore_server_cert:
            update_connection_toggle('ignoreInitialSslCert', ignore_server_cert)

        # URL Filtering - allowedUrlPatterns (multi-value, joined with newlines)
        if allowed_urls is not None:
            update_connection_string('allowedUrlPatterns', allowed_urls)

        # URL Filtering - allowedResourceUrlPatterns (multi-value, joined with newlines)
        if allowed_resource_urls is not None:
            update_connection_string('allowedResourceUrlPatterns', allowed_resource_urls)

        # Autofill Targets - autofillConfiguration (multi-value, joined with newlines)
        if autofill_targets is not None:
            update_connection_string('autofillConfiguration', autofill_targets)

        # Clipboard Settings - disableCopy (inverted: on -> disableCopy=False, off -> disableCopy=True)
        if allow_copy:
            update_connection_toggle('disableCopy', allow_copy, invert=True)

        # Clipboard Settings - disablePaste (inverted: on -> disablePaste=False, off -> disablePaste=True)
        if allow_paste:
            update_connection_toggle('disablePaste', allow_paste, invert=True)

        # Audio Settings - disableAudio (on -> disableAudio=True, off -> disableAudio=False)
        if disable_audio:
            update_connection_toggle('disableAudio', disable_audio)

        # Audio Settings - audioChannels (integer) - same location as disableAudio (inside connection)
        if audio_channels is not None:
            update_connection_int('audioChannels', audio_channels)

        # Audio Settings - audioBps (integer)
        if audio_bit_depth is not None:
            update_connection_int('audioBps', audio_bit_depth)

        # Audio Settings - audioSampleRate (integer)
        if audio_sample_rate is not None:
            update_connection_int('audioSampleRate', audio_sample_rate)

        if dirty:
            record_management.update_record(vault, record)
            vault.sync_down()

            traffic_encryption_key = record.get_typed_field('trafficEncryptionSeed')
            if not traffic_encryption_key:
                raise base.CommandError(f"Unable to add Seed to record {record_uid}. "
                                f"Please make sure you have edit rights to record {record_uid}")
            vault.sync_data = True

        # DAG manipulation options: config, rbi/connections, recording
        dirty = False
        if not (config_name or rbi or recording):
            return

        # resolve PAM Config
        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(vault)
        existing_config_uid = get_config_uid(vault, encrypted_session_token, encrypted_transmission_key, record_uid)
        existing_config_uid = str(existing_config_uid) if existing_config_uid else ''

        # config parameter is optional and may be (auto)resolved from RBI record
        cfg_rec = None
        if config_name:
            cfg_rec = vault.vault_data.load_record(config_name)
            msg = ("not found" if cfg_rec is None else "not the right type"
                   if not isinstance(cfg_rec, vault_record.TypedRecord) or cfg_rec.version != 6 else "")
            if msg:
                logger.warning(f'PAM Config record "{config_name}" {msg}')
                cfg_rec = None
        if not cfg_rec:
            logger.debug(f"PAM Config - using config from record {record_uid}")
            cfg_rec = vault.vault_data.load_record(existing_config_uid)
            msg = ("not found" if cfg_rec is None else "not the right type"
                   if not isinstance(cfg_rec, vault_record.TypedRecord) or cfg_rec.version != 6 else "")
            if msg:
                logger.warning(f'PAM Config record "{existing_config_uid}" {msg}')
                cfg_rec = None

        config_uid = cfg_rec.record_uid if cfg_rec else None
        if not config_uid:
            raise base.CommandError(f'PAM Config record not found.')

        tdag = TunnelDAG(vault, encrypted_session_token, encrypted_transmission_key, config_uid,
                         transmission_key=transmission_key)
        if tdag is None or not tdag.linking_dag.has_graph:
            raise base.CommandError(f"No valid PAM Configuration UID set. "
                               "This must be set or supplied for connections to work. "
                               "The ConfigUID can be found by running "
                               f"'pam config list'")

        if config_uid:
            if existing_config_uid and existing_config_uid != config_uid:
                old_dag = TunnelDAG(vault, encrypted_session_token, encrypted_transmission_key, existing_config_uid,
                                    transmission_key=transmission_key)
                old_dag.remove_from_dag(record_uid)
                logger.debug(f'Updated existing PAM Config UID from: {existing_config_uid} to: {config_uid}')
            tdag.link_resource_to_config(record_uid)

        # connections=on needed alongside remoteBrowserIsolation=on in PAM Config for RBI to work
        cfg_con_state = tdag.get_resource_setting(config_uid, 'allowedSettings', 'connections')
        cfg_rbi_state = tdag.get_resource_setting(config_uid, 'allowedSettings', 'remoteBrowserIsolation')
        cfg_rec_state = tdag.get_resource_setting(config_uid, 'allowedSettings', 'sessionRecording')
        if cfg_con_state != 'on' or cfg_rbi_state != 'on' or cfg_rec_state != 'on':
            if not silent:
                tdag.print_tunneling_config(config_uid, None)
            command = f"'pam connection edit {config_uid}"
            command += ' --connections=on' if cfg_con_state != 'on' else ''
            command += ' --remote-browser-isolation=on' if cfg_rbi_state != 'on' else ''
            command += ' --connections-recording=on' if cfg_rec_state != 'on' else ''
            logger.info(f"Some settings may be denied by PAM Configuration: {config_uid} "
                  f" [ --connections={cfg_con_state} --remote-browser-isolation={cfg_rbi_state} "
                  f" --connections-recording={cfg_rec_state} ] "
                  f"To enable these settings for the configuration run\n"
                  f"{command}'")

        if not tdag.is_tunneling_config_set_up(record_uid):
            tdag.link_resource_to_config(record_uid)

        if not tdag.is_tunneling_config_set_up(record_uid):
            logger.info(f"No PAM Configuration UID set. This must be set for connections to work. "
                f"This can be done by running "
                f"'pam connection edit {record_uid} --config [ConfigUID] --enable-connections' "
                f"The ConfigUID can be found by running 'pam config list'")
            return

        con_val, rec_val = None, None
        rec_con_state = tdag.get_resource_setting(record_uid, 'allowedSettings', 'connections')
        rec_rec_state = tdag.get_resource_setting(record_uid, 'allowedSettings', 'sessionRecording')
        if (rbi is not None and rbi != rec_con_state) or (recording is not None and recording != rec_rec_state):
            con_val = rbi if rbi != rec_con_state else None
            rec_val = recording if recording != rec_rec_state else None
            dirty = True

        allowed_settings_name = "allowedSettings"

        if dirty:
            tdag.set_resource_allowed(resource_uid=record_uid,
                                    allowed_settings_name=allowed_settings_name,
                                    connections=con_val,
                                    session_recording=rec_val)
                                    
        vault.sync_data = True
