import fnmatch
import json
import os
import argparse
import re

from keepersdk import crypto, utils
from keepersdk.errors import KeeperApiError
from keepersdk.helpers.keeper_dag import dag_utils
from keepersdk.helpers.tunnel.tunnel_graph import TunnelDAG
from keepersdk.helpers.tunnel.tunnel_utils import get_keeper_tokens, get_config_uid
from keepersdk.vault import record_management, vault_record, vault_types, vault_utils
from keepersdk.proto import pam_pb2, router_pb2

from .. import base
from ... import api
from ...params import KeeperParams
from ...helpers import gateway_utils, router_utils, report_utils


logger = api.get_logger()


choices = ['on', 'off', 'default']

# These characters are based on the Vault
PAM_DEFAULT_SPECIAL_CHAR = '''!@#$%^?();',.=+[]<>{}-_/\\*&:"`~|'''


class PAMListRecordRotationCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam rotation list')
        parser.add_argument('--verbose', '-v', required=False, default=False, dest='is_verbose', action='store_true',
                        help='Verbose output')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        self._validate_vault_and_permissions(context)
        vault = context.vault

        is_verbose = kwargs.get('is_verbose')

        rq = pam_pb2.PAMGenericUidsRequest()
        schedules_proto = router_utils.router_get_rotation_schedules(vault, rq)
        if schedules_proto:
            schedules = list(schedules_proto.schedules)
        else:
            schedules = []

        enterprise_all_controllers = list(gateway_utils.get_all_gateways(vault))
        enterprise_controllers_connected_resp = router_utils.router_get_connected_gateways(vault)
        enterprise_controllers_connected_uids_bytes = \
            [x.controllerUid for x in enterprise_controllers_connected_resp.controllers]

        all_pam_config_records = pam_configurations_get_all(params)
        table = []

        headers = []
        headers.append('Record UID')
        headers.append('Record Title')
        headers.append('Record Type')
        headers.append('Schedule')

        headers.append('Gateway')
        if is_verbose:
            headers.append('Gateway UID')

        headers.append('PAM Configuration (Type)')
        if is_verbose:
            headers.append('PAM Configuration UID')

        for s in schedules:
            row = []

            record_uid = utils.base64_url_encode(s.recordUid)
            controller_uid = s.controllerUid
            controller_details = next(
                (ctr for ctr in enterprise_all_controllers if ctr.controllerUid == controller_uid), None)
            configuration_uid = s.configurationUid
            configuration_uid_str = utils.base64_url_encode(configuration_uid)
            pam_configuration = next((pam_config for pam_config in all_pam_config_records if
                                      pam_config.get('record_uid') == configuration_uid_str), None)

            is_controller_online = any(
                (poc for poc in enterprise_controllers_connected_uids_bytes if poc == controller_uid))

            if record_uid in vault.vault_data._records:
                rec = vault.vault_data._records[record_uid]

                record_title = rec.info.title
                record_type = rec.info.record_type
            else:
                record_title = '[record inaccessible]'
                record_type = '[record inaccessible]'

            if record_type != "pamUser":
                # only pamUser records are supported for rotation
                continue

            row.append(f'{record_uid}')
            row.append(record_title)
            row.append(record_type)

            if s.noSchedule is True:
                # Per Sergey A:
                # > noSchedule=true means manual
                # > false is by default in proto and matches the default state for most records (would have a schedule)
                schedule_str = '[Manual Rotation]'
            else:
                if s.scheduleData:
                    schedule_arr = s.scheduleData.replace('RotateActionJob|', '').split('.')
                    if len(schedule_arr) == 4:
                        schedule_str = f'{schedule_arr[0]} on {schedule_arr[1]} at {schedule_arr[2]} UTC with interval count of {schedule_arr[3]}'
                    elif len(schedule_arr) == 3:
                        schedule_str = f'{schedule_arr[0]} at {schedule_arr[1]} UTC with interval count of {schedule_arr[2]}'
                    else:
                        schedule_str = s.scheduleData
                else:
                    schedule_str = '[empty]'

            row.append(f'{schedule_str}')

            # Controller Info

            enterprise_controllers_connected = router_utils.router_get_connected_gateways(vault)
            connected_controller = None
            if enterprise_controllers_connected and controller_details:
                router_controllers = {controller.controllerUid: controller for controller in
                                      list(enterprise_controllers_connected.controllers)}
                connected_controller = router_controllers.get(controller_details.controllerUid)

            if controller_details:
                row.append(f'{controller_details.controllerName}')
            else:
                row.append(f'[Does not exist]')

            if not pam_configuration:
                if not is_verbose:
                    row.append(f"[No config found]")
                else:
                    row.append(
                        f"[No config found. Looks like configuration {configuration_uid_str} was removed but rotation schedule was not modified]")

            else:
                pam_data_decrypted = pam_decrypt_configuration_data(pam_configuration)
                pam_config_name = pam_data_decrypted.get('title')
                pam_config_type = pam_data_decrypted.get('type')
                row.append(f"{pam_config_name} ({pam_config_type})")

            if is_verbose:
                row.append(f'{utils.base64_url_encode(configuration_uid)}')

            table.append(row)

        table.sort(key=lambda x: (x[1]))

        report_utils.dump_report_data(table, headers, fmt='table', filename="", row_number=False, column_width=None)

        print(f"\n----------------------------------------------------------")
        print(f"Example to rotate record to which this user has access to:")
        print(f"\tpam action rotate -r [RECORD UID]")



class PAMCreateRecordRotationCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(prog='pam rotation edit')
    record_group = parser.add_mutually_exclusive_group(required=True)
    record_group.add_argument('--record', '-r', dest='record_name', action='store',
                              help='Record UID, name, or pattern to be rotated manually or via schedule')
    record_group.add_argument('--folder', '-fd', dest='folder_name', action='store',
                              help='Used for bulk rotation setup. The folder UID or name that holds records to be '
                                   'configured')
    parser.add_argument('--force', '-f', dest='force', action='store_true', help='Do not ask for confirmation')
    parser.add_argument('--config', '-c', required=False, dest='config', action='store',
                        help='UID or path of the configuration record.')
    parser.add_argument('--iam-aad-config', '-iac', dest='iam_aad_config_uid', action='store',
                        help='UID of a PAM Configuration. Used for an IAM or Azure AD user in place of --resource.')
    parser.add_argument('--rotation-profile', '-rp', dest='rotation_profile', action='store',
                        choices=['general', 'iam_user', 'scripts_only'],
                        help='Rotation profile type: general (resource-based), iam_user (IAM/Azure user), '
                             'scripts_only (run PAM scripts only)')
    parser.add_argument('--resource', '-rs', dest='resource', action='store',
                        help='UID or path of the resource record.')
    schedule_group = parser.add_mutually_exclusive_group()
    schedule_group.add_argument('--schedulejson', '-sj', required=False, dest='schedule_json_data',
                                action='append', help='JSON of the scheduler. Example: -sj \'{"type": "WEEKLY", '
                                                      '"utcTime": "15:44", "weekday": "SUNDAY", "intervalCount": 1}\'')
    schedule_group.add_argument('--schedulecron', '-sc', required=False, dest='schedule_cron_data',
                                action='append', help='Cron tab string of the scheduler. Example: to run job daily at '
                                                      '5:56PM UTC enter following cron -sc "56 17 * * *"')
    schedule_group.add_argument('--on-demand', '-od', required=False, dest='on_demand',
                                action='store_true', help='Schedule On Demand')
    schedule_group.add_argument('--schedule-config', '-sf', required=False, dest='schedule_config',
                                action='store_true', help='Schedule from Configuration')
    parser.add_argument('--schedule-only', '-so', dest='schedule_only', action='store_true',
                        help='Only update the rotation schedule without changing other settings')
    parser.add_argument('--complexity', '-x', required=False, dest='pwd_complexity', action='store',
                        help='Password complexity: length, upper, lower, digits, symbols. Ex. 32,5,5,5,5[,SPECIAL CHARS]')
    parser.add_argument('--admin-user', '-a', required=False, dest='admin', action='store',
                        help='UID or path for the PAMUser record to configure the admin credential on the PAM Resource as the Admin when rotating')
    state_group = parser.add_mutually_exclusive_group()
    state_group.add_argument('--enable', '-e', dest='enable', action='store_true', help='Enable rotation')
    state_group.add_argument('--disable', '-d', dest='disable', action='store_true', help='Disable rotation')

    def get_parser(self):
        return PAMCreateRecordRotationCommand.parser
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam rotation edit')
        parser.add_argument('--record', '-r', dest='record_name', action='store',
                              help='Record UID, name, or pattern to be rotated manually or via schedule')
        parser.add_argument('--folder', '-fd', dest='folder_name', action='store',
                              help='Used for bulk rotation setup. The folder UID or name that holds records to be '
                                   'configured')
        parser.add_argument('--force', '-f', dest='force', action='store_true', help='Do not ask for confirmation')
        parser.add_argument('--config', '-c', required=False, dest='config', action='store',
                        help='UID or path of the configuration record.')
        parser.add_argument('--iam-aad-config', '-iac', dest='iam_aad_config_uid', action='store',
                        help='UID of a PAM Configuration. Used for an IAM or Azure AD user in place of --resource.')
        parser.add_argument('--rotation-profile', '-rp', dest='rotation_profile', action='store',
                        choices=['general', 'iam_user', 'scripts_only'],
                        help='Rotation profile type: general (resource-based), iam_user (IAM/Azure user), '
                             'scripts_only (run PAM scripts only)')

        parser.add_argument('--resource', '-rs', dest='resource', action='store',
                        help='UID or path of the resource record.')
        parser.add_argument('--schedulejson', '-sj', required=False, dest='schedule_json_data',
                                action='append', help='JSON of the scheduler. Example: -sj \'{"type": "WEEKLY", '
                                                      '"utcTime": "15:44", "weekday": "SUNDAY", "intervalCount": 1}\'')
        parser.add_argument('--schedulecron', '-sc', required=False, dest='schedule_cron_data',
                                action='append', help='Cron tab string of the scheduler. Example: to run job daily at '
                                                      '5:56PM UTC enter following cron -sc "56 17 * * *"')
        parser.add_argument('--on-demand', '-od', required=False, dest='on_demand',
                                action='store_true', help='Schedule On Demand')
        parser.add_argument('--schedule-config', '-sf', required=False, dest='schedule_config',
                                action='store_true', help='Schedule from Configuration')
        parser.add_argument('--schedule-only', '-so', dest='schedule_only', action='store_true',
                        help='Only update the rotation schedule without changing other settings')
        parser.add_argument('--complexity', '-x', required=False, dest='pwd_complexity', action='store',
                        help='Password complexity: length, upper, lower, digits, symbols. Ex. 32,5,5,5,5[,SPECIAL CHARS]')
        parser.add_argument('--admin-user', '-a', required=False, dest='admin', action='store',
                        help='UID or path for the PAMUser record to configure the admin credential on the PAM Resource as the Admin when rotating')
        state_group = parser.add_mutually_exclusive_group()
        state_group.add_argument('--enable', '-e', dest='enable', action='store_true', help='Enable rotation')
        state_group.add_argument('--disable', '-d', dest='disable', action='store_true', help='Disable rotation')
        super().__init__(parser)
        
    def execute(self, context: KeeperParams, **kwargs):
        """Configure rotation settings for one or multiple PAM records.

        The command accepts either ``--record`` or ``--folder`` to target
        records. It validates schedule options, password complexity and
        resource linkage and then submits rotation requests to the Keeper
        PAM router service.
        """
        self._validate_vault_and_permissions(context)
        vault = context.vault

        def config_resource(_dag, target_record, target_config_uid, silent=None):
            if not _dag.linking_dag.has_graph:
                # Add DAG for resource
                if target_config_uid:
                    _dag = TunnelDAG(vault, encrypted_session_token, encrypted_transmission_key, target_config_uid,
                                     transmission_key=transmission_key)
                    _dag.edit_tunneling_config(rotation=True)
                else:
                    raise base.CommandError(f'Resource "{target_record.record_uid}" is not associated '
                                           f'with any configuration. '
                                           f'pam rotation edit -rs {target_record.record_uid} '
                                           f'--config CONFIG')
            resource_dag = None
            if not _dag.resource_belongs_to_config(target_record.record_uid):
                # Change DAG to this new configuration.
                resource_dag = TunnelDAG(vault, encrypted_session_token, encrypted_transmission_key,
                                         target_record.record_uid, transmission_key=transmission_key)
                _dag.link_resource_to_config(target_record.record_uid)

            admin = kwargs.get('admin')
            adm_rec = vault.vault_data.load_record(admin)

            if adm_rec and isinstance(adm_rec, vault.TypedRecord):
                admin = adm_rec.record_uid

            if admin and target_record.record_type != 'pamRemoteBrowser':
                _dag.link_user_to_resource(admin, target_record.record_uid, is_admin=True)

            _rotation_enabled = True if kwargs.get('enable') else False if kwargs.get('disable') else None

            if _rotation_enabled is not None:
                _dag.set_resource_allowed(target_record.record_uid, rotation=_rotation_enabled,
                                          allowed_settings_name="rotation")

            if resource_dag is not None and resource_dag.linking_dag.has_graph:
                # TODO: Make sure this doesn't remove everything from the new dag too
                resource_dag.remove_from_dag(target_record.record_uid)

            if not silent:
                _dag.print_tunneling_config(target_record.record_uid, config_uid=target_config_uid)

        def config_iam_aad_user(_dag, target_record, target_iam_aad_config_uid):
            current_record_rotation = params.record_rotation_cache.get(target_record.record_uid)
            schedule_only = kwargs.get('schedule_only')

            # Handle schedule-only operations first to avoid unnecessary resource validation
            if schedule_only:
                if kwargs.get('folder_name') and (
                        not current_record_rotation or current_record_rotation.get('disabled')):
                    skipped_records.append([target_record.record_uid, target_record.title,
                                            'Rotation not enabled', 'Skipped'])
                    return
                if not current_record_rotation:
                    skipped_records.append([target_record.record_uid, target_record.title,
                                            'No rotation info', 'Skipped'])
                    return

                record_config_uid = current_record_rotation.get('configuration_uid')
                record_pam_config = pam_configurations.get(record_config_uid, pam_config)
                record_schedule_data = schedule_data
                if record_schedule_data is None:
                    try:
                        cs = current_record_rotation.get('schedule')
                        record_schedule_data = json.loads(cs) if cs else []
                    except:
                        record_schedule_data = []
                pwd_complexity_rule_list_encrypted = utils.base64_url_decode(
                    current_record_rotation.get('pwd_complexity', ''))
                record_resource_uid = current_record_rotation.get('resource_uid')
                # IAM users have resource_uid == config_uid; should be empty to preserve rotation profile
                if record_resource_uid == record_config_uid:
                    record_resource_uid = None
                disabled = current_record_rotation.get('disabled', False)

                schedule = 'On-Demand'
                if isinstance(record_schedule_data, list) and len(record_schedule_data) > 0:
                    if isinstance(record_schedule_data[0], dict):
                        schedule = record_schedule_data[0].get('type')
                complexity = ''
                if pwd_complexity_rule_list_encrypted:
                    try:
                        decrypted_complexity = crypto.decrypt_aes_v2(pwd_complexity_rule_list_encrypted,
                                                                     target_record.record_key)
                        c = json.loads(decrypted_complexity.decode())
                        complexity = f"{c.get('length', 0)},{c.get('caps', 0)},{c.get('lowercase', 0)},{c.get('digits', 0)},{c.get('special', 0)},{c.get('specialChars', PAM_DEFAULT_SPECIAL_CHAR)}"
                    except Exception:
                        pass

                valid_records.append([
                    target_record.record_uid, target_record.title, not disabled, record_config_uid,
                    record_resource_uid, schedule, complexity])

                # Check if we have NOOP rotation for schedule-only operations
                noop_rotation = str(kwargs.get('noop', False) or False).upper() == 'TRUE'
                if target_record and not noop_rotation:  # check from record data
                    noop_field = target_record.get_typed_field('text', 'NOOP')
                    if (noop_field and noop_field.value and
                            isinstance(noop_field.value, list) and
                            str(noop_field.value[0]).upper() == 'TRUE'):
                        noop_rotation = True

                rq = router_pb2.RouterRecordRotationRequest()
                rq.revision = current_record_rotation.get('revision', 0)
                rq.recordUid = utils.base64_url_decode(target_record.record_uid)
                rq.configurationUid = utils.base64_url_decode(record_config_uid)
                rq.resourceUid = utils.base64_url_decode(record_resource_uid) if record_resource_uid else b''
                rq.schedule = json.dumps(record_schedule_data) if record_schedule_data else ''
                rq.pwdComplexity = pwd_complexity_rule_list_encrypted
                rq.disabled = disabled
                if noop_rotation:
                    rq.noop = True
                    rq.resourceUid = b''
                r_requests.append(rq)
                return

            if _dag and not _dag.linking_dag.has_graph:
                _dag = TunnelDAG(vault, encrypted_session_token, encrypted_transmission_key, target_iam_aad_config_uid,
                                 transmission_key=transmission_key)
                if not _dag or not _dag.linking_dag.has_graph:
                    _dag.edit_tunneling_config(rotation=True)
            old_dag = TunnelDAG(vault, encrypted_session_token, encrypted_transmission_key, target_record.record_uid,
                                transmission_key=transmission_key)
            if old_dag.linking_dag.has_graph and old_dag.record.record_uid != target_iam_aad_config_uid:
                old_dag.remove_from_dag(target_record.record_uid)

            # with IAM users the user is at the level the resource is usually at,
            if not _dag.user_belongs_to_config(target_record.record_uid):
                old_resource_uid = _dag.get_resource_uid(target_record.record_uid)
                if old_resource_uid is not None:
                    logger.info(
                        f'User "{target_record.record_uid}" is associated with another resource: '
                        f'{old_resource_uid}. '
                        f'Now moving it to {target_iam_aad_config_uid} and it will no longer be rotated on {old_resource_uid}.')
                    if old_resource_uid == _dag.record.record_uid:
                        _dag.unlink_user_from_resource(target_record.record_uid, old_resource_uid)
                    _dag.link_user_to_resource(target_record.record_uid, old_resource_uid, belongs_to=False)
                _dag.link_user_to_config(target_record.record_uid)

            # 1. PAM Configuration UID
            record_config_uid = _dag.record.record_uid
            record_pam_config = pam_config
            if not record_config_uid:
                if current_record_rotation:
                    record_config_uid = current_record_rotation.get('configuration_uid')
                    pc = vault.vault_data.load_record(record_config_uid)
                    if pc is None:
                        skipped_records.append(
                            [target_record.record_uid, target_record.title, 'PAM Configuration was deleted',
                             'Specify a configuration UID parameter [--config]'])
                        return
                    if not isinstance(pc, vault.TypedRecord) or pc.version != 6:
                        skipped_records.append(
                            [target_record.record_uid, target_record.title, 'PAM Configuration is invalid',
                             'Specify a configuration UID parameter [--config]'])
                        return
                    record_pam_config = pc
                else:
                    skipped_records.append(
                        [target_record.record_uid, target_record.title, 'No current PAM Configuration',
                         'Specify a configuration UID parameter [--config]'])
                    return

            # 2. Schedule
            record_schedule_data = schedule_data
            if record_schedule_data is None:
                if current_record_rotation and not schedule_config:
                    try:
                        current_schedule = current_record_rotation.get('schedule')
                        if current_schedule:
                            record_schedule_data = json.loads(current_schedule)
                    except:
                        pass
                else:
                    schedule_field = record_pam_config.get_typed_field('schedule', 'defaultRotationSchedule')
                    if schedule_field and isinstance(schedule_field.value, list) and len(schedule_field.value) > 0:
                        if isinstance(schedule_field.value[0], dict):
                            record_schedule_data = [schedule_field.value[0]]

            # 3. Password complexity
            if pwd_complexity_rule_list is None:
                if current_record_rotation:
                    pwd_complexity_rule_list_encrypted = utils.base64_url_decode(
                        current_record_rotation['pwd_complexity'])
                else:
                    pwd_complexity_rule_list_encrypted = b''
            else:
                if len(pwd_complexity_rule_list) > 0:
                    pwd_complexity_rule_list_encrypted = router_utils.encrypt_pwd_complexity(pwd_complexity_rule_list,
                                                                                              target_record.record_key)
                else:
                    pwd_complexity_rule_list_encrypted = b''

            # 4. Resource record
            record_resource_uid = target_iam_aad_config_uid
            if record_resource_uid is None:
                if current_record_rotation:
                    record_resource_uid = current_record_rotation.get('resource_uid')
            if record_resource_uid is None:
                resource_field = record_pam_config.get_typed_field('pamResources')
                if resource_field and isinstance(resource_field.value, list) and len(resource_field.value) > 0:
                    resources = resource_field.value[0]
                    if isinstance(resources, dict):
                        resource_uids = resources.get('resourceRef')
                        if isinstance(resource_uids, list) and len(resource_uids) > 0:
                            if len(resource_uids) == 1:
                                record_resource_uid = resource_uids[0]
                            else:
                                skipped_records.append([target_record.record_uid, target_record.title,
                                                        f'PAM Configuration: {len(resource_uids)} admin resources',
                                                        'Specify both configuration UID and resource UID  [--config, --resource]'])
                                return

            disabled = False
            # 5. Enable rotation
            if kwargs.get('enable'):
                _dag.set_resource_allowed(target_iam_aad_config_uid, rotation=True,
                                          is_config=bool(target_iam_aad_config_uid))
            elif kwargs.get('disable'):
                _dag.set_resource_allowed(target_iam_aad_config_uid, rotation=False,
                                          is_config=bool(target_iam_aad_config_uid))
                disabled = True

            schedule = 'On-Demand'
            if isinstance(record_schedule_data, list) and len(record_schedule_data) > 0:
                if isinstance(record_schedule_data[0], dict):
                    schedule = record_schedule_data[0].get('type')
            complexity = ''
            if pwd_complexity_rule_list_encrypted:
                try:
                    decrypted_complexity = crypto.decrypt_aes_v2(pwd_complexity_rule_list_encrypted,
                                                                 target_record.record_key)
                    c = json.loads(decrypted_complexity.decode())
                    complexity = f"{c.get('length', 0)}," \
                                 f"{c.get('caps', 0)}," \
                                 f"{c.get('lowercase', 0)}," \
                                 f"{c.get('digits', 0)}," \
                                 f"{c.get('special', 0)}," \
                                 f"{c.get('specialChars', PAM_DEFAULT_SPECIAL_CHAR)}"
                except:
                    pass
            valid_records.append(
                [target_record.record_uid, target_record.title, not disabled, record_config_uid, record_resource_uid,
                 schedule,
                 complexity])

            # 6. Construct Request object for IAM: empty resourceUid and noop=False
            rq = router_pb2.RouterRecordRotationRequest()
            if current_record_rotation:
                rq.revision = current_record_rotation.get('revision', 0)
            rq.recordUid = utils.base64_url_decode(target_record.record_uid)
            rq.configurationUid = utils.base64_url_decode(record_config_uid)
            rq.resourceUid = b''  # non-empty resourceUid sets is as General rotation
            rq.noop = False  # True sets it as NOOP
            rq.schedule = json.dumps(record_schedule_data) if record_schedule_data else ''
            rq.pwdComplexity = pwd_complexity_rule_list_encrypted
            rq.disabled = disabled
            r_requests.append(rq)

        def config_user(_dag, target_record, target_resource_uid, target_config_uid=None, silent=None):
            current_record_rotation = params.record_rotation_cache.get(target_record.record_uid)
            schedule_only = kwargs.get('schedule_only')

            # Handle schedule-only operations first to avoid unnecessary resource validation
            if schedule_only:
                if kwargs.get('folder_name') and (
                        not current_record_rotation or current_record_rotation.get('disabled')):
                    skipped_records.append([target_record.record_uid, target_record.title,
                                            'Rotation not enabled', 'Skipped'])
                    return
                if not current_record_rotation:
                    skipped_records.append([target_record.record_uid, target_record.title,
                                            'No rotation info', 'Skipped'])
                    return

                record_config_uid = current_record_rotation.get('configuration_uid')
                record_pam_config = pam_configurations.get(record_config_uid, pam_config)
                record_schedule_data = schedule_data
                if record_schedule_data is None:
                    try:
                        cs = current_record_rotation.get('schedule')
                        record_schedule_data = json.loads(cs) if cs else []
                    except:
                        record_schedule_data = []
                pwd_complexity_rule_list_encrypted = utils.base64_url_decode(
                    current_record_rotation.get('pwd_complexity', ''))
                record_resource_uid = current_record_rotation.get('resource_uid')
                # IAM users have resource_uid == config_uid; should be empty to preserve rotation profile
                if record_resource_uid == record_config_uid:
                    record_resource_uid = None
                disabled = current_record_rotation.get('disabled', False)

                schedule = 'On-Demand'
                if isinstance(record_schedule_data, list) and len(record_schedule_data) > 0:
                    if isinstance(record_schedule_data[0], dict):
                        schedule = record_schedule_data[0].get('type')
                complexity = ''
                if pwd_complexity_rule_list_encrypted:
                    try:
                        decrypted_complexity = crypto.decrypt_aes_v2(pwd_complexity_rule_list_encrypted,
                                                                     target_record.record_key)
                        c = json.loads(decrypted_complexity.decode())
                        complexity = f"{c.get('length', 0)},{c.get('caps', 0)},{c.get('lowercase', 0)},{c.get('digits', 0)},{c.get('special', 0)},{c.get('specialChars', PAM_DEFAULT_SPECIAL_CHAR)}"
                    except Exception:
                        pass

                valid_records.append([
                    target_record.record_uid, target_record.title, not disabled, record_config_uid,
                    record_resource_uid, schedule, complexity])

                # Check if we have NOOP rotation for schedule-only operations
                noop_rotation = str(kwargs.get('noop', False) or False).upper() == 'TRUE'
                if target_record and not noop_rotation:  # check from record data
                    noop_field = target_record.get_typed_field('text', 'NOOP')
                    if (noop_field and noop_field.value and
                            isinstance(noop_field.value, list) and
                            str(noop_field.value[0]).upper() == 'TRUE'):
                        noop_rotation = True

                rq = router_pb2.RouterRecordRotationRequest()
                rq.revision = current_record_rotation.get('revision', 0)
                rq.recordUid = utils.base64_url_decode(target_record.record_uid)
                rq.configurationUid = utils.base64_url_decode(record_config_uid)
                rq.resourceUid = utils.base64_url_decode(record_resource_uid) if record_resource_uid else b''
                rq.schedule = json.dumps(record_schedule_data) if record_schedule_data else ''
                rq.pwdComplexity = pwd_complexity_rule_list_encrypted
                rq.disabled = disabled
                if noop_rotation:
                    rq.noop = True
                    rq.resourceUid = b''
                r_requests.append(rq)
                return

            # NOOP rotation (for non-schedule-only operations)
            noop_rotation = str(kwargs.get('noop', False) or False).upper() == 'TRUE'
            if target_record and not noop_rotation:  # check from record data
                noop_field = target_record.get_typed_field('text', 'NOOP')
                if (noop_field and noop_field.value and
                        isinstance(noop_field.value, list) and
                        str(noop_field.value[0]).upper() == 'TRUE'):
                    noop_rotation = True
                    # script_field = target_record.get_typed_field('script', 'rotationScripts')
                    # if script_field and isinstance(script_field.value, list) and len(script_field.value) > 0:
                    #     record_refs = [x.get('recordRef')[0] for x in script_field.value if isinstance(x, dict) and x.get('recordRef', [])]
                    #     if record_refs:
                    #         logging.warning(f'Record "{target_record.record_uid}" is set for NOOP rotation '
                    #                         f'but rotation scripts reference some recordRef: {record_refs}')

            if _dag and _dag.linking_dag:
                admin_record_uids = _dag.get_all_admins()
                if folder_name and target_record.record_uid in admin_record_uids:
                    # If iterating through a folder, skip admin records
                    skipped_records.append([target_record.record_uid, target_record.title, 'Admin Credential',
                                            'This record is used as Admin credentials on a PAM Configuration. Skipped'])
                    return

            if isinstance(target_resource_uid, str) and len(target_resource_uid) > 0:
                _dag = TunnelDAG(vault, encrypted_session_token, encrypted_transmission_key, target_resource_uid,
                                 transmission_key=transmission_key)
                if not _dag or not _dag.linking_dag.has_graph:
                    if target_config_uid and target_resource_uid:
                        config_resource(_dag, target_record, target_config_uid, silent=silent)
                    if not _dag or not _dag.linking_dag.has_graph:
                        raise base.CommandError(f'Resource "{target_resource_uid}" is not associated '
                                               f'with any configuration. '
                                               f'pam rotation edit -rs {target_resource_uid} '
                                               f'--config CONFIG')

                if not _dag.check_if_resource_has_admin(target_resource_uid):
                    raise base.CommandError(f'PAM Resource "{target_resource_uid}'" does not have "
                                           "admin credentials. Please link an admin credential to this resource. "
                                           f"pam rotation edit -rs {target_resource_uid} "
                                           f"--admin-user ADMIN")
            current_record_rotation = params.record_rotation_cache.get(target_record.record_uid)

            if not _dag or not _dag.linking_dag.has_graph:
                _dag = TunnelDAG(vault, encrypted_session_token, encrypted_transmission_key, target_resource_uid,
                                 transmission_key=transmission_key)
                if not _dag.linking_dag.has_graph:
                    raise base.CommandError(f'Resource "{target_resource_uid}" is not associated '
                                           f'with any configuration. '
                                           f'pam rotation edit -rs {target_resource_uid} '
                                           f'--config CONFIG')
            # Noop and resource cannot be both assigned
            if noop_rotation:
                target_resource_uid = target_record.record_uid
                record_resource_uid = None
            else:
                if not target_resource_uid:
                    # Get the resource configuration from DAG
                    resource_uids = _dag.get_all_owners(target_record.record_uid)
                    if len(resource_uids) > 1:
                        # When processing folders, skip records with multiple resources
                        if folder_name:
                            skipped_records.append([
                                target_record.record_uid,
                                target_record.title,
                                'Multiple Resources',
                                f'Record is associated with {len(resource_uids)} resources. Use --record with --resource to configure individually.'
                            ])
                            return
                        else:
                            raise base.CommandError(f'Record "{target_record.record_uid}" is '
                                                   f'associated with multiple resources so you must supply '
                                                   f'"--resource/-rs RESOURCE".')
                    elif len(resource_uids) == 0:
                        raise base.CommandError(
                                           f'Record "{target_record.record_uid}" is not associated with'
                                           f' any resource. Please use "pam rotation user '
                                           f'{target_record.record_uid} --resource RESOURCE" to associate '
                                           f'it.')
                    target_resource_uid = resource_uids[0]

                if not _dag.resource_belongs_to_config(target_resource_uid):
                    # some rotations (iam_user/noop) link straight to pamConfiguration
                    if target_resource_uid != _dag.record.record_uid:
                        raise base.CommandError(
                                           f'Resource "{target_resource_uid}" is not associated with the '
                                           f'configuration of the user "{target_record.record_uid}". To associated the resources '
                                           f'to this config run "pam rotation resource {target_resource_uid} '
                                           f'--config {_dag.record.record_uid}"')
                if not _dag.user_belongs_to_resource(target_record.record_uid, target_resource_uid):
                    old_resource_uid = _dag.get_resource_uid(target_record.record_uid)
                    if old_resource_uid is not None and old_resource_uid != target_resource_uid:
                        logger.info(
                            f'User "{target_record.record_uid}" is associated with another resource: '
                            f'{old_resource_uid}. '
                            f'Now moving it to {target_resource_uid} and it will no longer be rotated on {old_resource_uid}.'
                            )
                        _dag.link_user_to_resource(target_record.record_uid, old_resource_uid, belongs_to=False)
                    _dag.link_user_to_resource(target_record.record_uid, target_resource_uid, belongs_to=True)

            # 1. PAM Configuration UID
            record_config_uid = _dag.record.record_uid
            record_pam_config = pam_config
            if not record_config_uid:
                if current_record_rotation:
                    record_config_uid = current_record_rotation.get('configuration_uid')
                    pc = vault.vault_data.load_record(record_config_uid)
                    if pc is None:
                        skipped_records.append(
                            [target_record.record_uid, target_record.title, 'PAM Configuration was deleted',
                             'Specify a configuration UID parameter [--config]'])
                        return
                    if not isinstance(pc, vault_record.TypedRecord) or pc.version != 6:
                        skipped_records.append(
                            [target_record.record_uid, target_record.title, 'PAM Configuration is invalid',
                             'Specify a configuration UID parameter [--config]'])
                        return
                    record_pam_config = pc
                else:
                    skipped_records.append(
                        [target_record.record_uid, target_record.title, 'No current PAM Configuration',
                         'Specify a configuration UID parameter [--config]'])
                    return

            # 2. Schedule
            record_schedule_data = schedule_data
            if record_schedule_data is None:
                if current_record_rotation:
                    try:
                        current_schedule = current_record_rotation.get('schedule')
                        if current_schedule:
                            record_schedule_data = json.loads(current_schedule)
                    except:
                        pass
                elif record_pam_config:
                    schedule_field = record_pam_config.get_typed_field('schedule', 'defaultRotationSchedule')
                    if schedule_field and isinstance(schedule_field.value, list) and len(schedule_field.value) > 0:
                        if isinstance(schedule_field.value[0], dict):
                            record_schedule_data = [schedule_field.value[0]]
                else:
                    record_schedule_data = []

            # 3. Password complexity
            if pwd_complexity_rule_list is None:
                if current_record_rotation:
                    pwd_complexity_rule_list_encrypted = utils.base64_url_decode(
                        current_record_rotation['pwd_complexity'])
                else:
                    pwd_complexity_rule_list_encrypted = b''
            else:
                if len(pwd_complexity_rule_list) > 0:
                    pwd_complexity_rule_list_encrypted = router_utils.encrypt_pwd_complexity(pwd_complexity_rule_list,
                                                                                              target_record.record_key)
                else:
                    pwd_complexity_rule_list_encrypted = b''

            # 4. Resource record
            # Noop and resource cannot be both assigned
            if not noop_rotation:
                record_resource_uid = target_resource_uid
                # IAM users are linked directly to config (target_resource_uid == config_uid)
                # In this case, resourceUid should be empty to preserve IAM rotation profile
                if record_resource_uid == _dag.record.record_uid:
                    record_resource_uid = None
                if record_resource_uid is None:
                    if current_record_rotation:
                        record_resource_uid = current_record_rotation.get('resource_uid')
                        # Also check if the cached resource_uid is actually the config UID
                        if record_resource_uid == record_config_uid:
                            record_resource_uid = None
                if record_resource_uid is None:
                    resource_field = record_pam_config.get_typed_field('pamResources')
                    if resource_field and isinstance(resource_field.value, list) and len(resource_field.value) > 0:
                        resources = resource_field.value[0]
                        if isinstance(resources, dict):
                            resource_uids = resources.get('resourceRef')
                            if isinstance(resource_uids, list) and len(resource_uids) > 0:
                                if len(resource_uids) == 1:
                                    record_resource_uid = resource_uids[0]
                                else:
                                    skipped_records.append([target_record.record_uid, target_record.title,
                                                            f'PAM Configuration: {len(resource_uids)} admin resources',
                                                            'Specify both configuration UID and resource UID  [--config, --resource]'])
                                    return

            disabled = False
            # 5. Enable rotation
            if kwargs.get('enable'):
                _dag.set_resource_allowed(target_resource_uid, rotation=True)
            elif kwargs.get('disable'):
                _dag.set_resource_allowed(target_resource_uid, rotation=False)
                disabled = True

            schedule = 'On-Demand'
            if isinstance(record_schedule_data, list) and len(record_schedule_data) > 0:
                if isinstance(record_schedule_data[0], dict):
                    schedule = record_schedule_data[0].get('type')
            complexity = ''
            if pwd_complexity_rule_list_encrypted:
                try:
                    decrypted_complexity = crypto.decrypt_aes_v2(pwd_complexity_rule_list_encrypted,
                                                                 target_record.record_key)
                    c = json.loads(decrypted_complexity.decode())
                    complexity = f"{c.get('length', 0)}," \
                                 f"{c.get('caps', 0)}," \
                                 f"{c.get('lowercase', 0)}," \
                                 f"{c.get('digits', 0)}," \
                                 f"{c.get('special', 0)}," \
                                 f"{c.get('specialChars', PAM_DEFAULT_SPECIAL_CHAR)}"
                except:
                    pass
            valid_records.append(
                [target_record.record_uid, target_record.title, not disabled, record_config_uid, record_resource_uid,
                 schedule,
                 complexity])

            # 6. Construct Request object
            rq = router_pb2.RouterRecordRotationRequest()
            if current_record_rotation:
                rq.revision = current_record_rotation.get('revision', 0)
            rq.recordUid = utils.base64_url_decode(target_record.record_uid)
            rq.configurationUid = utils.base64_url_decode(record_config_uid)
            rq.resourceUid = utils.base64_url_decode(record_resource_uid) if record_resource_uid else b''
            rq.schedule = json.dumps(record_schedule_data) if record_schedule_data else ''
            rq.pwdComplexity = pwd_complexity_rule_list_encrypted
            rq.disabled = disabled
            if noop_rotation:
                rq.noop = True
                rq.resourceUid = b''  # Noop and resource cannot be both assigned
            r_requests.append(rq)

        # Main execute() logic starts here
        record_uids = set()

        folder_uids = set()
        record_pattern = ''
        record_name = kwargs.get('record_name')

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(vault)
        if record_name:
            if record_name in vault.vault_data._records:
                record_uids.add(record_name)
            else:
                rs = folder_utils.try_resolve_path(vault, record_name, find_all_matches=True)
                if rs is not None:
                    folder, record_title = rs
                    if record_title:
                        record_pattern = record_title
                        if isinstance(folder, vault_types.Folder):
                            folder_uids.add(folder.folder_uid)
                        elif isinstance(folder, list):
                            for f in folder:
                                if isinstance(f, vault_types.Folder):
                                    folder_uids.add(f.folder_uid)
                    else:
                        logger.warning('Record \"%s\" not found. Skipping.', record_name)

        folder_name = kwargs.get('folder_name')
        if folder_name:
            if folder_name in vault.vault_data._folders:
                folder_uids.add(folder_name)
            else:
                rs = folder_utils.try_resolve_path(vault, folder_name, find_all_matches=True)
                if rs is not None:
                    folder, record_title = rs
                    if not record_title:

                        def add_folders(sub_folder):  # type: (BaseFolderNode) -> None
                            folder_uids.add(sub_folder.uid or '')

                        if isinstance(folder, vault_types.Folder):
                            folder = [folder]
                        if isinstance(folder, list):
                            for f in folder:
                                vault_utils.traverse_folder_tree(vault, f.folder_uid, add_folders)
                    else:
                        logger.warning('Folder \"%s\" not found. Skipping.', folder_name)

        if record_name and folder_name:
            raise base.CommandError('Cannot use both --record and --folder at the same time.')

        if folder_uids:
            regex = re.compile(fnmatch.translate(record_pattern), re.IGNORECASE).match if record_pattern else None
            for folder_uid in folder_uids:
                folder_records = vault.vault_data.get_folder(folder_uid).records
                if not folder_records:
                    continue
                if record_pattern and record_pattern in folder_records:
                    record_uids.add(record_pattern)
                else:
                    for record_uid in folder_records:
                        if record_uid not in record_uids:
                            r = vault.vault_data.load_record(record_uid)
                            if r:
                                if regex and not regex(r.title):
                                    continue
                                record_uids.add(record_uid)

        pam_records = []  # type: List[vault.TypedRecord]
        valid_record_types = ['pamDatabase', 'pamDirectory', 'pamMachine', 'pamUser', 'pamRemoteBrowser']
        for record_uid in record_uids:
            record = vault.vault_data.load_record(record_uid)
            if record and isinstance(record, vault_record.TypedRecord) and record.record_type in valid_record_types:
                pam_records.append(record)

        if len(pam_records) == 0:
            rts = ', '.join(valid_record_types)
            raise base.CommandError(f'No PAM record is found. Valid PAM record types: {rts}')
        else:
            if not kwargs.get('silent'):
                logger.info('Selected %d PAM record(s) for rotation', len(pam_records))

        pam_configurations = {x.record_uid: x for x in vault.vault_data.find_records(record_version=6) if
                              isinstance(x, vault_record.TypedRecord)}

        config_uid = kwargs.get('config')
        cfg_rec = vault.vault_data.load_record(kwargs.get('config', None))
        if cfg_rec and cfg_rec.version == 6 and cfg_rec.record_uid in pam_configurations:
            config_uid = cfg_rec.record_uid

        pam_config = None
        if config_uid:
            if config_uid in pam_configurations:
                pam_config = pam_configurations[config_uid]
            else:
                raise base.CommandError(f'Record uid {config_uid} is not a PAM Configuration record.')

        schedule_config = kwargs.get('schedule_config') is True
        schedule_data = parse_schedule_data(kwargs)

        pwd_complexity = kwargs.get("pwd_complexity")
        pwd_complexity_rule_list = None 
        if pwd_complexity is not None:
            if pwd_complexity:
                pwd_complexity_list = [s.strip() for s in pwd_complexity.split(',', maxsplit=5)]
                if len(pwd_complexity_list) < 5 or not all(n.isnumeric() for n in pwd_complexity_list[:5]):
                    raise base.CommandError('Invalid rules to generate password. ''Format is "length, '
                                           'upper, lower, digits, symbols". Ex: 32,5,5,5,5[,SPECIAL CHARS]')

                special_chars = PAM_DEFAULT_SPECIAL_CHAR
                if len(pwd_complexity_list) == 6:

                    # Get the special characters.
                    # Only take chars in our special char list.
                    special_chars = ""
                    for char in PAM_DEFAULT_SPECIAL_CHAR:
                        if char in pwd_complexity_list[5]:
                            special_chars += char

                pwd_complexity_rule_list = {
                    'length': int(pwd_complexity_list[0]),
                    'caps': int(pwd_complexity_list[1]),
                    'lowercase': int(pwd_complexity_list[2]),
                    'digits': int(pwd_complexity_list[3]),
                    'special': int(pwd_complexity_list[4]),
                    'specialChars': special_chars
                }
            else:
                pwd_complexity_rule_list = {}

        resource_uid = kwargs.get('resource')
        res_rec = vault.vault_data.load_record(kwargs.get('resource', None))
        if res_rec and isinstance(res_rec, vault_record.TypedRecord):
            resource_uid = res_rec.record_uid

        skipped_header = ['record_uid', 'record_title', 'problem', 'description']
        skipped_records = []
        valid_header = ['record_uid', 'record_title', 'enabled', 'configuration_uid', 'resource_uid', 'schedule',
                        'complexity']
        valid_records = []

        r_requests = []  # type: List[router_pb2.RouterRecordRotationRequest]

        # Note: --folder, -fd FOLDER_NAME sets up General rotation
        # use --schedule-only, -so to preserve individual setups (General, IAM, NOOP)
        # use --iam-aad-config, -iac IAM_AAD_CONFIG_UID to convert to IAM User
        for _record in pam_records:
            tmp_dag = TunnelDAG(vault, encrypted_session_token, encrypted_transmission_key, _record.record_uid,
                                transmission_key=transmission_key)
            if _record.record_type in ['pamMachine', 'pamDatabase', 'pamDirectory', 'pamRemoteBrowser']:
                config_resource(tmp_dag, _record, config_uid, silent=kwargs.get('silent'))
            elif _record.record_type == 'pamUser':
                iam_aad_config_uid = kwargs.get('iam_aad_config_uid')
                rotation_profile = kwargs.get('rotation_profile')

                if iam_aad_config_uid and iam_aad_config_uid not in pam_configurations:
                    raise base.CommandError(f'Record uid {iam_aad_config_uid} is not a PAM Configuration record.')

                if resource_uid and iam_aad_config_uid:
                    raise base.CommandError('Cannot use both --resource and --iam-aad-config_uid at once.'
                                           ' --resource is used to configure users found on a resource.'
                                           ' --iam-aad-config-uid is used to configure AWS IAM or Azure AD users')

                # Handle --rotation-profile option
                if rotation_profile:
                    if rotation_profile == 'iam_user':
                        # Use iam_aad_config_uid if provided, otherwise try to get from current rotation or --config
                        effective_config_uid = iam_aad_config_uid or config_uid
                        if not effective_config_uid:
                            current_rotation = params.record_rotation_cache.get(_record.record_uid)
                            if current_rotation:
                                effective_config_uid = current_rotation.get('configuration_uid')
                        if not effective_config_uid:
                            raise base.CommandError('IAM user rotation requires a PAM Configuration. '
                                                   'Use --config or --iam-aad-config to specify one.')
                        if effective_config_uid not in pam_configurations:
                            raise base.CommandError(
                                               f'Record uid {effective_config_uid} is not a PAM Configuration record.')
                        config_iam_aad_user(tmp_dag, _record, effective_config_uid)
                    elif rotation_profile == 'scripts_only':
                        # Set noop flag for scripts_only profile
                        kwargs['noop'] = 'TRUE'
                        config_user(tmp_dag, _record, resource_uid, config_uid, silent=kwargs.get('silent'))
                    elif rotation_profile == 'general':
                        # General rotation requires a resource
                        if not resource_uid:
                            raise base.CommandError('General rotation profile requires --resource to be specified.')
                        config_user(tmp_dag, _record, resource_uid, config_uid, silent=kwargs.get('silent'))
                # NB! --folder=UID without --iam-aad-config, or --schedule-only converts to General rotation
                elif iam_aad_config_uid:
                    config_iam_aad_user(tmp_dag, _record, iam_aad_config_uid)
                else:
                    config_user(tmp_dag, _record, resource_uid, config_uid, silent=kwargs.get('silent'))

        force = kwargs.get('force') is True

        if len(skipped_records) > 0:
            skipped_header = [field_to_title(x) for x in skipped_header]
            dump_report_data(skipped_records, skipped_header, title='The following record(s) were skipped')

            if len(r_requests) > 0 and not force:
                answer = user_choice('\nDo you want to cancel password rotation?', 'Yn', 'Y')
                if answer.lower().startswith('y'):
                    return

        if len(r_requests) > 0:
            valid_header = [field_to_title(x) for x in valid_header]
            if not kwargs.get('silent'):
                dump_report_data(valid_records, valid_header, title='The following record(s) will be updated')
            if not force:
                answer = user_choice('\nDo you want to update password rotation?', 'Yn', 'Y')
                if answer.lower().startswith('n'):
                    return

            for rq in r_requests:
                record_uid = utils.base64_url_encode(rq.recordUid)
                try:
                    router_set_record_rotation_information(params, rq, transmission_key, encrypted_transmission_key,
                                                           encrypted_session_token)
                except KeeperApiError as kae:
                    logger.warning('Record "%s": Set rotation error "%s": %s',
                                    record_uid, kae.result_code, kae.message)
            vault.sync_data = True



class PAMRouterGetRotationInfo(Command):
    parser = argparse.ArgumentParser(prog='dr-router-get-rotation-info-parser')
    parser.add_argument('--record-uid', '-r', required=True, dest='record_uid', action='store',
                        help='Record UID to rotate')

    def get_parser(self):
        return PAMRouterGetRotationInfo.parser

    def execute(self, params, **kwargs):

        record_uid = kwargs.get('record_uid')
        record_uid_bytes = url_safe_str_to_bytes(record_uid)

        rri = record_rotation_get(params, record_uid_bytes)
        rri_status_name = router_pb2.RouterRotationStatus.Name(rri.status)
        if rri_status_name == 'RRS_ONLINE':

            print(f'Rotation Status: {bcolors.OKBLUE}Ready to rotate ({rri_status_name}){bcolors.ENDC}')
            configuration_uid = utils.base64_url_encode(rri.configurationUid)
            print(f'PAM Config UID: {bcolors.OKBLUE}{configuration_uid}{bcolors.ENDC}')
            print(f'Node ID: {bcolors.OKBLUE}{rri.nodeId}{bcolors.ENDC}')

            print(
                f"Gateway Name where the rotation will be performed: {bcolors.OKBLUE}{(rri.controllerName if rri.controllerName else '-')}{bcolors.ENDC}")
            print(
                f"Gateway Uid: {bcolors.OKBLUE}{(utils.base64_url_encode(rri.controllerUid) if rri.controllerUid else '-')} {bcolors.ENDC}")

            def is_resource_ok(resource_id, params, configuration_uid):
                if resource_id not in params.record_cache:
                    return False

                configuration = vault.KeeperRecord.load(params, configuration_uid)
                if not isinstance(configuration, vault.TypedRecord):
                    return False

                field = configuration.get_typed_field('pamResources')
                if not (field and isinstance(field.value, list) and len(field.value) == 1):
                    return False

                rv = field.value[0]
                if not isinstance(rv, dict):
                    return False

                resources = rv.get('resourceRef')
                return isinstance(resources, list) and resource_id in resources

            if rri.resourceUid:
                resource_id = utils.base64_url_encode(rri.resourceUid)
                resource_ok = is_resource_ok(resource_id, params, configuration_uid)
                print(f"Admin Resource Uid: {bcolors.OKBLUE if resource_ok else bcolors.FAIL}{resource_id}"
                      f"{bcolors.ENDC}")

            # print(f"Router Cookie: {bcolors.OKBLUE}{(rri.cookie if rri.cookie else '-')}{bcolors.ENDC}")
            # print(f"scriptName: {bcolors.OKGREEN}{rri.scriptName}{bcolors.ENDC}")
            if rri.pwdComplexity:
                print(f"Password Complexity: {bcolors.OKGREEN}{rri.pwdComplexity}{bcolors.ENDC}")
                try:
                    record = params.record_cache.get(record_uid)
                    if record:
                        complexity = crypto.decrypt_aes_v2(utils.base64_url_decode(rri.pwdComplexity),
                                                           record['record_key_unencrypted'])
                        c = json.loads(complexity.decode())
                        print(f"Password Complexity Data: {bcolors.OKBLUE}"
                              f"Length: {c.get('length')}; Lowercase: {c.get('lowercase')}; "
                              f"Uppercase: {c.get('caps')}; "
                              f"Digits: {c.get('digits')}; "
                              f"Symbols: {c.get('special')}; "
                              f"Symbols Chars: {c.get('specialChars')} {bcolors.ENDC}")
                except:
                    pass
            else:
                print(f"Password Complexity: {bcolors.OKGREEN}[not set]{bcolors.ENDC}")

            print(f"Is Rotation Disabled: {bcolors.OKGREEN}{rri.disabled}{bcolors.ENDC}")

            # Get schedule information
            rq = pam_pb2.PAMGenericUidsRequest()
            schedules_proto = router_get_rotation_schedules(params, rq)
            if schedules_proto:
                schedules = list(schedules_proto.schedules)
                for s in schedules:
                    if s.recordUid == record_uid_bytes:
                        if s.noSchedule is True:
                            print(f"Schedule Type: {bcolors.OKBLUE}Manual Rotation{bcolors.ENDC}")
                        else:
                            if s.scheduleData:
                                schedule_arr = s.scheduleData.replace('RotateActionJob|', '').split('.')
                                if len(schedule_arr) == 4:
                                    schedule_str = f'{schedule_arr[0]} on {schedule_arr[1]} at {schedule_arr[2]} UTC with interval count of {schedule_arr[3]}'
                                elif len(schedule_arr) == 3:
                                    schedule_str = f'{schedule_arr[0]} at {schedule_arr[1]} UTC with interval count of {schedule_arr[2]}'
                                else:
                                    schedule_str = s.scheduleData
                                print(f"Schedule: {bcolors.OKBLUE}{schedule_str}{bcolors.ENDC}")
                        break

            print(f"\nCommand to manually rotate: {bcolors.OKGREEN}pam action rotate -r {record_uid}{bcolors.ENDC}")
        else:
            print(f'{bcolors.WARNING}Rotation Status: Not ready to rotate ({rri_status_name}){bcolors.ENDC}')


class PAMRouterScriptCommand(GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('list', PAMScriptListCommand(), 'List script fields')
        self.register_command('add', PAMScriptAddCommand(), 'List Record Rotation Schedulers')
        self.register_command('edit', PAMScriptEditCommand(), 'Add, delete, or edit script field')
        self.register_command('delete', PAMScriptDeleteCommand(), 'Delete script field')
        self.default_verb = 'list'



class PAMScriptListCommand(Command):
    parser = argparse.ArgumentParser(prog='pam rotate script view', parents=[report_output_parser],
                                     description='List script fields')
    parser.add_argument('pattern', nargs='?', help='Record UID, path, or search pattern')

    def get_parser(self):
        return PAMScriptListCommand.parser

    def execute(self, params, **kwargs):
        pattern = kwargs.get('pattern')

        table = []
        header = ['record_uid', 'title', 'record_type', 'script_uid', 'script_name', 'records', 'command']
        for record in vault_extensions.find_records(params, search_str=pattern, record_version=3,
                                                    record_type=('pamUser', 'pamDirectory')):
            if not isinstance(record, vault.TypedRecord):
                continue
            for field in (x for x in record.fields if x.type == 'script'):
                value = field.get_default_value(dict)
                if not value:
                    continue
                file_ref = value.get('fileRef')
                if not file_ref:
                    continue
                file_record = vault.KeeperRecord.load(params, file_ref)
                if not file_record:
                    continue
                records = value.get('recordRef')
                command = value.get('command')
                table.append([record.record_uid, record.title, record.record_type, file_record.record_uid,
                              file_record.title, records, command])
        fmt = kwargs.get('format')
        if fmt != 'json':
            header = [field_to_title(x) for x in header]
        return dump_report_data(table, header, fmt=fmt, filename=kwargs.get('output'), row_number=True)


class PAMScriptAddCommand(Command):
    parser = argparse.ArgumentParser(prog='pam rotate script add', description='Add script to record')
    parser.add_argument('--script', required=True, dest='script', action='store',
                        help='Script file name')
    parser.add_argument('--add-credential', dest='add_credential', action='append',
                        help='Record with rotation credential')
    parser.add_argument('--script-command', dest='script_command', action='store',
                        help='Script command')
    parser.add_argument('record', help='Record UID or Title')

    def get_parser(self):
        return PAMScriptAddCommand.parser

    def execute(self, params, **kwargs):
        record_name = kwargs.get('record')
        if not record_name:
            raise CommandError('rotate script', '"record" argument is required')
        records = list(vault_extensions.find_records(
            params, search_str=record_name, record_version=3, record_type=('pamUser', 'pamDirectory')))
        if len(records) == 0:
            raise CommandError('rotate script', f'Record "{record_name}" not found')
        if len(records) > 1:
            raise CommandError('rotate script', f'Record "{record_name}" is not unique. Use record UID.')
        record = records[0]
        if not isinstance(record, vault.TypedRecord):
            raise CommandError('rotate script', f'Record "{record.title}" is not a rotation record.')

        script_field = next((x for x in record.fields if x.type == 'script'), None)
        if not script_field:
            script_field = vault.TypedField.new_field('script', [], 'rotationScripts')
            record.fields.append(script_field)

        file_name = kwargs.get('script')
        full_name = os.path.expanduser(file_name)
        if not os.path.isfile(full_name):
            raise CommandError('rotate script', f'File "{file_name}" not found.')

        facade = record_facades.FileRefRecordFacade()
        facade.record = record
        pre = set(facade.file_ref)
        upload_task = attachment.FileUploadTask(full_name)
        attachment.upload_attachments(params, record, [upload_task])
        post = set(facade.file_ref)
        df = post.difference(pre)
        if len(df) == 1:
            file_uid = df.pop()
            facade.file_ref.remove(file_uid)
            script_value = {
                'fileRef': file_uid,
                'recordRef': [],
                'command': '',
            }
            script_field.value.append(script_value)
            record_refs = kwargs.get('add_credential')
            if isinstance(record_refs, list):
                for ref in record_refs:
                    if ref in params.record_cache:
                        script_value['recordRef'].append(ref)
            cmd = kwargs.get('script_command')
            if cmd:
                script_value['command'] = cmd

        record_management.update_record(params, record)
        params.sync_data = True


class PAMScriptEditCommand(Command):
    parser = argparse.ArgumentParser(prog='pam rotate script edit', description='Edit script field')
    parser.add_argument('--script', required=True, dest='script', action='store',
                        help='Script UID or name')
    parser.add_argument('-ac', '--add-credential', dest='add_credential', action='append',
                        help='Add a record with rotation credential')
    parser.add_argument('-rc', '--remove-credential', dest='remove_credential', action='append',
                        help='Remove a record with rotation credential')
    parser.add_argument('--script-command', dest='script_command', action='store',
                        help='Script command')
    parser.add_argument('record', help='Record UID or Title')

    def get_parser(self):
        return PAMScriptEditCommand.parser

    def execute(self, params, **kwargs):
        record_name = kwargs.get('record')
        if not record_name:
            raise CommandError('rotate script', '"record" argument is required')

        script_name = kwargs.get('script')  # type: Optional[str]
        if not script_name:
            raise CommandError('rotate script', '"script" argument is required')

        records = list(vault_extensions.find_records(
            params, search_str=record_name, record_version=3, record_type=('pamUser', 'pamDirectory')))
        if len(records) == 0:
            raise CommandError('rotate script', f'Record "{record_name}" not found')
        if len(records) > 1:
            raise CommandError('rotate script', f'Record "{record_name}" is not unique. Use record UID.')
        record = records[0]
        if not isinstance(record, vault.TypedRecord):
            raise CommandError('rotate script', f'Record "{record.title}" is not a rotation record.')

        script_field = next((x for x in record.fields if x.type == 'script'), None)
        if script_field is None:
            raise CommandError('rotate script', f'Record "{record.title}" has no rotation scripts.')
        script_value = next((x for x in script_field.value if x.get('fileRef') == script_name), None)
        if script_value is None:
            s_name = script_name.casefold()
            for x in script_field.value:
                file_uid = x.get('fileRef')
                file_record = vault.KeeperRecord.load(params, file_uid)
                if isinstance(file_record, vault.FileRecord):
                    if file_record.title.casefold() == s_name:
                        script_value = x
                        break
                    elif file_record.name.casefold() == s_name:
                        script_value = x
                        break

        if not isinstance(script_value, dict):
            raise CommandError('rotate script', f'Record "{record.title}" does not have script "{script_name}"')

        modified = False
        refs = set()
        record_refs = script_value.get('recordRef')
        if isinstance(record_refs, list):
            refs.update(record_refs)
        remove_credential = kwargs.get('remove_credential')
        if isinstance(remove_credential, list) and remove_credential:
            refs.difference_update(remove_credential)
            modified = True
        add_credential = kwargs.get('add_credential')
        if isinstance(add_credential, list) and add_credential:
            refs.update(add_credential)
            modified = True
        if modified:
            script_value['recordRef'] = list(refs)
        command = kwargs.get('script_command')
        if command:
            script_value['command'] = command
            modified = True

        if not modified:
            raise CommandError('rotate script', 'Nothing to do')

        record_management.update_record(params, record)
        params.sync_data = True


class PAMScriptDeleteCommand(Command):
    parser = argparse.ArgumentParser(prog='pam rotate script delete', description='Delete script field')
    parser.add_argument('--script', required=True, dest='script', action='store',
                        help='Script UID or name')
    parser.add_argument('record', help='Record UID or Title')

    def get_parser(self):
        return PAMScriptDeleteCommand.parser

    def execute(self, params, **kwargs):
        record_name = kwargs.get('record')
        if not record_name:
            raise CommandError('rotate script', '"record" argument is required')

        script_name = kwargs.get('script')  # type: Optional[str]
        if not script_name:
            raise CommandError('rotate script', '"script" argument is required')

        records = list(vault_extensions.find_records(
            params, search_str=record_name, record_version=3, record_type=('pamUser', 'pamDirectory')))
        if len(records) == 0:
            raise CommandError('rotate script', f'Record "{record_name}" not found')
        if len(records) > 1:
            raise CommandError('rotate script', f'Record "{record_name}" is not unique. Use record UID.')
        record = records[0]
        if not isinstance(record, vault.TypedRecord):
            raise CommandError('rotate script', f'Record "{record.title}" is not a rotation record.')

        script_field = next((x for x in record.fields if x.type == 'script'), None)
        if script_field is None:
            raise CommandError('rotate script', f'Record "{record.title}" has no rotation scripts.')
        script_value = next((x for x in script_field.value if x.get('fileRef') == script_name), None)
        if script_value is None:
            s_name = script_name.casefold()
            for x in script_field.value:
                file_uid = x.get('fileRef')
                file_record = vault.KeeperRecord.load(params, file_uid)
                if isinstance(file_record, vault.FileRecord):
                    if file_record.title.casefold() == s_name:
                        script_value = x
                        break
                    elif file_record.name.casefold() == s_name:
                        script_value = x
                        break

        if not isinstance(script_value, dict):
            raise CommandError('rotate script', f'Record "{record.title}" does not have script "{script_name}"')

        script_field.value.remove(script_value)
        record_management.update_record(params, record)
        params.sync_data = True

