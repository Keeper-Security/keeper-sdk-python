import argparse
import datetime
import hashlib
import hmac
import json
import os
import platform
import re
import socket
import subprocess
from typing import Optional, Any, Dict, List, Set, Union, Tuple

import attrs

from keepersdk import utils, constants, crypto
from keepersdk.plugins.pedm import agent_plugin, pedm_shared
from keepersdk.plugins.pedm.pedm_shared import approval_type_to_name
from keepersdk.proto import NotificationCenter_pb2
from keepersdk.utils import get_logger
from . import base
from .. import prompt_utils, api
from ..helpers import report_utils
from ..params import KeeperParams


class PedmAgentCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('KEPM Agent commands')
        self.register_command(PedmAgentCreateCommand(), 'create')
        self.register_command(PedmAgentLoadCommand(), 'load')
        self.register_command(PedmAgentInfoCommand(), 'info')
        self.register_command(PedmAgentRegisterCommand(), 'register')
        self.register_command(PedmAgentUnregisterCommand(), 'unregister')
        self.register_command(PedmAgentSyncDownCommand(), 'sync-down')
        self.register_command(PedmAgentAuditLogCommand(), 'audit')
        self.register_command(PedmAgentUnloadCommand(), 'unload')
        self.register_command(PedmAgentPingCommand(), 'ping')
        self.register_command(PedmAgentInventoryCommand(), 'inventory', 'i')
        self.register_command(PedmAgentCollectionCommand(), 'collection', 'c')
        self.register_command(PedmAgentApprovalCommand(), 'approval', 'a')
        self.register_command(PedmAgentPolicyCommand(), 'policy', 'p')
        self.register_command(PedmAgentVerify2faCommand(), '2fa')
        self.register_command(PedmAgentNotificationCommand(), 'notification')
        self.register_command(PedmAgentKeychainCommand(), 'keychain')


class PedmAgentCreateCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='create', description='Create a KEPM agent')
        parser.add_argument('--file', dest='filename', action='store',
                            help='Filename to store agent configuration')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = agent_plugin.create_agent()
        config = json.dumps(agent.to_dict(), indent=2)
        file_name = kwargs.get('filename')
        if file_name:
            if os.path.isfile(file_name):
                raise Exception(f'File "{file_name}" already exists')
            with open(file_name, 'wt') as f:
                f.write(config)
        else:
            return config


class PedmAgentLoadCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='load', description='Load a KEPM agent from configuration')
        parser.add_argument('config', metavar='FILENAME', help='Config file name')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        if context.pedm_agent_plugin is not None:
            raise base.CommandError('KEPM Agent is already loaded. Use "unload" command first')

        file_name: Optional[str] = kwargs['config']
        if file_name is None:
            raise base.CommandError(f'"config" argument cannot be empty')

        file_name = os.path.expanduser(file_name)
        if not os.path.isfile(file_name):
            raise ValueError(f'File {file_name} does not exist')

        agent_config_loader = agent_plugin.JsonAgentConfigurationStorage(file_name)
        agent = agent_plugin.PedmAgentPlugin(agent_config_loader, get_connection=context.keeper_config.get_connection)

        context.pedm_agent_plugin = agent
        if not agent.is_registered:
            prompt_utils.output_text('Agent is not registered', color='WARNING')


class PedmAgentInfoCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='info', description='Displays KEPM agent information')
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                            help='print verbose information')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = context.pedm_agent_plugin
        verbose = kwargs.get('verbose') is True
        if agent is None:
            raise base.CommandError('KEPM Agent is not loaded. "load" agent configuration.')
        table = []
        table.append(['Agent UID', agent.agent_uid])
        if isinstance(agent.config_storage, agent_plugin.JsonAgentConfigurationStorage):
            table.append(['Configuration File', os.path.abspath(agent.config_storage.file_name)])
        if agent.is_registered:
            assert agent.hash_key
            assert agent.hostname
            if agent.deployment_uid:
                table.append(['Deployment UID', agent.deployment_uid])
            table.append(['Host Name', agent.hostname])
            if verbose:
                table.append(['Hash Key', utils.base64_url_encode(agent.hash_key)])

        return report_utils.dump_report_data(table, ('key', 'value'), no_header=True)


class PedmAgentPingCommand(base.ICliCommand):
    def description(self):
        return "Ping the backend"

    def execute_args(self, context: KeeperParams, args: str, **kwargs):
        agent = context.pedm_agent_plugin
        assert agent
        if not agent.is_registered:
            raise base.CommandError('KEPM agent is not registered')
        agent.execute_rest('ping')


class PedmAgentRegisterCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='register', description='Register a KEPM agent')
        parser.add_argument('--machine-id', dest='machine_id', action='store',
                            help='Unique machine identifier. Can be random text')
        parser.add_argument('--hostname', dest='hostname', action='store',
                            help='Hostname to identify the agent in the Console')
        parser.add_argument('token', help='Deployment token or file name: @filename')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        agent = context.pedm_agent_plugin
        if agent is None:
            raise base.CommandError('KEPM Agent is not loaded. "load" agent configuration.')

        if agent.is_registered:
            answer = prompt_utils.user_choice(
                'KEPM Agent is already registered. Do you want to register is again?','yN', default='n')
            if answer.lower() not in ('y', 'yes'):
                return

        file_name = kwargs.get('token')
        if not isinstance(file_name, str) or len(file_name) == 0:
            raise base.CommandError('token parameter cannot be empty')
        if file_name.startswith('@'):
            file_name = os.path.expanduser(file_name[1:])
            if not os.path.isfile(file_name):
                raise base.CommandError(f'Deployment file "{file_name}" does not exist')
            with open(file_name, 'rt') as f:
                token = f.read()
        else:
            token = file_name
        comps = token.split(':')
        if len(comps) != 3:
            raise base.CommandError(f'Invalid deployment token')
        hostname = comps[0]
        if hostname in constants.KEEPER_PUBLIC_HOSTS:
            hostname = constants.KEEPER_PUBLIC_HOSTS[hostname]
        deployment_uid = comps[1]
        private_key = utils.base64_url_decode(comps[2])
        deployment_token = agent_plugin.DeploymentToken(
            hostname=hostname, deployment_uid=deployment_uid, private_key=private_key)

        machine_id: Optional[bytes] = None
        m_id = kwargs.get('machine_id')
        if isinstance(m_id, str) and len(m_id) > 0:
            agent.machine_id = m_id
            machine_id = m_id.encode('utf-8')

        agent.register(deployment_token, machine_id=machine_id, force=True)

        logger = utils.get_logger()
        if agent.is_registered:
            logger.info('Agent is registered')

            hostname = kwargs.get('hostname')
            if isinstance(hostname, str) and hostname:
                cmd = PedmAgentInventoryBasicCommand()
                cmd.execute(context, hostname=hostname)

            agent.sync_down(reload=True)


class PedmAgentUnregisterCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='unregister', description='Unregister KEPM agent')
        parser.add_argument('-f', '--force', dest='force', action='store_true',
                            help='do not prompt for confirmation')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = context.pedm_agent_plugin
        assert agent
        if not agent.is_registered:
            raise base.CommandError('KEPM agent is not registered')
        agent.unregister()
        context.pedm_agent_plugin = None

class PedmAgentUnloadCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='disconnect', description='Disconnect a KEPM agent')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        context.pedm_agent_plugin = None


HASH_FIELDS = {'target_info', 'user_info', 'admin_info'}
ENCRYPTED_FIELDS = {'notification_info', 'justification_info', 'current_configuration'}

@attrs.define(kw_only=True)
class CollectionValue:
    field: str
    value_uid: str
    data: bytes

class PedmAgentAuditLogCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='audit', description='Post agent audit logs')
        parser.add_argument('--event-type', dest='event_type', action='store', required=True, help='event type')
        parser.add_argument('fields', nargs='*', type=str, help='event fields')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        agent = context.pedm_agent_plugin
        assert agent
        if not agent.is_registered:
            raise base.CommandError('KEPM agent is not registered')
        assert agent.peer_public_key

        inputs:  Dict[str, Any] = {}
        pending_collections: List[CollectionValue] = []

        collection_logs: List[Dict[str, str]] = []
        item_logs: List[Dict[str, Any]] = []
        rejected_events: List[Dict[str, Any]] = []

        event_type = kwargs.get('event_type')
        try:
            fields = kwargs.get('fields')
            if isinstance(fields, list):
                for field in fields:
                    name, sep, value = field.partition('=')
                    if sep != '=':
                        raise Exception(f'Invalid audit event field: "{field}"')
                    if name in HASH_FIELDS:
                        if isinstance(value, str):
                            value_uid, encrypted_data = agent.get_hashed_value(name, value)
                            pending_collections.append(CollectionValue(field=name, value_uid=value_uid, data=encrypted_data))
                            inputs[name] = value_uid
                        else:
                            raise Exception(f'Invalid audit event field "{field}" value. text expected')
                    elif name in ENCRYPTED_FIELDS:
                        if isinstance(value, str):
                            value_uid = utils.generate_uid()
                            encrypted_data = crypto.encrypt_ec(value.encode('utf-8'), agent.peer_public_key)
                            inputs[name] = value_uid
                            collection_logs.append({
                                'field': name,
                                'value_uid': value_uid,
                                'encrypted_data': utils.base64_url_encode(encrypted_data)
                            })
                        else:
                            raise Exception(f'Invalid audit event field "{field}" value. text expected')
                    else:
                        inputs[name] = value

            event = {
                'audit_event_type': event_type,
            }
            if len(inputs) > 0:
                event['inputs'] = inputs
            item_logs.append(event)
        except Exception as e:
            rejected_events.append({
                'audit_event_type': event_type,
                'message': str(e),
            })

        logger = utils.get_logger()
        while len(item_logs) > 0 or len(collection_logs) > 0:
            rq = {}
            if len(item_logs) > 0:
                rq['item_logs'] = item_logs
            if len(collection_logs) > 0:
                rq['collection_logs'] = collection_logs

            rs = agent.execute_rest('audit_event_logging', rq)
            assert rs is not None
            item_logs.clear()
            collection_logs.clear()
            rejected = rs.get('rejected_events')
            if isinstance(rejected, list) and len(rejected) > 0:
                rejected_events.extend(rejected)

            collection_values = rs.get('collection_values')
            if isinstance(collection_values, list) and len(collection_values) > 0 and len(pending_collections) > 0:
                for cv in collection_values:
                    fld = cv.get('field')
                    value_uid = cv.get('value_uid')
                    cvd = next((x for x in pending_collections if x.field == fld and x.value_uid == value_uid ), None)
                    if cvd is not None:
                        collection_logs.append({
                            'field': fld,
                            'value_uid': value_uid,
                            'encrypted_data': utils.base64_url_encode(cvd.data)
                        })

        if len(rejected_events) > 0:
            logger.info('Rejected events')
            for event in rejected_events:
                logger.info(f'{event.get("audit_event_type")}: {event.get("message")}')

class PedmAgentSyncDownCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='sync-down', description='Sync down policies')
        parser.add_argument('--reload', dest='reload', action='store_true', help='Perform full sync')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        agent = context.pedm_agent_plugin
        if not agent:
            raise base.CommandError('KEPM Agent is not connected')

        agent.sync_down(reload=kwargs.get('reload') is True)


class PedmAgentApprovalCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('KEPM Agent approvals')
        self.register_command(PedmAgentApprovalListCommand(), 'list', 'l')
        self.register_command(PedmAgentApprovalCreateCommand(), 'create')
        self.default_verb = 'list'


class PedmAgentApprovalListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='list', description='List KEPM approval requests',
                                         parents=[base.report_output_parser])
        parser.add_argument('--status', dest='status', choices=['pending', 'approved', 'denied'],
                            action='append', help='Approval request status filter')

        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = context.pedm_agent_plugin
        if not agent:
            raise base.CommandError('KEPM Agent is not connected')
        assert agent.hash_key is not None

        status: Any = kwargs.get('status')
        if isinstance(status, str):
            status = [status]
        if not status:
            status = ['pending', 'approved', 'denied']
        status_filter: Set[str] = set(status)

        headers = ['approval_uid', 'approval_type', 'status', 'account', 'application', 'justification', 'expire_in', 'created']
        table = []
        for ar in agent.storage.approvals.get_all_entities():
            approval_status = agent.storage.approval_status.get_entity(ar.approval_uid)
            if approval_status:
                status = 'approved' if approval_status.approval_status == NotificationCenter_pb2.NAS_APPROVED  else 'denied'
            else:
                status = 'pending'
            if status not in status_filter:
                continue
            try:
                justi: Any = crypto.decrypt_aes_v2(ar.justification, agent.hash_key).decode() if ar.justification else None
                if isinstance(justi, str):
                    justi = [y for y in (x.strip() for x in justi.split('\n')) if y]
                else:
                    justi = None

                app_info: Any = crypto.decrypt_aes_v2(ar.application_info, agent.hash_key)
                app_info = json.loads(app_info)
                if isinstance(app_info, dict):
                    app_info = [f'{k}={v}' for k, v in app_info.items()]

                acc_info: Any = crypto.decrypt_aes_v2(ar.account_info, agent.hash_key)
                acc_info = json.loads(acc_info)
                if isinstance(acc_info, dict):
                    acc_info = [f'{k}={v}' for k, v in acc_info.items()]
            except:
                continue


            time_created = datetime.datetime.fromtimestamp(int(ar.created // 1000))
            row = [ar.approval_uid, pedm_shared.approval_type_to_name(ar.approval_type), status, acc_info, app_info, justi, ar.expire_in, time_created]
            table.append(row)

        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, sort_by=1, column_width=40, fmt=fmt, filename=kwargs.get('output'))


class PedmAgentApprovalCreateCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='create', description='Create KEPM approval request')
        parser.add_argument('--type', dest='type', action='store', required=True,
                            choices=['elevate', 'file_access', 'command', 'agentic_ai', 'agentic_access', 'agentic_elevate'],
                            help='Approval Request Type')
        application_group = parser.add_mutually_exclusive_group(required=True)
        application_group.add_argument('--application', dest='application', action='append',
                                       help='Application Properties: KEY:VALUE')
        application_group.add_argument('--application-uid', dest='application_uid', action='store',
                                       help='Application UID')
        account_group = parser.add_mutually_exclusive_group(required=True)
        account_group.add_argument('--account', dest='account', action='append',
                                   help='User Account Properties: KEY:VALUE')
        account_group.add_argument('--account-uid', dest='account_uid', action='store',
                                   help='Application UID')
        parser.add_argument('--justification', dest='justification', action='store', required=True,
                            help='Approval Request Justification')
        parser.add_argument('--expire-in', dest='expire_in', action='store', type=int,
                            help='Approval Request Expiration in minutes')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = context.pedm_agent_plugin
        if not agent:
            raise base.CommandError('KEPM Agent is not connected')
        assert isinstance(agent.hash_key, bytes)

        a_type = kwargs.get('type') or ''
        if a_type == 'elevate':
            approval_type = pedm_shared.EventRequestType.PrivilegeElevation
        elif a_type == 'file_access':
            approval_type = pedm_shared.EventRequestType.FileAccess
        elif a_type == 'command':
            approval_type = pedm_shared.EventRequestType.CommandLine
        elif a_type == 'agentic_ai':
            approval_type = pedm_shared.EventRequestType.AgenticAi
        elif a_type == 'agentic_access':
            approval_type = pedm_shared.EventRequestType.AgenticFileAccess
        elif a_type == 'agentic_elevate':
            approval_type = pedm_shared.EventRequestType.AgenticPrivilegeElevation
        else:
            raise base.CommandError(f'Approval type "{a_type}" is not supported')

        def load_properties(prop_arg: str, coll_arg: str, coll_type: int) -> Dict[str, str]:
            assert isinstance(agent.hash_key, bytes)
            info: Dict[str, str] = {}
            props = kwargs.get(prop_arg)
            if props is not None:
                if isinstance(props, str):
                    props = [props]
                for prop in props:
                    key, sep, value = prop.partition(':')
                    if not sep:
                        raise base.CommandError(f'Application property "{prop}". Expected KEY:VALUE format')
                    info[key] = value

            collection_uid = kwargs.get(coll_arg)
            if collection_uid:
                collection = agent.storage.collections.get_entity(collection_uid)
                if not collection:
                    raise base.CommandError(f'Collection "{collection_uid}" not found')
                if collection.collection_type != coll_type:
                    raise base.CommandError(f'Collection "{collection_uid}" is not application')
                if collection.data:
                    coll_data = json.loads(collection.data)
                    if isinstance(coll_data, dict):
                        info.update(coll_data)
            return info

        application_dict = load_properties('application', 'application_uid', pedm_shared.CollectionType.Application)
        if len(application_dict) == 0:
            raise base.CommandError(f'Application information cannot be empty')
        application_info = crypto.encrypt_aes_v2(json.dumps(application_dict).encode('utf-8'), agent.hash_key)

        account_dict = load_properties('account', 'account_uid', pedm_shared.CollectionType.UserAccount)
        if len(account_dict) == 0:
            raise base.CommandError(f'User Account information cannot be empty')
        account_info = crypto.encrypt_aes_v2(json.dumps(account_dict).encode('utf-8'), agent.hash_key)

        justification: Union[str, bytes, None] = kwargs.get('justification')
        if isinstance(justification, str):
            justification = justification.encode('utf-8')
        if isinstance(justification, bytes):
            justification = crypto.encrypt_aes_v2(justification, agent.hash_key)
            justification = utils.base64_url_encode(justification)
        else:
            justification = None
        expire_in = kwargs.get('expire_in')

        approval_uid = utils.generate_uid()
        approval_rq = {
            'add_approvals': [{
                'approval_uid': approval_uid,
                'approval_type': approval_type,
                'application_info': utils.base64_url_encode(application_info),
                'account_info': utils.base64_url_encode(account_info),
                'justification': justification,
                'expire_in': expire_in,
            }]
        }
        approval_rs = agent.execute_rest('modify_approval', approval_rq)
        assert isinstance(approval_rs, dict)
        failed_approvals = approval_rs.get('failed_approvals')
        if isinstance(failed_approvals, list):
            logger = api.get_logger()
            for fa in failed_approvals:
                logger.warning(fa.get('message'))
        if isinstance(failed_approvals, list) and len(failed_approvals) > 0:
            return

        # self.add_approval_audience(agent, approval_uid, approval_type, account_dict, application_dict, kwargs.get('justification'))

    def add_approval_audience(self, agent: agent_plugin.PedmAgentPlugin, approval_uid: str, approval_type: int,
                              account_dict: Dict[str, Any], application_dict: Dict[str, Any], justification: Optional[str]) -> None:
        """Encrypts the approval for its approver teams and posts it with add_approval_audience."""
        logger = api.get_logger()
        audience = agent.get_approval_audience(approval_type)
        if not audience:
            logger.info('No approval audience is configured for this approval type; approvers are not notified')
            return
        username = account_dict.get('Username')
        if not username:
            raise base.CommandError('User Account information should contain "Username"')
        encrypted_data, audience_keys = self.encrypt_for_audience(agent, audience, {
            'version': 1,
            'account_info': {'Username': username},
            'application_info': {k: v for k, v in application_dict.items() if k != 'FileHash'},
            'justification': justification or '',
            'agent_info': self.get_agent_info(agent),
        })
        rq = {'approvals': [{'approval_uid': approval_uid, 'encrypted_data': encrypted_data, 'audience': audience_keys}]}
        rs = agent.execute_rest('add_approval_audience', rq)
        failed = rs.get('failed_approvals') if isinstance(rs, dict) else None
        if isinstance(failed, list) and len(failed) > 0:
            for fa in failed:
                logger.warning(fa.get('message'))
        else:
            logger.info('Approval request %s is encrypted for %d approver team(s)', approval_uid, len(audience_keys))

    @staticmethod
    def get_agent_info(agent: agent_plugin.PedmAgentPlugin) -> Dict[str, Any]:
        inventory = PedmAgentInventoryBasicCommand.get_system_info()
        return {
            'AgentUID': agent.agent_uid,
            'MachineName': inventory.get('MachineName'),
            'OS': inventory.get('Name'),
            'OSVersion': inventory.get('Version'),
        }

    @staticmethod
    def encrypt_for_audience(agent: agent_plugin.PedmAgentPlugin, audience: List[Dict[str, Any]],
                             data: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
        """Encrypts the approval data with a new key and wraps that key for every audience public key."""
        approval_key = utils.generate_aes_key()
        encrypted_data = utils.base64_url_encode(crypto.encrypt_aes_v2(json.dumps(data).encode('utf-8'), approval_key))
        audience_keys: List[Dict[str, Any]] = []
        for a in audience:
            public_key = crypto.load_ec_public_key(utils.base64_url_decode(a['public_key']))
            audience_keys.append({
                'audience_type': a['audience_type'],
                'audience_uid': a['audience_uid'],
                'encrypted_key': utils.base64_url_encode(crypto.encrypt_ec(approval_key, public_key)),
            })
        return encrypted_data, audience_keys


class PedmAgentPolicyCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('KEPM Agent policies')
        self.register_command(PedmAgentPolicyListCommand(), 'list', 'l')
        self.register_command(PedmAgentPolicyViewCommand(), 'view', 'v')
        self.default_verb = 'list'

class PedmAgentPolicyListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='list', description='List KEPM policies', parents=[base.report_output_parser])
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = context.pedm_agent_plugin
        if not agent:
            raise base.CommandError('KEPM Agent is not connected')

        table = []
        headers = ['policy_uid', 'policy_name', 'policy_type', 'status', 'controls', 'users', 'machines', 'applications', 'days']
        for policy in agent.policies.get_all_entities():
            data = policy.data
            actions = data.get('Actions') or {}
            on_success = actions.get('OnSuccess') or {}
            controls = on_success.get('Controls') or ''
            data = policy.data or {}
            days: Any = data.get('DayCheck')
            if isinstance(days, list):
                days = ','.join((str(x) for x in days))
            table.append([policy.policy_uid, data.get('PolicyName'), data.get('PolicyType'), data.get('Status'),
                          controls, data.get('UserCheck'), data.get('MachineCheck'), data.get('ApplicationCheck'),
                          days])

        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'), sort_by=1)


class PedmAgentPolicyViewCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='view', description='View KEPM policy', parents=[base.json_output_parser])
        parser.add_argument('policy', help='Policy UID or name')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = context.pedm_agent_plugin
        if not agent:
            raise base.CommandError('KEPM Agent is not connected')

        policy_name: Optional[str] = kwargs.get('policy')
        if not policy_name:
            raise base.CommandError(f'"policy" argument must not be empty')
        policies = [x for x in agent.policies.get_all_entities() if x.policy_uid == policy_name]
        if not policies:
            raise base.CommandError(f'Policy {policy_name} does not exist')
        if len(policies) > 1:
            raise base.CommandError(f'Policy {policy_name} is not unique. Use policy UID')
        policy = policies[0]

        body = json.dumps(policy.data, indent=4)
        filename = kwargs.get('output')
        if kwargs.get('format') == 'json' and filename:
            with open(filename, 'w') as f:
                f.write(body)
        else:
            return body

class PedmAgentInventoryCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('KEPM Agent inventory')
        self.register_command(PedmAgentInventoryBasicCommand(), 'basic')

class PedmAgentInventoryBasicCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='inventory-basic', description='Upload basic inventory')
        parser.add_argument('--hostname', dest='hostname', action='store',
                            help='Hostname to identify the agent')
        super().__init__(parser)

    @staticmethod
    def get_os_name():
        system = platform.system()

        if system == 'Darwin':  # macOS
            try:
                macos_version = subprocess.check_output(['sw_vers', '-productVersion']).decode().strip()
                major_version = int(macos_version.split('.')[0])

                # Map macOS version numbers to names
                macos_names = {
                    15: "Sequoia",
                    14: "Sonoma",
                    13: "Ventura",
                    12: "Monterey",
                    11: "Big Sur",
                    10: "Catalina"  # This would need refinement for older versions
                }

                return macos_names.get(major_version, f"macOS {macos_version}")
            except:
                return "macOS"

        elif system == 'Windows':
            try:
                # Method 1: Using platform.release() and version()
                win_version = platform.release()

                # Windows 10/11 detection
                if win_version == '10':
                    build = platform.version().split('.')
                    if len(build) >= 3 and int(build[2]) >= 22000:
                        return "Windows11"
                    else:
                        return "Windows10"

                # Earlier Windows versions
                win_versions = {
                    '7': 'Windows7',
                    '8': 'Windows8',
                    '8.1': 'Windows8.1',
                    '10': 'Windows10',
                    'Vista': 'WindowsVista',
                    'XP': 'WindowsXP'
                }

                return win_versions.get(win_version, f"Windows{win_version}")

            except:
                # Fallback
                try:
                    import winreg
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                        name = winreg.QueryValueEx(key, "ProductName")[0]
                        # Simplify to format like Windows10, Windows11, etc.
                        if '10' in name:
                            build = platform.version().split('.')
                            if len(build) >= 3 and int(build[2]) >= 22000:
                                return "Windows11"
                            return "Windows10"
                        elif '11' in name:
                            return "Windows11"
                        else:
                            # Remove spaces and non-alphanumeric chars
                            return re.sub(r'[^a-zA-Z0-9]', '', name.replace("Microsoft ", ""))
                except:
                    return "Windows"

        elif system == 'Linux':
            try:
                # Try to get distribution name from /etc/os-release
                if os.path.exists('/etc/os-release'):
                    with open('/etc/os-release', 'r') as f:
                        lines = f.readlines()
                        for line in lines:
                            if line.startswith('ID='):
                                distro = line.split('=')[1].strip().strip('"')
                                return distro[0].upper() + distro[1:] if distro else "Linux"
                try:
                    distro = subprocess.check_output(['lsb_release', '-is']).decode().strip()
                    return distro
                except:
                    pass
            except:
                pass

            return "Linux"

        return system  # Default fallback to platform.system()

    @staticmethod
    def get_system_info():
        is_64bit = platform.machine().endswith('64')
        if not is_64bit:
            is_64bit = platform.architecture()[0] == '64bit'

        system = platform.system()  # Windows, Darwin (macOS), or Linux
        if system == 'Darwin':
            system = 'macOS'

        # Get version info - with special handling for macOS
        if system == 'macOS':
            try:
                version = subprocess.check_output(['sw_vers', '-productVersion']).decode().strip()
                build = subprocess.check_output(['sw_vers', '-buildVersion']).decode().strip()
                version_string = f"{system} {version} ({build})"
            except:
                version = platform.release()
                version_string = f"{system} {version}"
        else:
            version = platform.release()
            version_string = f"{system} {version}"

        system_info = {
            "Is64Bit": is_64bit,
            "MachineName": socket.gethostname(),
            "Name": PedmAgentInventoryBasicCommand.get_os_name(),
            "OsType": version_string,
            "Platform": system,
            "Version": version,
            "VersionString": version_string
        }

        return system_info

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = context.pedm_agent_plugin
        if not agent:
            raise base.CommandError('KEPM Agent is not connected')
        assert isinstance(agent.hash_key, bytes)

        system_info = PedmAgentInventoryBasicCommand.get_system_info()
        hostname = kwargs.get('hostname')
        if isinstance(hostname, str) and len(hostname) > 0:
            system_info['MachineName'] = hostname

        resource_uid, resource_data = PedmCollectionMixin.extract_collection_data(
            agent, pedm_shared.CollectionType.OsBuild, system_info)

        existing_collections: Dict[int, Set[str]] = {}
        done = False
        from_resource_uid: Optional[str] = None
        while not done:
            res_rq = {
                'resource_type': [pedm_shared.CollectionType.OsBuild],
                'from_resource_uid': from_resource_uid
            }
            res_rs = agent.execute_rest('get_resources', res_rq)
            assert res_rs is not None
            done = not (res_rs.get('has_more') is True)
            if not done:
                from_resource_uid = res_rs.get('next_resource_uid')
                if not from_resource_uid:
                    done = True
            resources = res_rs.get('resources')
            if isinstance(resources, list):
                for resource in resources:
                    resource_uid = resource.get('resource_uid')
                    resource_type = resource.get('resource_type')
                    if isinstance(resource_type, int) and resource_uid:
                        if resource_type not in existing_collections:
                            existing_collections[resource_type] = set()
                        existing_collections[resource_type].add(resource_uid)

        existing_uids = existing_collections.get(pedm_shared.CollectionType.OsBuild)

        coll_rq: Dict[str, Any] = {
            'add_collection': []
        }

        if existing_uids is None or resource_uid not in existing_uids:
            coll_rq['add_collection'].append({
                'collection_uid': resource_uid,
                'collection_type': pedm_shared.CollectionType.OsBuild,
                'collection_data': utils.base64_url_encode(resource_data)
            })
            agent_data = json.dumps(system_info).encode('utf-8')
            agent_data = crypto.encrypt_aes_v2(agent_data, agent.hash_key)
            coll_rq['add_agent_collections'] = [{
                'collection_uid': resource_uid,
                'collection_type': pedm_shared.CollectionType.OsBuild,
                'agent_data': utils.base64_url_encode(agent_data)
            }]


        group_uid, group_data = PedmCollectionMixin.extract_collection_data(
            agent, pedm_shared.CollectionType.OsVersion, system_info)
        coll_rq['add_collection'].append({
            'collection_uid': group_uid,
            'collection_type': pedm_shared.CollectionType.OsVersion,
            'collection_data': utils.base64_url_encode(group_data)
        })

        if existing_uids is not None:
            existing_uids.remove(resource_uid)
            if not existing_uids:
                coll_rq['remove_agent_collections'] = list(existing_uids)
        coll_rq['connect_agent_collections'] = [{
            'parent_collection_uid': group_uid,
            'child_collection_uid': [resource_uid]
        }]

        coll_rs = agent.execute_rest('modify_collection', coll_rq)
        assert isinstance(coll_rs, dict)
        failed_collections = coll_rs.get('failed_collections')
        if isinstance(failed_collections, list):
            logger = api.get_logger()
            for fc in failed_collections:
                logger.warning(fc.get('message'))


class PedmAgentCollectionCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('KEPM Agent collections')
        self.register_command(PedmAgentCollectionListCommand(), 'list', 'l')
        self.register_command(PedmAgentCollectionSyncCommand(), 'sync')
        self.register_command(PedmAgentCollectionAddCommand(), 'add', 'a')
        # self.register_command(PedmAgentCollectionAddInventoryCommand(), 'add-inventory')
        # self.register_command(PedmAgentCollectionLinkCommand(), 'link')
        self.register_command(PedmAgentCollectionShowLinkCommand(), 'show-link')
        self.register_command(PedmAgentCollectionSnapshotCommand(), 'snapshot')
        self.default_verb = 'list'

class PedmAgentCollectionListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='list', parents=[base.report_output_parser],
                                         description='List local collection cache')
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                            help='print verbose information')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = context.pedm_agent_plugin
        if not agent:
            raise base.CommandError('KEPM Agent is not connected')
        assert isinstance(agent.hash_key, bytes)

        verbose = kwargs.get('verbose') is True
        headers = ['collection_uid', 'collection_type', 'collection_value']

        table = []
        for inventory in agent.storage.collections.get_all_entities():
            c_type = pedm_shared.collection_type_to_name(inventory.collection_type)
            try:
                agent_data = json.loads(inventory.data)
            except Exception as e:
                utils.get_logger().debug('Failed to decrypt collection data: %s', e)
                agent_data = None
            agent_info: Any
            if isinstance(agent_data, dict):
                agent_info = [f'{k}={v}' for k, v in agent_data.items()]
            elif isinstance(agent_data, str):
                agent_info = agent_data
            elif agent_data:
                agent_info = str(agent_data)
            else:
                agent_info = None

            row = [inventory.collection_uid, f'{c_type} ({inventory.collection_type})', agent_info]
            table.append(row)

        fmt = kwargs.get('format')
        column_width = None if verbose else 40
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers=headers, sort_by=1, column_width=column_width,
                                             fmt=fmt, filename=kwargs.get('output'))


class PedmAgentCollectionSyncCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='sync', description='Load agent''s collections')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = context.pedm_agent_plugin
        if not agent:
            raise base.CommandError('KEPM Agent is not connected')

        agent.load_agent_collections()



# class PedmAgentCollectionAddInventoryCommand(base.ArgparseCommand):
#     def __init__(self):
#         parser = argparse.ArgumentParser(prog='add-inventory', description='Add executable to the inventory collection')
#         parser.add_argument('files', nargs='+', metavar='FILENAME', help='List of local files')
#         super().__init__(parser)
#
#     def execute(self, context: KeeperParams, **kwargs) -> Any:
#         if kwargs.get('show_syntax'):
#             print(collection_syntax)
#             return
#         agent = context.pedm_agent_plugin
#         if not agent:
#             raise base.CommandError('PEDM Agent is not connected')
#         assert agent.hash_key is not None
#
#         files = kwargs.get('files')
#         if not isinstance(files, list):
#             files = [files]
#
#         rq: Dict[str, Any] = {
#             'add_collection': [],
#             'add_agent_collections': []
#         }
#         for filepath in files:
#             if not isinstance(filepath, str):
#                 continue
#             filepath = os.path.expanduser(filepath)
#             filepath = os.path.abspath(filepath)
#
#             if not os.path.isfile(filepath):
#                 raise base.CommandError(f'File not found: {filepath}')
#
#             with open(filepath, "rb") as f:
#                 file_hash = hashlib.sha256(f.read()).hexdigest().upper()
#             file_name = os.path.basename(filepath)
#             mod_time = int(os.path.getmtime(filepath))
#             file_version = datetime.datetime.fromtimestamp(mod_time).isoformat()
#             file_info = {
#                 'FileHash': file_hash,
#                 'ProductName': file_name,
#                 'ProductVersion': file_version,
#             }
#             encrypted_collection_data = crypto.encrypt_aes_v2(json.dumps(file_info).encode('utf-8'), agent.hash_key)
#             file_uid = agent.get_collection_value_hash(pedm_shared.CollectionType.Application, file_hash)
#             rq['add_collection'].append({
#                 'collection_uid': file_uid,
#                 'collection_type': pedm_shared.CollectionType.Application,
#                 'collection_data': utils.base64_url_encode(encrypted_collection_data),
#             })
#             rq['add_agent_collections'].append({
#                 'collection_uid': file_uid,
#                 'agent_data': utils.base64_url_encode(encrypted_collection_data),
#             })
#
#         rs = agent.execute_rest('modify_collection', rq)
#         if isinstance(rs, dict):
#             if 'failed_values' in rs:
#                 logger = utils.get_logger()
#                 for fv in rs['failed_values']:
#                     logger.warning('Collection UID "%s": %s', fv.get('collection_uid'), fv.get('message'))


@attrs.define(frozen=True, kw_only=True)
class InventoryRequiredFields:
    key_fields: Optional[List[str]]
    all_fields: List[str]

class PedmCollectionMixin:
    OS_FIELDS: InventoryRequiredFields = InventoryRequiredFields(
        all_fields=['Name', 'Version'], key_fields=None)
    APPLICATION_FIELDS: InventoryRequiredFields = InventoryRequiredFields(
        all_fields=['FileHash', 'ProductName', 'ProductVersion'], key_fields=['FileHash'])
    USER_ACCOUNT_FIELDS: InventoryRequiredFields = InventoryRequiredFields(
        all_fields=['Domainname', 'Username', 'AccountType'], key_fields=None)
    GROUP_ACCOUNT_FIELDS: InventoryRequiredFields = InventoryRequiredFields(
        all_fields=['GroupName'], key_fields=None)
    OS_VERSION_FIELDS: InventoryRequiredFields = InventoryRequiredFields(
        all_fields=['Name'], key_fields=None)

    @staticmethod
    def collection_name_to_type(collection_name: str) -> pedm_shared.CollectionType:
        if collection_name.lower() == 'os':
            return pedm_shared.CollectionType.OsBuild
        if collection_name.lower() == 'application':
            return pedm_shared.CollectionType.Application
        if collection_name.lower() == 'account':
            return pedm_shared.CollectionType.UserAccount
        if collection_name.lower() == 'app_name':
            return pedm_shared.CollectionType.ApplicationName
        if collection_name.lower() == 'groups':
            return pedm_shared.CollectionType.GroupAccount
        return pedm_shared.CollectionType.Other

    @staticmethod
    def get_required_fields(resource_type: pedm_shared.CollectionType) -> Optional[InventoryRequiredFields]:
        if resource_type == pedm_shared.CollectionType.OsBuild:
            return PedmAgentCollectionAddCommand.OS_FIELDS
        elif resource_type == pedm_shared.CollectionType.Application:
            return PedmAgentCollectionAddCommand.APPLICATION_FIELDS
        elif resource_type == pedm_shared.CollectionType.UserAccount:
            return PedmAgentCollectionAddCommand.USER_ACCOUNT_FIELDS
        elif resource_type == pedm_shared.CollectionType.GroupAccount:
            return PedmAgentCollectionAddCommand.GROUP_ACCOUNT_FIELDS
        elif resource_type == pedm_shared.CollectionType.OsVersion:
            return PedmAgentCollectionAddCommand.OS_VERSION_FIELDS
        return None

    @staticmethod
    def show_field_information() -> None:
        table = []
        headers = ['resource_type', 'resource_fields', 'key_fields']
        for resource_type in pedm_shared.CollectionType:
            fields = PedmCollectionMixin.get_required_fields(resource_type)
            if fields:
                resource_name = pedm_shared.collection_type_to_name(resource_type)
                all_fields = ', '.join(fields.all_fields)
                key_fields = None
                if fields.key_fields:
                    key_fields = ', '.join(fields.key_fields)
                table.append([resource_name, all_fields, key_fields])
        headers = [report_utils.field_to_title(x) for x in headers]
        report_utils.dump_report_data(table, headers=headers)

    @staticmethod
    def extract_collection_data(
            agent: agent_plugin.PedmAgentPlugin,
            collection_type: pedm_shared.CollectionType,
            values: Dict[str, Any]) -> Tuple[str, bytes]:

        assert agent.hash_key
        required_fields = PedmCollectionMixin.get_required_fields(collection_type)
        assert required_fields is not None
        key = ''
        for key_field in required_fields.key_fields or required_fields.all_fields:
            if key_field not in values:
                raise base.CommandError(f'Collection {collection_type} should have field {key_field}')
            key_value = values[key_field]
            if not key_value:
                continue
            if not isinstance(key_value, str):
                key_value = str(key_value)
            key = key + key_value

        collection_data: Dict[str, Any] = {}
        for key_field in required_fields.all_fields:
            if key_field not in values:
                raise base.CommandError(f'Collection {collection_type} should have field {key_field}')
            collection_data[key_field] = values[key_field]

        collection_uid = agent.get_collection_value_hash(collection_type, key)
        encrypted_collection_data = crypto.encrypt_aes_v2(json.dumps(collection_data).encode('utf-8'), agent.hash_key)
        return collection_uid, encrypted_collection_data


class PedmAgentCollectionAddCommand(base.ArgparseCommand, PedmCollectionMixin):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='add', description='Add KEPM resource')
        parser.add_argument('--show-syntax', dest='show_syntax', action='store_true',
                            help='Show collection syntax')
        parser.add_argument('--type', choices=['os', 'application', 'account', 'group'],
                            help='Resource type')
        parser.add_argument('--skip-agent', action='store_true', help='Do not link agent to the resource')
        parser.add_argument('fields', nargs='*', metavar='NAME:VALUE', help='Resource fields')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        if kwargs.get('show_syntax'):
            PedmCollectionMixin.show_field_information()
            return

        agent = context.pedm_agent_plugin
        if not agent:
            raise base.CommandError('KEPM Agent is not connected')
        assert agent.hash_key is not None

        skip_agent = kwargs.get('skip_agent') is True

        ct: Any = kwargs.get('type')
        if not ct:
            raise base.CommandError(f'Resource type argument is required')

        resource_type = PedmCollectionMixin.collection_name_to_type(ct)
        required_fields = PedmCollectionMixin.get_required_fields(resource_type)
        if required_fields is None:
            raise base.CommandError(f'Resource type {ct} is not supported')

        fields = kwargs.get('fields')
        collection: Dict[str, str] = {}
        if isinstance(fields, list):
            for field in fields:
                name, sep, value = field.partition('=')
                if not value:
                    raise base.CommandError(f'Invalid collection field {field}: NAME:VALUE is expected')
                collection[name.strip()] = value.strip()

        key = ''
        for key_field in required_fields.key_fields or required_fields.all_fields:
            if key_field not in collection:
                raise base.CommandError(f'Collection {ct} should have field {key_field}')
            key_value = collection[key_field]
            key = key + key_value

        collection_data: Dict[str, str] = {}
        for key_field in required_fields.all_fields:
            if key_field not in collection:
                raise base.CommandError(f'Collection {ct} should have field {key_field}')
            collection_data[key_field] = collection[key_field]

        collection_uid = agent.get_collection_value_hash(resource_type, key)
        encrypted_collection_data = crypto.encrypt_aes_v2(json.dumps(collection_data).encode('utf-8'), agent.hash_key)
        encrypted_agent_data = crypto.encrypt_aes_v2(json.dumps(collection).encode('utf-8'), agent.hash_key)
        rq = {
            'add_collection': [{
                'collection_uid': collection_uid,
                'collection_type': resource_type,
                'collection_data': utils.base64_url_encode(encrypted_collection_data),
            }]
        }
        if not skip_agent:
            rq['add_agent_collections'] = [{
                'collection_uid': collection_uid,
                'agent_data': utils.base64_url_encode(encrypted_agent_data),
            }]

        rs = agent.execute_rest('modify_collection', rq)
        if isinstance(rs, dict):
            if 'failed_values' in rs:
                logger = utils.get_logger()
                for fv in rs['failed_values']:
                    logger.warning('Collection UID "%s": %s', fv.get('collection_uid'), fv.get('message'))


class PedmAgentCollectionShowLinkCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='show-link', parents=[base.report_output_parser],
                                         description='Show collection resource links')
        parser.add_argument('collection', nargs='+', help='Agent collection UIDs')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = context.pedm_agent_plugin
        if not agent:
            raise base.CommandError('KEPM Agent is not connected')

        collections = kwargs.get('collection')
        if isinstance(collections, str):
            collections = [collections]

        rq = {
            'collection_uid': collections
        }
        rs = agent.execute_rest('get_collection_links', rq)
        assert isinstance(rs, dict)
        table = []
        headers = ['collection_uid', 'resources']

        collection_members = rs.get('collections')
        if isinstance(collection_members, list):
            for collection_member in collection_members:
                collection_uid = collection_member.get('collection_uid')
                resources = collection_member.get('resources')
                if collection_uid:
                    table.append([collection_uid, resources])

        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))

"""
class PedmAgentCollectionLinkCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='link', description='Link agent collection to group collection')
        parser.add_argument('-c', '--group_collection', required=True, help='Group collection UID')
        parser.add_argument('agent_collection', nargs='+', help='Agent collection UIDs')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = context.pedm_agent_plugin
        if not agent:
            raise base.CommandError('PEDM Agent is not connected')

        group_collection = kwargs.get('group_collection')
        if not group_collection:
            raise base.CommandError('Group Collection cannot be empty')

        rq = {
            "link_agent_collections": [{
                'parent_collection_uid': group_collection,
                'child_collection_uid': kwargs.get('agent_collection')
            }]
        }
        rs = agent.execute_rest('modify_collection', rq)
"""

class PedmAgentCollectionSnapshotCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='snapshot', description='Assign collection snapshot')
        parser.add_argument('--show-syntax', dest='show_syntax', action='store_true',
                            help='Show collection syntax')
        parser.add_argument('file', help='JSON file that contains a list of collection values')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        if kwargs.get('show_syntax'):
            PedmCollectionMixin.show_field_information()
            return

        agent = context.pedm_agent_plugin
        if not agent:
            raise base.CommandError('KEPM Agent is not connected')
        assert agent.hash_key is not None

        file_name: Any = kwargs.get('file')
        with open(file_name, 'r') as f:
            collections = json.load(f)
            if not isinstance(collections, dict):
                raise base.CommandError(f'File {file_name} should contain a JSON object')

        collection_types: List[int] = []
        for ct in collections.keys():
            collection_type: Any = PedmCollectionMixin.collection_name_to_type(ct)
            if collection_type != pedm_shared.CollectionType.Other:
                collection_types.append(collection_type)

        if len(collection_types) == 0:
            raise base.CommandError(f'File {file_name} does not contain supported collections')

        existing_collections: Dict[int, Set[str]] = {}
        done = False
        from_resource_uid: Optional[str] = None
        while not done:
            res_rq = {
                'from_resource_uid': from_resource_uid
            }
            res_rs = agent.execute_rest('get_resources', res_rq)
            assert res_rs is not None
            done = not (res_rs.get('has_more') is True)
            if not done:
                from_resource_uid = res_rs.get('next_resource_uid')
                if not from_resource_uid:
                    done = True
            resources = res_rs.get('resources')
            if isinstance(resources, list):
                for resource in resources:
                    resource_uid = resource.get('resource_uid')
                    resource_type = resource.get('resource_type')
                    if isinstance(resource_type, int) and resource_uid:
                        if resource_type not in existing_collections:
                            existing_collections[resource_type] = set()
                        existing_collections[resource_type].add(resource_uid)

        add_collections: List[Dict[str, Any]] = []
        add_agent_data: List[Dict[str, Any]] = []
        remove_agent_data: List[str] = []
        for ct, cv in collections.items():
            collection_type = PedmCollectionMixin.collection_name_to_type(ct)
            if collection_type == pedm_shared.CollectionType.Other:
                continue

            key_fields = PedmCollectionMixin.get_required_fields(collection_type)
            if not key_fields:
                continue

            if not isinstance(cv, list):
                raise base.CommandError(f'Collection {ct} should be an array of objects')

            existing_uids = existing_collections.get(collection_type, set())
            collection: Dict[str, Any]

            # collection_links_name = ''
            # collection_links_type = pedm_shared.CollectionType.Other
            # collection_link_fields: Optional[List[str]] = None
            #
            # if collection_type == pedm_shared.CollectionType.GroupAccount:
            #     collection_links_type = pedm_shared.CollectionType.UserAccount
            #     collection_link_fields = get_required_fields(collection_links_type)
            #     if collection_link_fields:
            #         collection_links_name = 'UserAccounts'

            for collection in cv:
                key = ''
                for key_field in key_fields.key_fields or key_fields.all_fields:
                    if key_field not in collection:
                        raise base.CommandError(f'Collection {ct} should have field {key_field}')
                    key_value = collection[key_field]
                    key = key + key_value

                collection_data: Dict[str, str] = {}
                for key_field in key_fields.all_fields:
                    if key_field not in collection:
                        raise base.CommandError(f'Collection {ct} should have field {key_field}')
                    collection_data[key_field] = collection[key_field]

                collection_uid = agent.get_collection_value_hash(collection_type, key)
                encrypted_collection_data = crypto.encrypt_aes_v2(json.dumps(collection_data).encode('utf-8'), agent.hash_key)
                """
                if collection_links_name and collection_links_name in collection:
                    collection_links = collection.pop(collection_links_name)
                    link_required_fields = get_required_fields(collection_links_type)
                    if not link_required_fields:
                        raise base.CommandError(f'Collection {ct} link {collection_links_name} type cannot be detected')
                    if isinstance(link_required_fields, list):
                        children: List[str] = []
                        for link in collection_links:
                            if isinstance(link, dict):
                                key = ''
                                for key_field in link_required_fields:
                                    if key_field not in link:
                                        raise base.CommandError(f'Collection {ct} link {collection_links_name} should have field {key_field}')
                                    key_value = link[key_field]
                                    key = key + key_value
                                link_uid = agent.get_collection_value_hash(collection_links_type, key)
                            elif isinstance(link, str):
                                link_uid = link
                            else:
                                raise base.CommandError(
                                    f'Collection {ct} link {collection_links_name} has invalid type: object or string expected')
                            children.append(link_uid)
                        link_agent_collections.append({
                            'parent_collection_uid': collection_uid,
                            'child_collection_uid': children,
                        })
                    else:
                        raise base.CommandError(f'Collection {ct} link {collection_links_name} invalid type: array expected')
                """

                encrypted_agent_data = crypto.encrypt_aes_v2(json.dumps(collection).encode('utf-8'), agent.hash_key)
                existing_uids.discard(collection_uid)
                add_collections.append({
                    'collection_uid': collection_uid,
                    'collection_type': collection_type,
                    'collection_data': utils.base64_url_encode(encrypted_collection_data),
                })
                add_agent_data.append({
                    'collection_uid': collection_uid,
                    'agent_data': utils.base64_url_encode(encrypted_agent_data),
                })

            if len(existing_uids) > 0:
                remove_agent_data.extend(existing_uids)

        coll_rq = {
            'add_collection': add_collections,
            'add_agent_collections': add_agent_data,
            'remove_agent_collections': remove_agent_data,
            #'connect_agent_collections': link_agent_collections,
        }

        coll_rs = agent.execute_rest('modify_collection', coll_rq)
        if isinstance(coll_rs, dict):
            if 'failed_values' in coll_rs:
                logger = utils.get_logger()
                for fv in coll_rs['failed_values']:
                    logger.warning('Collection UID "%s": %s', fv.get('collection_uid'), fv.get('message'))


class PedmAgentVerify2faCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='2fa', description='Verify 2FA code')
        parser.add_argument('--email', dest='email', help='Keeper account email')
        parser.add_argument('--code', dest='code', help='Verification code')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = context.pedm_agent_plugin
        if not agent:
            raise base.CommandError('KEPM Agent is not connected')
        email = kwargs.get('email')
        if not email:
            raise base.CommandError(f'"email" argument must not be empty')
        code = kwargs.get('code')
        if not code:
            raise base.CommandError(f'"code" argument must not be empty')

        rq = {
            'username': email,
            'code': code,
        }

        rs = agent.execute_rest('verify_2fa', rq)
        if isinstance(rs, dict):
            success = rs.get('success') is True
            get_logger().info(f'Verification code "{code}" is {success}')


class PedmAgentNotificationCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='notification', description='Notification listener')
        parser.add_argument('--active', dest='active', choices=['on', 'off'],
                            help='Notification ')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = context.pedm_agent_plugin
        if not agent:
            raise base.CommandError('KEPM Agent is not connected')

        active = kwargs.get('active') == 'on'
        if active:
            agent.start_notifications()
        else:
            agent.stop_notifications()


# Keychain entity types by CLI name; the value is the entityType of the KRouter routes api/agent/keychain/*
KEYCHAIN_ENTITY_TYPES = {'password': 'PASSWORD', 'approval': 'APPROVAL'}

# The entity types "keychain add" can store; a password always gets rows for the agent itself and the enterprise.
KEYCHAIN_ADD_ENTITY_TYPES = ['password']


def keychain_entity_type(kwargs: Dict[str, Any]) -> str:
    entity_type = kwargs.get('entity_type') or 'password'
    name = KEYCHAIN_ENTITY_TYPES.get(entity_type)
    if not name:
        raise base.CommandError(f'Entity type "{entity_type}" is not supported')
    return name


def aes_fingerprint(key: bytes) -> str:
    """HKDF-SHA256 with an empty salt and info "keychain key id", 8 bytes; see KRouter docs/Keychain/Keychain.md#fingerprints"""
    prk = hmac.new(bytes(32), key, hashlib.sha256).digest()
    return utils.base64_url_encode(hmac.new(prk, b'keychain key id\x01', hashlib.sha256).digest()[:8])


def keychain_agent(context: KeeperParams) -> agent_plugin.PedmAgentPlugin:
    agent = context.pedm_agent_plugin
    if not agent:
        raise base.CommandError('KEPM Agent is not connected')
    if not agent.is_registered:
        raise base.CommandError('KEPM agent is not registered')
    return agent


def keychain_request(agent: agent_plugin.PedmAgentPlugin, action: str, rq: Dict[str, Any]) -> Any:
    """Every request names the AGENT_KEY instance the agent holds, by its fingerprint."""
    assert agent.hash_key
    rq['agentKey'] = aes_fingerprint(agent.hash_key)
    return agent.execute_rest(f'keychain/{action}', rq)


class KeychainEntity:
    """An entity read with keychain/get: its AES key, opened along the path, and its data."""

    def __init__(self, rs: Dict[str, Any], key: bytes):
        self.rs = rs
        self.key = key

    @property
    def aes_fingerprint(self) -> str:
        return self.rs['path'][-1]['subject']['fingerprint']

    @property
    def data(self) -> Optional[Dict[str, Any]]:
        return self.rs.get('data')

    def decrypt_data(self) -> bytes:
        data = self.data
        if not data:
            return b''
        if data['aesFingerprint'] != self.aes_fingerprint:
            raise base.CommandError('The data is not encrypted by the key the path opened')
        return crypto.decrypt_aes_v2(utils.base64_url_decode(data['encryptedData']), self.key)


def keychain_get(agent: agent_plugin.PedmAgentPlugin, entity_type: str, uid: str) -> KeychainEntity:
    rs = keychain_request(agent, 'get', {'entityType': entity_type, 'uid': uid})
    if not isinstance(rs, dict):
        raise base.CommandError('Keychain returned no entity')
    if rs.get('stale'):
        raise base.CommandError('The agent only has an old key of this entity: its share was not renewed after a rotation')
    path = rs.get('path')
    if not isinstance(path, list) or len(path) == 0:
        raise base.CommandError('Keychain returned an empty path')
    return KeychainEntity(rs, keychain_open_path(agent, path))


def keychain_open_path(agent: agent_plugin.PedmAgentPlugin, path: List[Dict[str, Any]]) -> bytes:
    """Opens each step with the agent key, the agent's own ECC key, or a key opened by an earlier step."""
    assert agent.hash_key
    opened: Dict[Tuple[str, str, str, str], Any] = {}

    def instance(value: Dict[str, Any]) -> Tuple[str, str, str, str]:
        return value['entity']['type'], value['entity']['uid'], value['keyType'], value['fingerprint']

    key: Any = None
    for step in path:
        encrypted = utils.base64_url_decode(step['encrypted'])
        encryptor = instance(step['encryptor'])
        if encryptor in opened:
            opener = opened[encryptor]
        elif encryptor[0] == 'AGENT_KEY':
            opener = agent.hash_key
        elif encryptor[0] == 'AGENT' and encryptor[1] == agent.agent_uid:
            opener = agent.private_key
        else:
            raise base.CommandError(f'Cannot open a step encrypted by {encryptor}')
        plaintext = crypto.decrypt_ec(encrypted, opener) if encryptor[2] == 'ECC' else crypto.decrypt_aes_v2(encrypted, opener)
        subject = instance(step['subject'])
        if subject[2] == 'AES':
            if aes_fingerprint(plaintext) != subject[3]:
                raise base.CommandError(f'A step does not hold the key it names: {subject}')
            key = plaintext
        else:
            key = crypto.load_ec_private_key(plaintext)
        opened[subject] = key
    return key


class PedmAgentKeychainCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('KEPM Agent keychain')
        self.register_command(PedmAgentKeychainAddCommand(), 'add')
        self.register_command(PedmAgentKeychainGetCommand(), 'get')
        self.register_command(PedmAgentKeychainUpdateCommand(), 'update')
        self.register_command(PedmAgentKeychainListCommand(), 'list', 'l')
        self.register_command(PedmAgentKeychainRotateCommand(), 'rotate')


def keychain_load_data(text: str) -> bytes:
    if text.startswith('@'):
        file_name = os.path.expanduser(text[1:])
        if not os.path.isfile(file_name):
            raise base.CommandError(f'File "{file_name}" does not exist')
        with open(file_name, 'rb') as f:
            return f.read()
    return text.encode('utf-8')


class PedmAgentKeychainAddCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='add', description='Store data in the keychain, shared with the agent itself and the enterprise')
        parser.add_argument('--entity-type', dest='entity_type', action='store', choices=KEYCHAIN_ADD_ENTITY_TYPES,
                            default='password', help='Keychain entity type')
        parser.add_argument('--uid', dest='uid', action='store', help='Entity UID; generated when omitted')
        parser.add_argument('--label', dest='label', action='store', help='Plain text label')
        parser.add_argument('--all-agents', dest='all_agents', action='store_true', help='Share with the agent key')
        parser.add_argument('--agent', dest='agent', action='append', metavar='FILE',
                            help='Share with the agent of this agent configuration file')
        parser.add_argument('data', metavar='TEXT', help='Data to store, or @FILENAME to load it from a file')
        super().__init__(parser)

    @staticmethod
    def load_agent(file_name: str) -> Tuple[str, Any]:
        file_name = os.path.expanduser(file_name)
        if not os.path.isfile(file_name):
            raise base.CommandError(f'File "{file_name}" does not exist')
        with open(file_name, 'rt') as f:
            config = json.load(f)
        agent_uid = config.get('agent_uid')
        public_key = config.get('public_key')
        if not isinstance(agent_uid, str) or not isinstance(public_key, str):
            raise base.CommandError(f'File "{file_name}" has no agent_uid and public_key')
        return agent_uid, crypto.load_ec_public_key(utils.base64_url_decode(public_key))

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = keychain_agent(context)
        assert agent.hash_key
        assert agent.peer_public_key
        entity_type = keychain_entity_type(kwargs)
        data = keychain_load_data(kwargs.get('data') or '')
        uid = kwargs.get('uid') or utils.generate_uid()
        others = [self.load_agent(x) for x in (kwargs.get('agent') or [])]

        key = utils.generate_aes_key()

        def row(to: str, encrypted: bytes, row_uid: Optional[str] = None) -> Dict[str, Any]:
            value: Dict[str, Any] = {'to': to, 'encryptedKey': utils.base64_url_encode(encrypted)}
            if row_uid:
                value['uid'] = row_uid
            return value

        rows = [
            row('AGENT', crypto.encrypt_ec(key, agent.public_key), agent.agent_uid),
            row('ENTERPRISE', crypto.encrypt_ec(key, agent.peer_public_key)),
        ]
        if kwargs.get('all_agents') is True:
            rows.append(row('AGENT_KEY', crypto.encrypt_aes_v2(key, agent.hash_key)))
        for other_uid, other_key in others:
            if other_uid != agent.agent_uid:
                rows.append(row('AGENT', crypto.encrypt_ec(key, other_key), other_uid))
        encrypted_data = crypto.encrypt_aes_v2(data, key)
        rq: Dict[str, Any] = {
            'entityType': entity_type, 'uid': uid, 'aesFingerprint': aes_fingerprint(key), 'rows': rows,
            'encryptedData': utils.base64_url_encode(encrypted_data)
        }
        label = kwargs.get('label')
        if label:
            rq['label'] = label
        keychain_request(agent, 'add', rq)
        return f'UID: {uid}'


class PedmAgentKeychainGetCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='get', description='Read data from the keychain')
        parser.add_argument('--entity-type', dest='entity_type', action='store', choices=list(KEYCHAIN_ENTITY_TYPES.keys()),
                            default='password', help='Keychain entity type')
        parser.add_argument('--output', dest='output', action='store', metavar='FILE', help='Write the data to this file')
        parser.add_argument('uid', metavar='UID', help='Entity UID')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = keychain_agent(context)
        entity = keychain_get(agent, keychain_entity_type(kwargs), kwargs['uid'])
        rs = entity.rs
        owner = rs.get('owner') or {}
        prompt_utils.output_text(f'Owner: {owner.get("type")} {owner.get("uid")}  Permission: {rs.get("permission")}')
        if rs.get('label'):
            prompt_utils.output_text(f'Label: {rs["label"]}')
        if not entity.data:
            return 'No data'
        data = entity.decrypt_data()
        prompt_utils.output_text(f'Version: {entity.data.get("version")}')

        output = kwargs.get('output')
        if output:
            with open(os.path.expanduser(output), 'wb') as f:
                f.write(data)
            return f'{len(data)} bytes written to {output}'
        # UTF-8 text is printed as is; anything else as web-safe base64.
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return utils.base64_url_encode(data)


class PedmAgentKeychainUpdateCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='update', description='Replace the data of a keychain entity')
        parser.add_argument('--entity-type', dest='entity_type', action='store', choices=list(KEYCHAIN_ENTITY_TYPES.keys()),
                            default='password', help='Keychain entity type')
        parser.add_argument('uid', metavar='UID', help='Entity UID')
        parser.add_argument('data', metavar='TEXT', help='New data, or @FILENAME to load it from a file')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = keychain_agent(context)
        entity_type = keychain_entity_type(kwargs)
        entity = keychain_get(agent, entity_type, kwargs['uid'])
        version = entity.data.get('version', 0) if entity.data else 0
        data = keychain_load_data(kwargs.get('data') or '')
        encrypted = crypto.encrypt_aes_v2(data, entity.key)
        rq = {'entityType': entity_type, 'uid': kwargs['uid'], 'expectedVersion': version,
              'aesFingerprint': entity.aes_fingerprint, 'encryptedData': utils.base64_url_encode(encrypted)}
        rs = keychain_request(agent, 'update', rq)
        return f'Version: {rs.get("version") if isinstance(rs, dict) else "?"}'


class PedmAgentKeychainRotateCommand(base.ArgparseCommand):
    """Replaces the AES key of an entity the agent manages; see KRouter docs/Keychain/Keychain.md#rotation"""

    def __init__(self):
        parser = argparse.ArgumentParser(prog='rotate', description='Replace the key of a keychain entity the agent manages')
        parser.add_argument('--entity-type', dest='entity_type', action='store', choices=list(KEYCHAIN_ENTITY_TYPES.keys()),
                            default='password', help='Keychain entity type')
        parser.add_argument('--drop-foreign', dest='drop_foreign', action='store_true',
                            help='Drop the grants the agent cannot re-encrypt; by default their holders keep only the old key')
        parser.add_argument('--drop-agent', dest='drop_agent', action='append', metavar='AGENT_UID',
                            help='Cut this agent off instead of re-encrypting the key for it')
        parser.add_argument('--dry-run', dest='dry_run', action='store_true', help='Show what the rotation would touch and stop')
        parser.add_argument('uid', metavar='UID', help='Entity UID')
        super().__init__(parser)

    @staticmethod
    def list_grants(agent: agent_plugin.PedmAgentPlugin, entity_type: str, uid: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int]:
        """All pages of keychain/grants: the grants, the foreign grants, and the time of the first page."""
        grants: List[Dict[str, Any]] = []
        foreign: List[Dict[str, Any]] = []
        listed_at: Optional[int] = None
        start_after: Optional[str] = None
        while True:
            rq: Dict[str, Any] = {'entityType': entity_type, 'uid': uid}
            if start_after:
                rq['startAfter'] = start_after
            rs = keychain_request(agent, 'grants', rq)
            if not isinstance(rs, dict):
                raise base.CommandError('Keychain returned no grants')
            if listed_at is None:
                listed_at = rs['listedAt']
            grants.extend(rs.get('grants') or [])
            foreign.extend(rs.get('foreign') or [])
            start_after = rs.get('next')
            if not start_after:
                break
        assert listed_at is not None
        return grants, foreign, listed_at

    @staticmethod
    def encrypt_for(agent: agent_plugin.PedmAgentPlugin, grant: Dict[str, Any], key: bytes) -> Optional[bytes]:
        """The new key encrypted for the grant's encryptor, or None when the agent cannot do it."""
        assert agent.hash_key
        encryptor = grant['encryptor']
        if encryptor['keyType'] == 'AES':
            if encryptor['entity']['type'] == 'AGENT_KEY' and encryptor['fingerprint'] == aes_fingerprint(agent.hash_key):
                return crypto.encrypt_aes_v2(key, agent.hash_key)
            return None
        public_key = grant.get('publicKey')
        if not public_key:
            return None
        return crypto.encrypt_ec(key, crypto.load_ec_public_key(utils.base64_url_decode(public_key)))

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = keychain_agent(context)
        entity_type = keychain_entity_type(kwargs)
        uid = kwargs['uid']
        entity = keychain_get(agent, entity_type, uid)
        if entity.rs.get('permission') != 'MANAGE':
            raise base.CommandError('The agent does not manage this entity')

        stats = keychain_request(agent, 'stats', {'entityType': entity_type, 'uid': uid})
        if not isinstance(stats, dict):
            raise base.CommandError('Keychain returned no statistics')
        prompt_utils.output_text(f'Shares: {stats.get("shares")} ({stats.get("convertible")} the agent can re-encrypt, '
                                 f'{stats.get("notConvertible")} it cannot)  Children: {stats.get("children")}  '
                                 f'Instances: {stats.get("instances")}/{stats.get("maxInstances")}')
        blockers = stats.get('blockers') or []
        if blockers:
            raise base.CommandError(f'The key cannot be rotated now: {", ".join(blockers)}')

        grants, foreign, listed_at = self.list_grants(agent, entity_type, uid)
        dropped_agents = set(kwargs.get('drop_agent') or [])
        new_key = utils.generate_aes_key()
        converted: List[Dict[str, Any]] = []
        dropped: List[str] = []
        ignored = 0
        # Only the share grants of the current key move; grants of older keys stay with their stale holders.
        for grant in grants:
            if grant['kind'] != 'SHARE' or not grant['subjectCurrent']:
                continue
            encryptor = grant['encryptor']
            if encryptor['entity']['type'] == 'AGENT' and encryptor['entity']['uid'] in dropped_agents:
                if encryptor['entity']['uid'] == agent.agent_uid:
                    raise base.CommandError('The agent cannot drop its own grant')
                dropped.append(grant['token'])
                continue
            encrypted = self.encrypt_for(agent, grant, new_key)
            if encrypted is None:
                ignored += 1
                continue
            converted.append({'grant': grant['token'], 'encryptor': encryptor, 'encryptedKey': utils.base64_url_encode(encrypted)})
        foreign_current = [x for x in foreign if x['subjectCurrent']]
        drop_foreign = kwargs.get('drop_foreign') is True
        if kwargs.get('dry_run') is True:
            prompt_utils.output_text(f'Would re-encrypt {len(converted)} grants, drop {len(dropped)}, leave {ignored} stale, '
                                     f'and {"drop" if drop_foreign else "leave stale"} {len(foreign_current)} the agent cannot open')
            return None

        rq: Dict[str, Any] = {
            'entityType': entity_type, 'uid': uid,
            'expectedFingerprint': entity.aes_fingerprint, 'newFingerprint': aes_fingerprint(new_key),
            'defaultAction': 'DROP' if drop_foreign else 'IGNORE',
            'converted': converted, 'dropped': dropped,
        }
        if drop_foreign:
            rq['listedAt'] = listed_at
        if entity.data:
            rq['expectedDataVersion'] = entity.data.get('version')
            rq['encryptedData'] = utils.base64_url_encode(crypto.encrypt_aes_v2(entity.decrypt_data(), new_key))
        # Children stay under the old key; the self grant, the old key encrypted by the new one, keeps them reachable.
        if (stats.get('children') or 0) > 0:
            rq['selfGrant'] = utils.base64_url_encode(crypto.encrypt_aes_v2(entity.key, new_key))
        keychain_request(agent, 'rotate', rq)
        return (f'Rotated: {len(converted)} grants re-encrypted, {len(dropped)} dropped, '
                f'{len(foreign_current) if drop_foreign else 0} foreign dropped, {ignored + (0 if drop_foreign else len(foreign_current))} left stale')


class PedmAgentKeychainListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='list', description='List the keychain entities the agent can open',
                                         parents=[base.report_output_parser])
        parser.add_argument('--entity-type', dest='entity_type', action='store', choices=list(KEYCHAIN_ENTITY_TYPES.keys()),
                            help='Keychain entity type at any depth; without it, the entities directly under the agent keys')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = keychain_agent(context)
        entities: List[Dict[str, Any]] = []
        if kwargs.get('entity_type'):
            rs = keychain_request(agent, 'list', {'entityType': keychain_entity_type(kwargs)})
            if isinstance(rs, dict):
                entities.extend(rs.get('entities') or [])
        else:
            start_after: Optional[str] = None
            while True:
                rq: Dict[str, Any] = {} if start_after is None else {'startAfter': start_after}
                rs = keychain_request(agent, 'list', rq)
                if not isinstance(rs, dict):
                    break
                entities.extend(rs.get('entities') or [])
                start_after = rs.get('next')
                if not start_after:
                    break

        table = []
        for e in entities:
            owner = e.get('owner') or {}
            table.append([e['entity']['type'], e['entity']['uid'], e.get('label') or '', f'{owner.get("type", "")} {owner.get("uid", "")}'.strip(),
                          e.get('permission') or '', bool(e.get('stale'))])
        table.sort(key=lambda r: (r[0], r[2], r[1]))
        headers = ['entity_type', 'uid', 'label', 'owner', 'permission', 'stale']
        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))
