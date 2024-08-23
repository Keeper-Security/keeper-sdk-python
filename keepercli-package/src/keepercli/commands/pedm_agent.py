import argparse
import base64
import json
import os
from typing import Optional, Any

from keepersdk.plugins.pedm import agent_plugin
from . import base
from ..helpers import report_utils
from ..params import KeeperParams


class PedmAgentCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('PEDM Agent commands')
        self.register_command(PedmAgentConnectCommand(), 'connect')
        self.register_command(PedmAgentDisconnectCommand(), 'disconnect')
        self.register_command(PedmAgentSyncDownCommand(), 'sync-down')
        self.register_command(PedmAgentPolicyCommand(), 'policy', 'p')


class PedmAgentPolicyCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('PEDM Agent policies')
        self.register_command(PedmAgentPolicyListCommand(), 'list', 'l')
        self.register_command(PedmAgentPolicyViewCommand(), 'view', 'v')


class PedmAgentConnectCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='connect', description='Connect a PEDM agent')
        parser.add_argument('config', help='Config file name')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        if context.pedm_agent_plugin is not None:
            raise base.CommandError('PEDM Agent connection already exists. Use "disconnect" first')
        assert context.auth

        file_name: Optional[str] = kwargs['config']
        if file_name is None:
            raise base.CommandError(f'"config" argument must not be empty')

        file_name = os.path.expanduser(file_name)
        if not os.path.isfile(file_name):
            raise ValueError(f'File {file_name} does not exist')

        with open(file_name, 'r') as f:
            content = f.read()
            parts = os.path.splitext(file_name)
            if parts[1] == '.b64':
                content = base64.b64decode(content).decode('utf-8')
            config = json.loads(content)

        ksm_config = agent_plugin.KsmConfiguration.parse(config)
        agent = agent_plugin.PedmAgentPlugin(ksm_config)
        agent.connect()
        context.pedm_agent_plugin = agent


class PedmAgentDisconnectCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='disconnect', description='Disconnect a PEDM agent')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        context.pedm_agent_plugin = None


class PedmAgentSyncDownCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='sync-down', description='Sync down policies')
        parser.add_argument('--reload', dest='reload', action='store_true', help='Perform full sync')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        agent = context.pedm_agent_plugin
        assert agent

        agent.sync_down(reload=kwargs.get('reload') is True)


class PedmAgentPolicyListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='list', description='List PEDM policies', parents=[base.report_output_parser])
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = context.pedm_agent_plugin
        assert agent

        table = [[x.policy_uid, x.name] for x in agent.policies.get_all_entities()]
        headers = ['policy_uid', 'policy_name']

        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers=headers)


class PedmAgentPolicyViewCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='view', description='View PEDM policy', parents=[base.json_output_parser])
        parser.add_argument('policy', help='Policy UID or name')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        agent = context.pedm_agent_plugin
        assert agent
        policy_name: Optional[str] = kwargs.get('policy')
        if not policy_name:
            raise base.CommandError(f'"policy" argument must not be empty')
        l_name = policy_name.lower()
        policies = [x for x in agent.policies.get_all_entities() if x.policy_uid == policy_name or x.name.lower() == l_name]
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
