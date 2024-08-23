import argparse
import copy
import datetime
import json
import os
from collections import OrderedDict
from typing import Dict, Tuple, Any, List, Set, Optional, Union

from asciitree import LeftAligned

from keepersdk import utils
from keepersdk.plugins.pedm import pedm_types, pedm_plugin
from keepersdk.storage import dag
from . import base
from ..helpers import report_utils
from ..params import KeeperParams


class PedmUtils:
    @staticmethod
    def resolve_single_agent(pedm: pedm_plugin.PedmPlugin, agent_name: Any) -> pedm_types.PedmAgent:
        if not isinstance(agent_name, str):
            raise base.CommandError(f'Invalid agent_name: {agent_name}')

        agent = pedm.agents.get_entity(agent_name)
        if agent:
            return agent

        l_agent_name = agent_name.lower()
        agents = [x for x in pedm.agents.get_all_entities() if x.agent_name.lower() == l_agent_name]
        if len(agents) == 0:
            raise base.CommandError(f'Agent \"{agent_name}\" does not exist')
        if len(agents) > 2:
            raise base.CommandError(f'Agent name \"{agent_name}\" is not unique. Please use Agent UID')

        return agents[0]

    @staticmethod
    def get_unit_path(pedm: pedm_plugin.PedmPlugin, unit_uid: str) -> str:
        components: List[str] = []
        unit = pedm.units.get_entity(unit_uid)
        while unit is not None:
            name = unit.data.get('displayname') or unit.ou_uid
            components.append(name)
            unit_uid = unit.parent_ou_uid
            unit = pedm.units.get_entity(unit_uid)
        components.reverse()
        return '/'.join(components)

    @staticmethod
    def get_unit_name_lookup(pedm: pedm_plugin.PedmPlugin) -> Dict[str, Union[pedm_types.PedmOrganizationUnit, List[pedm_types.PedmOrganizationUnit]]]:
        unit_lookup: Dict[str, Union[pedm_types.PedmOrganizationUnit, List[pedm_types.PedmOrganizationUnit]]] = {}

        for unit in pedm.units.get_all_entities():
            unit_lookup[str(unit.ou_uid)] = unit
            unit_name = unit.data.get('displayname')
            if unit_name:
                unit_name = unit_name.lower()
                u = unit_lookup.get(unit_name)
                if u is None:
                    unit_lookup[unit_name] = unit
                elif isinstance(u, list):
                    u.append(unit)
                elif isinstance(u, pedm_types.PedmOrganizationUnit):
                    unit_lookup[unit_name] = [u, unit]
        return unit_lookup

    @staticmethod
    def resolve_single_unit(pedm: pedm_plugin.PedmPlugin, unit_name: Any) -> pedm_types.PedmOrganizationUnit:
        unit_lookup = PedmUtils.get_unit_name_lookup(pedm)
        if not isinstance(unit_name, str):
            raise base.CommandError(f'Invalid unit_name: {unit_name}')

        unit = unit_lookup.get(unit_name)
        if not unit:
            unit = unit_lookup.get(unit_name.lower())

        if isinstance(unit, pedm_types.PedmOrganizationUnit):
            return unit
        if isinstance(unit, list) and len(unit) > 1:
            raise base.CommandError(f'Unit name \"{unit_name}\" is not unique. Please use Unit UID')
        raise base.CommandError(f'Unit name \"{unit_name}\" does not exist')

    @staticmethod
    def resolve_existing_units(pedm: pedm_plugin.PedmPlugin, unit_names: Any) -> List[pedm_types.PedmOrganizationUnit]:
        found_units: Dict[str, pedm_types.PedmOrganizationUnit] = {}
        u: Optional[pedm_types.PedmOrganizationUnit]
        if isinstance(unit_names, list):
            unit_lookup = PedmUtils.get_unit_name_lookup(pedm)
            for unit_name in unit_names:
                u = None
                if isinstance(unit_name, str):
                    uu = unit_lookup.get(unit_name)
                    if not uu:
                        uu = unit_lookup.get(unit_name.lower())
                    if isinstance(uu, pedm_types.PedmOrganizationUnit):
                        u = uu
                    elif isinstance(uu, list):
                        if len(uu) == 1:
                            u = uu[0]
                        elif len(uu) >= 2:
                            raise base.CommandError(f'Unit name "{unit_name}" is not unique. Use Unit UID.')
                if u is None:
                    raise base.CommandError(f'Unit name "{unit_name}" is not found')
                found_units[u.ou_uid] = u
        if len(found_units) == 0:
            raise base.CommandError('No units were found')
        return list(found_units.values())

    @staticmethod
    def get_policy_name_lookup(pedm: pedm_plugin.PedmPlugin) -> Dict[str, Union[pedm_types.PedmPolicy, List[pedm_types.PedmPolicy]]]:
        policy_lookup: Dict[str, Union[pedm_types.PedmPolicy, List[pedm_types.PedmPolicy]]] = {}

        for policy in pedm.policies.get_all_entities():
            policy_lookup[str(policy.policy_uid)] = policy
            policy_name = policy.data.get('displayname')
            if policy_name:
                policy_name = policy_name.lower()
                p = policy_lookup.get(policy_name)
                if p is None:
                    policy_lookup[policy_name] = policy
                elif isinstance(p, list):
                    p.append(policy)
                elif isinstance(p, pedm_types.PedmPolicy):
                    policy_lookup[policy_name] = [p, policy]
        return policy_lookup

    @staticmethod
    def resolve_existing_policies(pedm: pedm_plugin.PedmPlugin, policy_names: Any) -> List[pedm_types.PedmPolicy]:
        found_policies: Dict[str, pedm_types.PedmPolicy] = {}
        p: Optional[pedm_types.PedmPolicy]
        if isinstance(policy_names, list):
            policy_lookup = PedmUtils.get_policy_name_lookup(pedm)
            for policy_name in policy_names:
                p = None
                if isinstance(policy_name, str):
                    pp = policy_lookup.get(policy_name)
                    if not pp:
                        pp = policy_lookup.get(policy_name.lower())
                    if isinstance(pp, pedm_types.PedmPolicy):
                        p = pp
                    elif isinstance(pp, list):
                        if len(pp) == 1:
                            p = pp[0]
                        elif len(pp) >= 2:
                            raise base.CommandError(f'Policy name "{policy_name}" is not unique. Use Policy UID.')
                if p is None:
                    raise base.CommandError(f'Policy name "{policy_name}" is not found')
                found_policies[p.policy_uid] = p
        if len(found_policies) == 0:
            raise base.CommandError('No policies were found')
        return list(found_policies.values())

    @staticmethod
    def resolve_single_policy(pedm, policy_name: Any) -> pedm_types.PedmPolicy:
        if not isinstance(policy_name, str):
            raise base.CommandError(f'Invalid policy name: {policy_name}')
        policy_lookup = PedmUtils.get_policy_name_lookup(pedm)
        policy = policy_lookup.get(policy_name)
        if not policy:
            policy = policy_lookup.get(policy_name.lower())

        if isinstance(policy, pedm_types.PedmPolicy):
            return policy
        if isinstance(policy, list) and len(policy) > 1:
            raise base.CommandError(f'Policy name \"{policy_name}\" is not unique. Please use Policy UID')
        raise base.CommandError(f'Policy name \"{policy_name}\" does not exist')


class PedmCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('Manage enterprise PEDM')
        self.register_command(PedmTreeCommand(), 'tree')
        self.register_command(PedmSyncDownCommand(), 'sync-down')
        self.register_command(PedmAgentCommand(), 'agent', 'a')
        self.register_command(PedmUnitCommand(), 'unit', 'u')
        self.register_command(PedmPolicyCommand(), 'policy', 'p')
        # self.register_command(PedmAgentLogCommand(), 'log', 'a')
        self.default_verb = 'tree'


class PedmAgentCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('Manage PEDM agent(s)')
        self.register_command(PedmAgentListCommand(), 'list', 'l')
        self.register_command(PedmAgentSetupCommand(), 'setup')
        self.default_verb = 'list'


class PedmUnitCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('Manage PEDM organization units')
        self.register_command(PedmUnitListCommand(), 'list', 'l')
        self.register_command(PedmUnitAddCommand(), 'add', 'a')
        self.register_command(PedmUnitEditCommand(), 'edit', 'e')
        self.default_verb = 'list'


class PedmPolicyCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('Manage PEDM policies')
        self.register_command(PedmPolicyListCommand(), 'list', 'l')
        self.register_command(PedmPolicyAddCommand(), 'add', 'a')
        self.register_command(PedmPolicyEditCommand(), 'edit', 'e')
        self.register_command(PedmPolicyViewCommand(), 'view', 'v')
        self.register_command(PedmPolicyDeleteCommand(), 'delete')
        self.default_verb = 'list'


class PedmTreeCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='tree', description='Show PEDM organization tree')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        plugin = context.pedm_plugin

        def unit_node(un: pedm_types.PedmOrganizationUnit) -> Tuple[str, Dict[str, Any]]:
            key = un.data.get('displayname') or un.ou_uid
            value: Dict[str, Any] = OrderedDict()
            if un.children_ou:
                for child_uid in un.children_ou:
                    ch_ou = plugin.units.get_entity(child_uid)
                    if ch_ou:
                        ch_key, ch_value = unit_node(ch_ou)
                        value[ch_key] = ch_value
            if un.agents and len(un.agents) > 0:
                agents: List[str] = []
                for agent_uid in un.agents:
                    agent = plugin.agents.get_entity(agent_uid)
                    if agent:
                        agents.append(agent.agent_name)
                if len(agents) > 0:
                    if len(agents) > 1:
                        agents.sort()
                    value['Agents'] = {x: {} for x in agents}

            return key, value

        key, value = unit_node(plugin.enterprise_unit)
        tree = {key: value}
        tr = LeftAligned()
        print(tr(tree))
        print()


class PedmSyncDownCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='sync-down', description='Sync down PEDM data from the backend')
        parser.add_argument('--reload', dest='reload', action='store_true', help='Perform full sync')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        plugin = context.pedm_plugin
        plugin.sync_down(reload=kwargs.get('reload') is True)


class PedmAgentListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='list', description='List PEDM agents',
                                         parents=[base.report_output_parser])
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        plugin = context.pedm_plugin
        table = []
        headers = ['agent_uid', 'agent_name', 'organization_unit', 'create', 'initialized', 'policy_count']
        agent_policies: Dict[str, Set[str]] = {}
        for policy in plugin.policies.get_all_entities():
            if policy.agents and len(policy.agents) > 0:
                for agent_uid in policy.agents:
                    if agent_uid not in agent_policies:
                        agent_policies[agent_uid] = set()
                    agent_policies[agent_uid].add(policy.policy_uid)
        agent_units: Dict[str, Set[str]] = {}
        for unit in plugin.units.get_all_entities():
            if unit.agents and len(unit.agents) > 0:
                for agent_uid in unit.agents:
                    if agent_uid not in agent_units:
                        agent_units[agent_uid] = set()
                    agent_units[agent_uid].add(unit.ou_uid)
        for agent in plugin.agents.get_all_entities():
            time_created = datetime.datetime.fromtimestamp(int(agent.created // 1000)) if agent.created else None
            units = agent_units.get(agent.agent_uid)
            row: List[Any] = [agent.agent_uid, agent.agent_name, list(units) if units else None, time_created, agent.is_initialized]
            policies = agent_policies.get(agent.agent_uid)
            row.append(len(policies) if policies else None)
            table.append(row)

        table.sort(key=lambda x: x[1])
        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))


class PedmAgentSetupCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='setup', description='Setup PEDM agent')
        parser.add_argument('--add-unit', dest='add_unit', action='append',
                            help='Add agent to unit. Can be repeated.')
        parser.add_argument('--remove-unit', dest='remove_unit', action='append',
                            help='Remove agent from unit. Can be repeated.')
        parser.add_argument('--add-policy', dest='add_policy', action='append',
                            help='Add policy to agent. Can be repeated.')
        parser.add_argument('--remove-policy', dest='remove_policy', action='append',
                            help='Remove policy from agent. Can be repeated.')
        parser.add_argument('agent', help='Agent Name or UID')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        plugin = context.pedm_plugin
        agent = PedmUtils.resolve_single_agent(plugin, kwargs.get('agent'))
        edges: List[dag.DagEdge] = []

        add_units = kwargs.get('add_unit')
        if isinstance(add_units, str):
            add_units = [add_units]
        if isinstance(add_units, list):
            units = PedmUtils.resolve_existing_units(plugin, add_units)
            for unit in units:
                edges.extend(plugin.add_agent_to_unit(agent.agent_uid, unit.ou_uid))

        remove_units = kwargs.get('remove_unit')
        if isinstance(remove_units, str):
            remove_units = [remove_units]
        if isinstance(remove_units, list):
            units = PedmUtils.resolve_existing_units(plugin, remove_units)
            for unit in units:
                edges.extend(plugin.remove_agent_from_unit(agent.agent_uid, unit.ou_uid))

        add_policy = kwargs.get('add_policy')
        if isinstance(add_policy, str):
            add_policy = [add_policy]
        if isinstance(add_policy, list):
            policies = PedmUtils.resolve_existing_policies(plugin, add_policy)
            for policy in policies:
                edges.extend(plugin.add_policy_to_agent(policy.policy_uid, agent.agent_uid))

        remove_policy = kwargs.get('remove_policy')
        if isinstance(remove_policy, str):
            remove_policy = [remove_policy]
        if isinstance(remove_policy, list):
            policies = PedmUtils.resolve_existing_policies(plugin, remove_policy)
            for policy in policies:
                edges.extend(plugin.remove_policy_from_agent(policy.policy_uid, agent.agent_uid))

        if len(edges) > 0:
            plugin.post_edges(edges)


class PedmUnitListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='list', description='List PEDM organization units',
                                         parents=[base.report_output_parser])
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        plugin = context.pedm_plugin
        table: List[List[Any]] = []
        headers = ['unit_uid', 'unit_path', 'subunits', 'agents']
        for unit in plugin.units.get_all_entities():
            path = PedmUtils.get_unit_path(context.pedm_plugin, unit.ou_uid)
            subunits = []
            if unit.children_ou:
                for child_uid in unit.children_ou:
                    child = context.pedm_plugin.units.get_entity(child_uid)
                    if child:
                        name = child.data.get('displayname') or child.ou_uid
                        subunits.append(name)
            subunits.sort()
            agents = []
            if unit.agents:
                for agent_uid in unit.agents:
                    agent = plugin.agents.get_entity(agent_uid)
                    if agent:
                        agents.append(agent.agent_name)
            table.append([unit.ou_uid, path, subunits, agents])

        table.sort(key=lambda x: x[1])
        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))


class PedmUnitAddCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='add', description='Add PEDM organization unit(s)')
        parser.add_argument('--parent', dest='parent', action='store', help='Parent OU name or ID')
        parser.add_argument('unit', type=str, nargs='+', help='Unit Name. Can be repeated.')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        pedm = context.pedm_plugin
        parent_unit: pedm_types.PedmOrganizationUnit
        if kwargs.get('parent'):
            parent_unit = PedmUtils.resolve_single_unit(pedm, kwargs.get('parent'))
        else:
            parent_unit = pedm.enterprise_unit

        units = kwargs.get('unit')
        if isinstance(units, list):
            edges: List[dag.DagEdge] = []
            unit_names = {x.lower(): x for x in units}
            if parent_unit.children_ou and len(parent_unit.children_ou) > 0:
                existing_subunits: List[str] = []
                for ou_uid in parent_unit.children_ou:
                    unit = pedm.units.get_entity(ou_uid)
                    if unit:
                        unit_name = unit.data.get('displayname')
                        if isinstance(unit_name, str):
                            if unit_name.lower() in unit_names:
                                existing_subunits.append(unit_name)
                if len(existing_subunits) > 0:
                    ex = ', '.join(existing_subunits)
                    raise base.CommandError(f'Unit(s) {ex} already exist')
            for unit_name in units:
                data = {
                    'displayname': unit_name,
                }
                ou = pedm_types.PedmOrganizationUnit(
                    ou_uid=utils.generate_uid(), parent_ou_uid=parent_unit.ou_uid, data=data)
                edges.extend(pedm.put_ou(ou))
            pedm.post_edges(edges)


class PedmUnitEditCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='edit', description='Edit PEDM organization unit(s)')
        parser.add_argument('--parent', dest='parent', action='store', help='Parent OU name or ID')
        parser.add_argument('--name', dest='displayname', action='store', help='set unit display name')
        parser.add_argument('unit', type=str, nargs='+', help='Unit Name or UID. Can be repeated.')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        pedm = context.pedm_plugin
        parent_unit: Optional[pedm_types.PedmOrganizationUnit] = None
        if 'parent' in kwargs:
            if kwargs.get('parent'):
                parent_unit = PedmUtils.resolve_single_unit(pedm, kwargs.get('parent'))
            else:
                parent_unit = pedm.enterprise_unit

        unit_list = PedmUtils.resolve_existing_units(pedm, kwargs.get('unit'))
        unit_name: Optional[str] = kwargs.get('displayname')
        if isinstance(unit_name, str) and len(unit_name) > 0:
            if len(unit_list) > 1:
                raise Exception('Cannot change unit name for more than one roles')
        else:
            unit_name = None

        if unit_name is None and parent_unit is None:
            return

        edges: List[dag.DagEdge] = []
        for unit in unit_list:
            data = {}
            if unit_name:
                data['displayname'] = unit_name
            parent_uid = parent_unit.ou_uid if parent_unit else ''
            ou = pedm_types.PedmOrganizationUnit(ou_uid=unit.ou_uid, parent_ou_uid=parent_uid, data=data)
            edges.extend(pedm.put_ou(ou))
        pedm.post_edges(edges)


class PedmPolicyListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='list', description='List PEDM policies',
                                         parents=[base.report_output_parser])
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        plugin = context.pedm_plugin
        table: List[List[Any]] = []
        headers = ['policy_uid', 'policy_name', 'agents']
        for policy in plugin.policies.get_all_entities():
            policy_name = policy.data.get('displayname')
            agents = []
            if policy.agents:
                for agent_uid in policy.agents:
                    agent = plugin.agents.get_entity(agent_uid)
                    if agent:
                        agents.append(agent.agent_name)
            agents.sort()
            table.append([policy.policy_uid, policy_name, agents])

        table.sort(key=lambda x: x[1])
        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))


class PedmPolicyAddCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='add', description='Add PEDM policy')
        parser.add_argument('--file', dest='file', required=True, action='store', help='policy file name')
        parser.add_argument('policy', help='Policy name')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        plugin = context.pedm_plugin

        file_name = kwargs.get('file')
        if not file_name:
            raise base.CommandError(f'Policy file name is required')
        file_name = os.path.expanduser(file_name)

        try:
            with open(file_name, 'r') as f:
                json_policy = json.load(f)
        except Exception as e:
            raise base.CommandError(f'Policy parse error: {e}')

        json_policy['displayname'] = kwargs.get('policy')
        policy_key = utils.generate_aes_key()
        policy = pedm_types.PedmPolicy(policy_uid=utils.generate_uid(), policy_key=policy_key, data=json_policy)

        edges: List[dag.DagEdge] = []
        edges.extend(plugin.put_policy(policy))

        plugin.post_edges(edges)


class PedmPolicyEditCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='add', description='Add PEDM policy')
        parser.add_argument('--file', dest='file', action='store', help='policy file name')
        parser.add_argument('--name', dest='name', action='store', help='new policy name')
        parser.add_argument('policy', help='Policy UID or name')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        plugin = context.pedm_plugin

        policy = PedmUtils.resolve_single_policy(plugin, kwargs.get('policy'))
        policy_name = policy.data.get('displayname')
        policy_data = copy.copy(policy.data)
        file_name = kwargs.get('file')
        if file_name:
            file_name = os.path.expanduser(file_name)
            try:
                with open(file_name, 'r') as f:
                    policy_data = json.load(f)
                if policy_name:
                    policy_data['displayname'] = policy_name

            except Exception as e:
                raise base.CommandError(f'Policy parse error: {e}')

        policy_name = kwargs.get('name')
        if policy_name:
            policy_data['displayname'] = policy_name

        policy = pedm_types.PedmPolicy(policy_uid=policy.policy_uid, data=policy_data)

        edges: List[dag.DagEdge] = []
        edges.extend(plugin.put_policy(policy))
        plugin.post_edges(edges)


class PedmPolicyViewCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='view', parents=[base.json_output_parser], description='View PEDM policy')
        parser.add_argument('policy', help='Policy UID or name')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        plugin = context.pedm_plugin

        policy = PedmUtils.resolve_single_policy(plugin, kwargs.get('policy'))

        body = json.dumps(policy.data, indent=4)
        filename = kwargs.get('output')
        if kwargs.get('format') == 'json' and filename:
            with open(filename, 'w') as f:
                f.write(body)
        else:
            return body


class PedmPolicyDeleteCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='delete', description='Delete PEDM policy')
        parser.add_argument('policy', type=str, nargs='+', help='Policy UID or name')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        plugin = context.pedm_plugin

        policies = PedmUtils.resolve_existing_policies(plugin, kwargs.get('policy'))
        edges: List[dag.DagEdge] = []
        for policy in policies:
            edges.extend(plugin.delete_policy(policy.policy_uid))

        plugin.post_edges(edges)
