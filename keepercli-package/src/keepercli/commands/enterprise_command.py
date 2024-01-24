import datetime
from typing import Set, List, Dict, Iterable

from keepersdk.enterprise import enterprise_types
from ..params import KeeperParams


class EnterpriseMixin:
    @staticmethod
    def get_user_status_dict(user: enterprise_types.User) -> str:
        if user.status == 'active':
            if user.lock == 0:
                if isinstance(user.account_share_expiration, int) and user.account_share_expiration > 0:
                    expire_at = datetime.datetime.fromtimestamp(user.account_share_expiration // 1000.0)
                    return 'Blocked' if expire_at < datetime.datetime.now() else 'Pending Transfer'
                else:
                    return 'Active'
            else:
                return 'Locked' if user.lock == 1 else 'Disabled'
        else:
            return 'Invited'

    @staticmethod
    def filter_managed_nodes(enterprise_data: enterprise_types.IEnterpriseData, managed_nodes: Dict[int, Set[int]], root_node_id: int) -> Dict[int, Set[int]]:
        subnodes = EnterpriseMixin.get_subnodes(enterprise_data)

        result: Dict[int, Set[int]] = {}
        for node_id, s_nodes in managed_nodes.items():
            if node_id == root_node_id:
                result[node_id] = set(s_nodes)
            elif node_id in s_nodes:
                nodes = [node_id]
                pos = 0
                while pos < len(nodes):
                    n_id = nodes[pos]
                    pos += 1
                    if n_id in subnodes:
                        nodes.extend(subnodes[n_id])
                result[node_id] = set(nodes)

        return result

    @staticmethod
    def get_subnodes(enterprise_data: enterprise_types.IEnterpriseData) ->  Dict[int, Set[int]]:
        subnodes: Dict[int, Set[int]] = {}
        for x in enterprise_data.nodes.get_all_entities():
            if isinstance(x.parent_id, int) and x.parent_id > 0:
                if x.parent_id not in subnodes:
                    subnodes[x.parent_id] = set()
                subnodes[x.parent_id].add(x.node_id)
        return subnodes

    @staticmethod
    def expand_managed_nodes(managed_nodes: Dict[int, bool], subnodes: Dict[int, Set[int]]) -> Dict[int, Set[int]]:
        result: Dict[int, Set[int]] = {}
        for node_id, cascade in managed_nodes.items():
            nodes = [node_id]
            if cascade:
                pos = 0
                while pos < len(nodes):
                    n_id = nodes[pos]
                    pos += 1
                    if n_id in subnodes:
                        nodes.extend(subnodes[n_id])
                result[node_id] = set(nodes)
        # TODO get rid of duplicates
        return result

    @staticmethod
    def get_managed_nodes_for_user(enterprise_data: enterprise_types.IEnterpriseData, username: str) -> Dict[int, bool]:
        result: Dict[int, bool] = {}

        enterprise_user_id = next((x.enterprise_user_id for x in enterprise_data.users.get_all_entities()
                                   if x.username == username), None)
        if enterprise_user_id is None:
            return result

        user_roles = {x.role_id for x in enterprise_data.role_users.get_all_links()
                      if x.enterprise_user_id == enterprise_user_id}

        for x in enterprise_data.managed_nodes.get_all_links():
            if x.role_id not in user_roles:
                continue
            if x.managed_node_id == enterprise_data.root_node.node_id and x.cascade_node_management:
                result.clear()
                result[enterprise_data.root_node.node_id] = True
                break

            if x.managed_node_id not in result:
                result[x.managed_node_id] = x.cascade_node_management
            else:
                if x.cascade_node_management:
                    result[x.managed_node_id] = x.cascade_node_management
        return result

    @staticmethod
    def resolve_nodes(context: KeeperParams, name: str) -> Iterable[enterprise_types.Node]:
        enterprise_data = context.enterprise_data
        assert enterprise_data is not None

        if not name:
            yield enterprise_data.root_node
            return

        node_id = 0
        node_name = ''
        if name:
            node_name = str(name).lower()
            try:
                node_id = int(name)
            except ValueError:
                pass

        for node in enterprise_data.nodes.get_all_entities():
            if node_id > 0:
                if node.node_id == node_id:
                    yield node
                    continue
            if node_name:
                if node.name.lower() == node_name:
                    yield node

'''
    def _load_managed_nodes(self, context: KeeperParams) -> None:
        enterprise_data = context.enterprise_data
        assert enterprise_data is not None
        nodes = enterprise_data.nodes
        current_user = context.auth.auth_context

        root_node_id = enterprise_data.root_node.node_id
        enterprise_user_id = next((x.enterprise_user_id for x in enterprise_data.users.get_all_entities()
                                   if x.username == current_user), None)
        assert enterprise_user_id is not None

        root_nodes: Set[int] = set()
        managed_nodes: Set[int] = set()

        current_user_roles = set((x.role_id for x in enterprise_data.role_users.get_links_by_object(enterprise_user_id)))
        is_main_admin = any(True for x in enterprise_data.managed_nodes.get_all_links()
                            if x.role_id in current_user_roles and x.cascade_node_management and x.managed_node_id == root_node_id)

        if is_main_admin:
            root_nodes.add(root_node_id)
            managed_nodes.update((x.node_id for x in enterprise_data.nodes.get_all_entities()))
        else:
            singles = []
            for mn in enterprise_data.managed_nodes.get_all_links():
                role_id = mn.role_id
                if role_id not in current_user_roles:
                    continue
                node_id = mn.managed_node_id
                if mn.cascade_node_management:
                    managed_nodes.add(node_id)
                else:
                    singles.append(node_id)

            missed = set()
            lookup = {x.node_id: x for x in nodes.get_all_entities()}
            for node in nodes.get_all_entities():
                node_id = node.node_id
                if node_id in managed_nodes:
                    continue

                stack = []
                while node_id in lookup:
                    if node_id in managed_nodes:
                        managed_nodes.update(stack)
                        stack.clear()
                        break
                    if node_id in missed:
                        break
                    stack.append(node_id)
                    node_id = lookup[node_id].parent_id or 0
                missed.update(stack)
            managed_nodes.update(singles)

            for mn in enterprise_data.managed_nodes.get_all_links():
                role_id = mn.role_id
                if role_id not in current_user_roles:
                    continue
                node_id = mn.managed_node_id
                if node_id in lookup:
                    parent_id = lookup[node_id].parent_id or 0
                    if parent_id not in managed_nodes:
                        root_nodes.add(node_id)

        self.user_root_nodes = list(root_nodes)
        self.user_managed_nodes = list(managed_nodes)

    def get_user_managed_nodes(self, context: KeeperParams) -> Iterable[int]:
        if self.user_managed_nodes is None:
            self._load_managed_nodes(context)

        for x in self.user_managed_nodes:
            yield x

    def get_user_root_nodes(self, context: KeeperParams) -> Iterable[int]:
        if self.user_managed_nodes is None:
            self._load_managed_nodes(context)

        for x in self.user_root_nodes:
            yield x


    def get_managed_nodes(self, context: KeeperParams) -> Tuple[Set[int], List[int]]:
        user_managed_nodes = set(self.get_user_managed_nodes(context))
        node_scope: Set[int] = set()
        root_nodes: List[int]

        if kwargs.get('node'):
            subnode = kwargs.get('node').lower()
            root_nodes = [x.node_id for x in self.resolve_nodes(context, subnode) if x.node_id in user_managed_nodes]
            if len(root_nodes) == 0:
                logger.warning('Node \"%s\" not found', subnode)
                return
            if len(root_nodes) > 1:
                logger.warning('More than one node \"%s\" found. Use Node ID.', subnode)
                return
            logger.info('Output is limited to \"%s\" node', subnode)

            node_tree = {}
            for node in context.enterprise_data.nodes.get_all_entities():
                if node.parent_id not in node_tree:
                    node_tree[node.parent_id] = []
                node_tree[node.parent_id].append(node.node_id)

            nl = [x for x in root_nodes]
            pos = 0
            while pos < len(nl):
                if nl[pos] in node_tree:
                    nl.extend(node_tree[nl[pos]])
                pos += 1
                if pos > 100:
                    break
            node_scope.update([x for x in nl if x in user_managed_nodes])
        else:
            node_scope.update((x.node_id for x in context.enterprise_data.nodes.get_all_entities()
                               if x.node_id in user_managed_nodes))
            root_nodes = list(self.get_user_root_nodes(context))

        return node_scope, root_nodes
'''