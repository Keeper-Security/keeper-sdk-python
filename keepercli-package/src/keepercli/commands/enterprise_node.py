import argparse
import json
import os
import time
from typing import Dict, List, Optional, Any

import requests

from keepersdk.authentication import keeper_auth
from keepersdk.enterprise import enterprise_types, batch_management, enterprise_management
from keepersdk.vault import attachment
from ..helpers import report_utils
from . import base, enterprise_utils
from .. import api, prompt_utils
from ..params import KeeperParams


class EnterpriseNodeCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('Manage an enterprise node(s)')
        self.register_command(EnterpriseNodeViewCommand(), 'view', 'v')
        self.register_command(EnterpriseNodeAddCommand(), 'add', 'a')
        self.register_command(EnterpriseNodeEditCommand(), 'edit', 'e')
        self.register_command(EnterpriseNodeDeleteCommand(), 'delete')
        self.register_command(EnterpriseNodeSetLogoCommand(), 'set-logo')
        self.register_command(EnterpriseNodeInviteCommand(), 'invite-email')
        self.register_command(EnterpriseNodeWipeOutCommand(), 'wipe-out')


class EnterpriseNodeViewCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-node view', parents=[base.json_output_parser],
                                         description='View enterprise node.')
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print verbose information')
        parser.add_argument('node', help='Node name or UID')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        assert context.enterprise_data is not None
        assert context.vault

        verbose = kwargs.get('verbose') is True

        enterprise_data = context.enterprise_data
        node = enterprise_utils.NodeUtils.resolve_single_node(enterprise_data, kwargs.get('node'))
        node_name = enterprise_utils.NodeUtils.get_node_path(enterprise_data, node.node_id, omit_root=False)

        node_obj = {
            'node_id': node.node_id,
            'node_name': node_name,
        }
        if node.parent_id:
            node_obj['parent_id'] = node.parent_id
            node_obj['parent_name'] = enterprise_utils.NodeUtils.get_node_path(
                enterprise_data, node.parent_id, omit_root=False)

        if node.restrict_visibility:
            node_obj['restrict_visibility'] = node.restrict_visibility
        if node.duo_enabled:
            node_obj['duo_enabled'] = node.duo_enabled
        if node.rsa_enabled:
            node_obj['rsa_enabled'] = node.rsa_enabled
        if isinstance(node.bridge_id, int) and node.bridge_id > 0:
            bridge_obj: Dict[str, Any] = {
                'bridge_id': node.bridge_id,
            }
            bridge = enterprise_data.bridges.get_entity(node.bridge_id)
            if bridge:
                bridge_obj['status'] = bridge.status
            node_obj['bridge'] = bridge_obj
        if isinstance(node.scim_id, int) and node.scim_id > 0:
            scim_obj: Dict[str, Any] = {
                'scim_id': node.scim_id,
            }
            scim = enterprise_data.scims.get_entity(node.scim_id)
            if scim:
                scim_obj['status'] = scim.status
                if isinstance(scim.last_synced, int) and scim.last_synced > 0:
                    scim_obj['last_synced'] = scim.last_synced
            node_obj['scim'] = scim_obj
        if isinstance(node.sso_service_provided_ids, list) and len(node.sso_service_provided_ids) > 0:
            for sso_id in node.sso_service_provided_ids:
                sso = enterprise_data.sso_services.get_entity(sso_id)
                if sso is not None:
                    cloud_sso_obj: Dict[str, Any] = {
                        'sso_id': sso.sso_service_provider_id,
                        'name': sso.name,
                        'active': sso.active,
                    }
                    cloud_sso_obj['cloud_sso' if sso.is_cloud else 'sso_connect'] = cloud_sso_obj

        node_obj['subnodes'] = [{
            'node_id': x.node_id,
            'name': x.name,
        } for x in enterprise_data.nodes.get_all_entities() if x.parent_id == node.node_id]
        node_obj['roles'] = [{
            'role_id': x.role_id,
            'name': x.name,
        } for x in enterprise_data.roles.get_all_entities() if x.node_id == node.node_id]
        node_obj['teams'] = [{
            'team_uid': x.team_uid,
            'name': x.name,
        } for x in enterprise_data.teams.get_all_entities() if x.node_id == node.node_id]
        node_obj['queued_teams'] = [{
            'team_uid': x.team_uid,
            'name': x.name,
        } for x in enterprise_data.queued_teams.get_all_entities() if x.node_id == node.node_id]
        node_obj['users'] = [{
            'enterprise_user_id': x.enterprise_user_id,
            'username': x.username,
        } for x in enterprise_data.users.get_all_entities() if x.node_id == node.node_id]

        if kwargs.get('format') == 'json':
            json_text = json.dumps(node_obj, indent=4)
            filename = kwargs.get('output')
            if filename is None:
                return json_text
            else:
                with open(filename, 'w') as f:
                    f.write(json_text)

        headers = ['node_id', 'node_name', 'parent_name', 'restrict_visibility', 'duo_enabled', 'rsa_enabled']
        table = []
        for field in headers:
            field_value = node_obj.get(field)
            if field_value is not None:
                row = [report_utils.field_to_title(field), field_value]
                if verbose:
                    if field == 'parent_name':
                        row.append(node_obj.get('parent_id'))
                    else:
                        row.append(None)
                table.append(row)

        obj = node_obj.get('subnodes')
        if isinstance(obj, list) and len(obj) > 0:
            row = ['Subnodes']
            obj.sort(key=lambda x: f'{(x.get("name") or "").lower()}')
            row.append([x['name'] for x in obj])
            if verbose:
                row.append([x['node_id'] for x in obj])
            else:
                row.append(None)
            table.append(row)

        obj = node_obj.get('bridge')
        if isinstance(obj, dict):
            row = ['Bridge', obj.get('status')]
            if verbose:
                row.append(obj.get('bridge_id'))
            else:
                row.append(None)
            table.append(row)

        obj = node_obj.get('scim')
        if isinstance(obj, dict):
            row = ['SCIM', obj.get('status')]
            if verbose:
                row.append(obj.get('bridge_id'))
            else:
                row.append(None)
            table.append(row)

        obj = node_obj.get('cloud_sso')
        if isinstance(obj, dict):
            row = ['Cloud SSO', obj.get('name')]
            if verbose:
                row.append(obj.get('sso_id'))
            else:
                row.append(None)
            table.append(row)

        obj = node_obj.get('sso_connect')
        if isinstance(obj, dict):
            row = ['SSO Connect', obj.get('name')]
            if verbose:
                row.append(obj.get('sso_id'))
            else:
                row.append(None)
            table.append(row)

        obj = node_obj.get('users')
        if isinstance(obj, list) and len(obj) > 0:
            row = ['User(s)']
            obj.sort(key=lambda x: str(x.get('username')).lower())
            row.append([x['username'] for x in obj])
            if verbose:
                row.append([x['enterprise_user_id'] for x in obj])
            else:
                row.append(None)
            table.append(row)

        obj = node_obj.get('roles')
        if isinstance(obj, list) and len(obj) > 0:
            row = ['Role(s)']
            obj.sort(key=lambda x: str(x.get('name')).lower())
            row.append([x['name'] for x in obj])
            if verbose:
                row.append([x['role_id'] for x in obj])
            else:
                row.append(None)
            table.append(row)

        obj = node_obj.get('teams')
        if isinstance(obj, list) and len(obj) > 0:
            row = ['Team(s)']
            obj.sort(key=lambda x: str(x.get('name')).lower())
            row.append([x['name'] for x in obj])
            if verbose:
                row.append([x['team_uid'] for x in obj])
            else:
                row.append(None)
            table.append(row)

        obj = node_obj.get('queued_teams')
        if isinstance(obj, list) and len(obj) > 0:
            row = ['Queued Team(s)']
            obj.sort(key=lambda x: str(x.get('name')).lower())
            row.append([x['name'] for x in obj])
            if verbose:
                row.append([x['team_uid'] for x in obj])
            else:
                row.append(None)
            table.append(row)

        headers = ['', '']
        if verbose:
            headers.append('')
        report_utils.dump_report_data(table, headers=headers, no_header=True, right_align=[0])


class EnterpriseNodeAddCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-node add', description='Create enterprise node(s).')
        parser.add_argument('--parent', dest='parent', action='store', help='Parent node name or ID')
        parser.add_argument('--name', dest='displayname', action='store', help='set node display name')
        parser.add_argument('--set-isolated', dest='set_isolated', action='store', choices=['on', 'off'],
                            help='set node isolated')
        parser.add_argument('-f', '--force', dest='force', action='store_true',
                            help='do not prompt for confirmation')
        parser.add_argument('node', type=str, nargs='+', help='Node Name. Can be repeated.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.auth is not None
        assert context.enterprise_loader is not None
        assert context.enterprise_data is not None

        parent_id: Optional[int]
        if kwargs.get('parent'):
            parent_node = enterprise_utils.NodeUtils.resolve_single_node(context.enterprise_data, kwargs.get('parent'))
            parent_id = parent_node.node_id
        else:
            parent_id = context.enterprise_data.root_node.node_id

        force = kwargs.get('force') is True
        node_name_lookup = enterprise_utils.NodeUtils.get_node_name_lookup(context.enterprise_data)
        node_names: Dict[str, str] = {}
        nodes = kwargs.get('node')
        if isinstance(nodes, list):
            node_names = {x.lower(): x for x in nodes}
            for node_key, node_name in list(node_names.items()):
                n = node_name_lookup.get(node_key)
                if n is not None:
                    skip = False
                    if isinstance(n, enterprise_types.Node):
                        n = [n]
                    for n1 in n:
                        if n1.parent_id == parent_id:
                            self.logger.info('Node \"%s\" already exists', n1.name)
                            skip = True
                            break
                        if not force:
                            answer = prompt_utils.user_choice('Do you want to create a node?', choice='yn', default='n')
                            skip = not answer.lower().startswith('y')
                    if skip:
                        del node_names[node_key]
        if len(node_names) == 0:
            raise base.CommandError('No nodes to add')
        set_isolated = kwargs.get('set_isolated')
        is_isolated = set_isolated if isinstance(set_isolated, bool) else None

        nodes_to_add = [enterprise_management.NodeEdit(
            node_id=context.enterprise_loader.get_enterprise_id(), name=x, parent_id=parent_id,
            restrict_visibility=is_isolated)
            for x in node_names.values()]
        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)
        batch.modify_nodes(to_add=nodes_to_add)
        batch.apply()


class EnterpriseNodeEditCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-node edit', description='Edit enterprise node(s).')
        parser.add_argument('--parent', dest='parent', action='store', help='Parent node name or ID')
        parser.add_argument('--name', dest='displayname', action='store', help='set node display name')
        parser.add_argument('--set-isolated', dest='set_isolated', action='store', choices=['on', 'off'],
                            help='set node isolated')
        parser.add_argument('node', type=str, nargs='+', help='Node Name or ID. Can be repeated.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.enterprise_data is not None
        node_list = enterprise_utils.NodeUtils.resolve_existing_nodes(context.enterprise_data, kwargs.get('node'))
        parent_id: Optional[int] = None
        if kwargs.get('parent'):
            parent_node = enterprise_utils.NodeUtils.resolve_single_node(context.enterprise_data, kwargs.get('parent'))
            parent_id = parent_node.node_id
        display_name = kwargs.get('displayname')
        if display_name and len(node_list) > 1:
            raise Exception('Cannot change node name for more than one nodes')
        set_isolated = kwargs.get('set_isolated')
        is_isolated = set_isolated if isinstance(set_isolated, bool) else None

        nodes_to_update = [enterprise_management.NodeEdit(
            node_id=x.node_id, name=display_name, parent_id=parent_id, restrict_visibility=is_isolated)
            for x in node_list]
        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)
        batch.modify_nodes(to_update=nodes_to_update)
        batch.apply()


class EnterpriseNodeDeleteCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-node delete', description='Delete enterprise node(s).')
        parser.add_argument('node', type=str, nargs='+', help='Node Name or ID. Can be repeated.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.enterprise_data is not None

        node_list = enterprise_utils.NodeUtils.resolve_existing_nodes(context.enterprise_data, kwargs.get('node'))
        depths: Dict[int, int] = {}
        for node in node_list:
            depths[node.node_id] = enterprise_utils.NodeUtils.get_node_depth(context.enterprise_data, node.node_id, 0)
        node_list.sort(key=lambda x: depths[x.node_id] or 0, reverse=True)

        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)
        batch.modify_nodes(to_remove=(enterprise_management.NodeEdit(node_id=x.node_id) for x in node_list))
        batch.apply()


class EnterpriseNodeSetLogoCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-node set-logo', description='Set node logo.')
        parser.add_argument('--logo-file', dest='logo_file', action='store',
                            help='Sets company logo using local image file (max size: 500 kB, min dimensions: 10x10, max dimensions: 320x320)')
        parser.add_argument('node', help='Node Name or ID.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    @staticmethod
    def set_logo(auth: keeper_auth.KeeperAuth, node_id: int, logo_fp: str, logo_type: str) -> None:
        upload_task = attachment.FileUploadTask(logo_fp)
        upload_task.prepare()
        # Check file MIME-type and size
        if upload_task.mime_type not in {'image/jpeg', 'image/png', 'image/gif'}:
            raise Exception('File must be a JPEG, PNG, or GIF image')
        if upload_task.size > 500000:
            raise Exception('Filesize must be less than 500 kB')
        rq_logo = {
            'command': f'request_{logo_type}_logo_upload',
            'node_id': node_id,
        }
        rs_logo = auth.execute_auth_command(rq_logo)
        # Construct POST request for upload
        upload_id = rs_logo.get('upload_id')
        upload_url = rs_logo.get('url')
        assert isinstance(upload_url, str)
        success_status_code = rs_logo.get('success_status_code')
        file_param: Optional[str] = rs_logo.get('file_parameter')
        assert file_param is not None
        form_data = rs_logo.get('parameters')
        assert isinstance(form_data, dict)
        form_data['Content-Type'] = upload_task.mime_type
        with upload_task.open() as task_stream:
            files = {file_param: (None, task_stream, upload_task.mime_type)}
            upload_rs = requests.post(upload_url, files=files, data=form_data)
            if upload_rs.status_code == success_status_code:
                # Verify file upload
                check_rq = {
                    'command': f'check_{logo_type}_logo_upload',
                    'node_id': node_id,
                    'upload_id': upload_id
                }
                while True:
                    check_rs = auth.execute_auth_command(check_rq)
                    check_status = check_rs.get('status')
                    if check_status == 'pending':
                        time.sleep(2)
                    else:
                        if check_status != 'active':
                            if check_status == 'invalid_dimensions':
                                raise Exception('Image dimensions must be between 10x10 and 320x320')
                            else:
                                raise Exception(f'Upload status = {check_status}')
                        else:
                            api.get_logger().info('File "%s" set as %s logo.', logo_fp, logo_type)
                            break
            else:
                raise Exception(f'HTTP status code: {upload_rs.status_code}, expected {success_status_code}')

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.enterprise_data is not None
        assert context.auth is not None

        node = enterprise_utils.NodeUtils.resolve_single_node(context.enterprise_data, kwargs.get('node'))
        logo_file = kwargs.get('logo_file')
        if not logo_file:
            raise Exception('No logo file specified')

        logo_types = {'email', 'vault'}
        try:
            for logo_type in logo_types:
                self.set_logo(context.auth, node.node_id, logo_file, logo_type)
        except Exception as e:
            self.logger.warning(f'Error uploading logo: {e}')


class EnterpriseNodeInviteCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-node invite-email', description='Set invitation email.')
        parser.add_argument('-f', '--force', dest='force', action='store_true',
                            help='do not prompt for confirmation')
        parser.add_argument('--invite-email', dest='invite_email', action='store',
                            help='Sets invite email template from file. Saves current template if file does not exist. dash (-) use stdout')
        parser.add_argument('node', help='Node Name or ID.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.enterprise_data is not None
        assert context.auth is not None

        node = enterprise_utils.NodeUtils.resolve_single_node(context.enterprise_data, kwargs.get('node'))
        email_template = kwargs.get('invite_email')
        if isinstance(email_template, str):
            subject_section = 'Subject'
            heading_section = 'Heading'
            message_section = 'Message'
            button_text_section = 'Button Text'

            if email_template and email_template != '-':
                email_template = os.path.expanduser(email_template)
            else:
                email_template = ''
            if email_template and os.path.isfile(email_template):
                self.logger.info('Loading email template from a file \"%s\"', email_template)
                with open(email_template, 'rt', encoding='utf-8') as t:
                    lines = t.readlines()

                lines = [x.strip() for x in lines if x[0:2] != '//']
                template: Dict[str, str] = {}
                section = ''
                for line in lines:
                    if line.startswith('[') and line.endswith(']'):
                        section = line[1:-1].strip()
                    else:
                        current = template.get(section, '')
                        if current:
                            current += '\n'
                        current += line
                        template[section] = current

                for section in template:
                    template[section] = template[section].strip()

                subject = template.get(subject_section) or ''
                heading = template.get(heading_section) or ''
                message = template.get(message_section) or ''
                button_text = template.get(button_text_section) or ''

                valid = subject and heading and message and button_text
                missing = prompt_utils.get_formatted_text('MISSING!', color=prompt_utils.COLORS.FAIL)
                prompt_utils.output_text([
                    '',
                    f'[{subject_section}]',
                    subject or missing,
                    '',
                    f'[{heading_section}]',
                    heading or missing,
                    '',
                    f'[{message_section}]',
                    message or missing,
                    '',
                    f'[{button_text_section}]',
                    button_text or missing,
                    '',
                ])

                if valid:
                    if kwargs.get('force') is True:
                        answer = 'y'
                    else:
                        answer = prompt_utils.user_choice('Do you want to use this email invitation template?', 'yn',
                                                          'y')
                    answer = answer.lower()
                    if answer in ['y', 'yes']:
                        rq = {
                            'command': 'set_enterprise_custom_invitation',
                            'node_id': node.node_id,
                            'subject': subject,
                            'header': heading,
                            'body': message,
                            'button_label': button_text
                        }
                        context.auth.execute_auth_command(rq)
            else:
                rq = {
                    'command': 'get_enterprise_custom_invitation',
                    'node_id': node.node_id
                }
                try:
                    rs = context.auth.execute_auth_command(rq)
                    description = ''
                    subject = rs.get('subject') or ''
                    heading = rs.get('header') or ''
                    message = rs.get('body') or ''
                    button_text = rs.get('button_label') or ''
                except Exception:
                    description = '// A line started with <//> is a comment\n' \
                                  '// https://docs.keeper.io/enterprise-guide/user-and-team-provisioning/custom-invite-and-logo'
                    subject = '// The email subject line.\n//e.g. Keeper Invitation'
                    heading = '// The header or title that is in bold and above the rest of the email content\n//e.g Invite to Join Keeper Company '
                    message = '// The main body of text in the email. Any HTML present will be escaped such that it will show as plain text.\n' \
                              '// Newlines will be converted to <br> tags to allow text to move to a new line.\n' \
                              '//e.g Your organization has purchased Keeper, the world\'s leading password manager and digital vault.\n' \
                              '// Your Keeper admin has invited you to join your organization\'s account.'
                    button_text = '// The label for the button at the bottom of the email.\n' \
                                  '// This button/link will take the user to the vault to either join the enterprise, or sign up with Keeper then join the enterprise.\n' \
                                  '//e.g Setup Account'
                lines = []
                if description:
                    lines.append(description)
                lines.append(f'[{subject_section}]')
                lines.append(subject)
                lines.append('')
                lines.append(f'[{heading_section}]')
                lines.append(heading)
                lines.append('')
                lines.append(f'[{message_section}]')
                lines.append(message)
                lines.append('')
                lines.append(f'[{button_text_section}]')
                lines.append(button_text)

                if email_template:
                    with open(email_template, 'wt') as t:
                        t.writelines((f'{x}\n' for x in lines))

                    self.logger.info('Email invitation template is written to file: \"%s\"', email_template)
                else:
                    prompt_utils.output_text(lines)


class EnterpriseNodeWipeOutCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-node wipe-out', description='Wipe out node content.')
        parser.add_argument('node', help='Node Name or ID.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.enterprise_data is not None

        node = enterprise_utils.NodeUtils.resolve_single_node(context.enterprise_data, kwargs.get('node'))
        if node.node_id == context.enterprise_data.root_node.node_id:
            raise base.CommandError('Cannot wipe out root node')

        alert_text = prompt_utils.get_formatted_text('\nALERT!\n', prompt_utils.COLORS.FAIL)
        prompt_utils.output_text(alert_text)
        answer = prompt_utils.user_choice('This action cannot be undone.\n\n' +
                                          'Do you want to proceed with deletion?', 'yn', 'n')
        if answer.lower() != 'y':
            return

        subnode_lookup: Dict[int, List[int]] = {}
        for n in context.enterprise_data.nodes.get_all_entities():
            parent_id = n.parent_id or 0
            if parent_id not in subnode_lookup:
                subnode_lookup[parent_id] = []
            subnode_lookup[parent_id].append(n.node_id)

        sub_nodes = [node.node_id]
        pos = 0
        while pos < len(sub_nodes):
            if sub_nodes[pos] in subnode_lookup:
                sub_nodes.extend(subnode_lookup[sub_nodes[pos]])
            pos += 1
        nodes = set(sub_nodes)

        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)

        roles = {x.role_id for x in context.enterprise_data.roles.get_all_entities() if x.node_id in nodes}
        users = {x.enterprise_user_id for x in context.enterprise_data.users.get_all_entities() if x.node_id in nodes}

        role_users = [enterprise_management.RoleUserEdit(role_id=x.role_id, enterprise_user_id=x.enterprise_user_id)
                      for x in context.enterprise_data.role_users.get_all_links() if
                      x.role_id in roles or x.enterprise_user_id in users]
        if len(role_users) > 0:
            batch.modify_role_users(to_remove=role_users)

        managed_nodes = [enterprise_management.ManagedNodeEdit(role_id=x.role_id, managed_node_id=x.managed_node_id)
                         for x in context.enterprise_data.managed_nodes.get_all_links() if
                         x.managed_node_id in nodes or x.role_id in roles]
        if len(managed_nodes) > 0:
            batch.modify_managed_nodes(to_remove=managed_nodes)

        roles_to_remove = [enterprise_management.RoleEdit(role_id=x) for x in roles]
        if len(roles) > 0:
            batch.modify_roles(to_remove=roles_to_remove)

        users_to_remove = [enterprise_management.UserEdit(enterprise_user_id=x) for x in users]
        if len(users_to_remove) > 0:
            batch.modify_users(to_remove=users_to_remove)

        queued_teams = [enterprise_management.TeamEdit(team_uid=x.team_uid)
                        for x in context.enterprise_data.queued_teams.get_all_entities() if x.node_id in nodes]
        if len(queued_teams) > 0:
            batch.modify_teams(to_remove=queued_teams)

        teams = [enterprise_management.TeamEdit(team_uid=x.team_uid)
                 for x in context.enterprise_data.teams.get_all_entities() if x.node_id in nodes]
        if len(teams) > 0:
            batch.modify_teams(to_remove=teams)

        sub_nodes.pop(0)
        sub_nodes.reverse()
        nodes_to_remove = [enterprise_management.NodeEdit(node_id=x) for x in sub_nodes]
        if len(nodes_to_remove) > 0:
            batch.modify_nodes(to_remove=nodes_to_remove)

        batch.apply()
