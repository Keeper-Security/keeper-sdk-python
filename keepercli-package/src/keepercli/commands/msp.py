import argparse
from typing import List, Optional

from keepersdk import errors as sdk_errors
from keepersdk.enterprise import enterprise_constants, msp_auth
from . import base, enterprise_utils
from .. import prompt_utils, api
from ..helpers import report_utils
from ..params import KeeperParams

_MSP_PLAN_CHOICES = [x[1] for x in enterprise_constants.MSP_PLANS]


class MspDownCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='msp-down',
            description='Download current MSP data from the Keeper cloud (refresh managed companies and enterprise graph).',
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            '--reset',
            dest='reset',
            action='store_true',
            help='Clear sync continuation token and reload enterprise data from scratch',
        )

    def execute(self, context: KeeperParams, **kwargs) -> None:
        base.require_login(context)
        base.require_enterprise_admin(context)
        enterprise_loader = context.enterprise_loader

        reset: Optional[bool] = None
        if kwargs.get('reset') is True:
            reset = True
        msp_auth.msp_down(enterprise_loader, reset=reset or False)


class MspInfoCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='msp-info',
            parents=[base.report_output_parser],
            description='Display MSP details, including managed companies, restrictions, and pricing.',
            formatter_class=argparse.RawTextHelpFormatter,
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('-p', '--pricing', dest='pricing', action='store_true', help='Display pricing information')
        parser.add_argument('-r', '--restriction', dest='restriction', action='store_true',
                            help='Display MSP restriction information')
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Print details')
        parser.add_argument('-mc', '--managed-company', dest='managed_company', action='store',
                            help='Filter by managed company name or id')

    def execute(self, context: KeeperParams, **kwargs):
        base.require_login(context)
        base.require_enterprise_admin(context)
        enterprise_loader = context.enterprise_loader

        try:
            report = msp_auth.msp_info(
                enterprise_loader,
                restriction=bool(kwargs.get('restriction')),
                pricing=bool(kwargs.get('pricing')),
                managed_company=kwargs.get('managed_company'),
                verbose=bool(kwargs.get('verbose')),
            )
        except sdk_errors.KeeperError as e:
            raise base.CommandError(str(e)) from e

        if report.message:
            api.get_logger().info(report.message)
            return None

        headers = list(report.headers)
        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]

        return report_utils.dump_report_data(
            [list(r) for r in report.rows],
            headers,
            fmt=fmt,
            filename=kwargs.get('output'),
            row_number=report.row_numbers,
        )


class MspAddCommand(base.ArgparseCommand):
    fp_help = ', '.join((x[2].lower() for x in enterprise_constants.MSP_FILE_PLANS))
    addon_help = ', '.join((x[0] + (':N' if x[2] else '') for x in enterprise_constants.MSP_ADDONS))

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='msp-add',
            description='Add a managed company to the MSP tenant.',
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--node', dest='node', action='store', help='Node name or node ID (default: enterprise root)')
        parser.add_argument('-s', '--seats', dest='seats', action='store', type=int,
                            help='Maximum licences allowed (-1 for unlimited when permitted)')
        parser.add_argument('-p', '--plan', dest='plan', action='store', required=True, choices=_MSP_PLAN_CHOICES,
                            help=f'License plan: {", ".join(_MSP_PLAN_CHOICES)}')
        parser.add_argument('-f', '--file-plan', dest='file_plan', action='store', help=f'File storage plan: {MspAddCommand.fp_help}')
        parser.add_argument('-a', '--addon', dest='addon', action='append', metavar='ADDON[:SEATS]',
                            help=f'Add-ons: {MspAddCommand.addon_help}')
        parser.add_argument('name', action='store', help='Managed company name')

    def execute(self, context: KeeperParams, **kwargs):
        base.require_login(context)
        base.require_enterprise_admin(context)
        enterprise_loader = context.enterprise_loader
        enterprise_data = context.enterprise_data

        node_arg = kwargs.get('node')
        if node_arg:
            node = enterprise_utils.NodeUtils.resolve_single_node(enterprise_data, node_arg)
            node_id = node.node_id
        else:
            node_id = enterprise_data.root_node.node_id

        addon_list: Optional[List[str]] = kwargs.get('addon')
        if isinstance(addon_list, list) and len(addon_list) == 0:
            addon_list = None

        try:
            mc_id = msp_auth.msp_add_managed_company(
                enterprise_loader,
                enterprise_name=str(kwargs['name']),
                plan=str(kwargs['plan']),
                node_id=node_id,
                seats=kwargs.get('seats'),
                file_plan=kwargs.get('file_plan'),
                addons=addon_list,
            )
        except sdk_errors.KeeperError as e:
            raise base.CommandError(str(e)) from e

        api.get_logger().info('Managed company "%s" added. ID=%s', kwargs['name'], mc_id)
        return mc_id


class MspUpdateCommand(base.ArgparseCommand):
    fp_help = ', '.join((x[2].lower() for x in enterprise_constants.MSP_FILE_PLANS))
    addon_help = ', '.join(((x[0] + (':N' if x[2] else '')) for x in enterprise_constants.MSP_ADDONS))

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='msp-update',
            description='Modify a managed company license (plan, seats, node, add-ons).',
            )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--node', dest='node', action='store', help='Node name or node ID')
        parser.add_argument('-n', '--name', dest='name', action='store', help='Update managed company name')
        parser.add_argument('-p', '--plan', dest='plan', action='store', choices=_MSP_PLAN_CHOICES,
                            help=f'License plan: {", ".join(_MSP_PLAN_CHOICES)}')
        parser.add_argument('-s', '--seats', dest='seats', action='store', type=int,
                            help='Maximum licences allowed (-1 for unlimited when permitted)')
        parser.add_argument('-f', '--file-plan', dest='file_plan', action='store', help=f'File storage plan: {MspUpdateCommand.fp_help}')
        parser.add_argument('-aa', '--add-addon', dest='add_addon', action='append', metavar='ADDON[:SEATS]',
                            help=f'Add add-ons: {MspUpdateCommand.addon_help}')
        parser.add_argument('-ra', '--remove-addon', dest='remove_addon', action='append', metavar='ADDON',
                            help=f'Remove add-ons: {MspUpdateCommand.addon_help}')
        parser.add_argument('mc', action='store', help='Managed company name or id')

    def execute(self, context: KeeperParams, **kwargs):
        base.require_login(context)
        base.require_enterprise_admin(context)
        enterprise_loader = context.enterprise_loader
        enterprise_data = context.enterprise_data

        node_id: Optional[int] = None
        node_arg = kwargs.get('node')
        if node_arg:
            node = enterprise_utils.NodeUtils.resolve_single_node(enterprise_data, node_arg)
            node_id = node.node_id

        add_list: Optional[List[str]] = kwargs.get('add_addon')
        if isinstance(add_list, list) and len(add_list) == 0:
            add_list = None
        rem_list: Optional[List[str]] = kwargs.get('remove_addon')
        if isinstance(rem_list, list) and len(rem_list) == 0:
            rem_list = None

        try:
            eid = msp_auth.msp_update_managed_company(
                enterprise_loader,
                managed_company=str(kwargs['mc']),
                node_id=node_id,
                new_name=kwargs.get('name'),
                plan=kwargs.get('plan'),
                seats=kwargs.get('seats'),
                file_plan=kwargs.get('file_plan'),
                add_addons=add_list,
                remove_addons=rem_list,
            )
        except sdk_errors.KeeperError as e:
            raise base.CommandError(str(e)) from e

        api.get_logger().info('Successfully updated managed company id=%s', eid)
        return eid


class MspRemoveCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='msp-remove',
            description='Remove a managed company (MC) tenant.',
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('-f', '--force', dest='force', action='store_true',
                            help='Do not prompt for confirmation')
        parser.add_argument('mc', action='store', help='Managed company name or id')

    def execute(self, context: KeeperParams, **kwargs):
        base.require_login(context)
        base.require_enterprise_admin(context)
        enterprise_loader = context.enterprise_loader
        enterprise_data = context.enterprise_data

        mc_input = str(kwargs.get('mc') or '').strip()
        if not mc_input:
            raise base.CommandError('Managed Company name or id is required')

        current = None
        if mc_input.isdigit():
            current = enterprise_data.managed_companies.get_entity(int(mc_input))
        else:
            key = mc_input.lower()
            for mc in enterprise_data.managed_companies.get_all_entities():
                if mc.mc_enterprise_name.lower() == key:
                    current = mc
                    break
        if current is None:
            raise base.CommandError(f'Managed Company "{mc_input}" not found')

        if not kwargs.get('force'):
            seats = current.number_of_seats
            seat_txt = 'unlimited' if seats > 2147483646 else str(seats)
            msg = (
                'ALERT: Remove Managed Company.\n\n'
                'Removing will expire the licences for the managed company and your admin access for the account.\n'
                f'Managed company: "{current.mc_enterprise_name}", licences: {seat_txt}\n\n'
                'I want to remove these licences, the managed vault folder, and my access to the admin console from my MSP account.'
            )
            answer = prompt_utils.user_choice(msg, 'yn', default='n')
            if str(answer).lower() != 'y':
                api.get_logger().info('Removal cancelled')
                return None

        try:
            eid = msp_auth.msp_remove_managed_company(enterprise_loader, managed_company=mc_input)
        except sdk_errors.KeeperError as e:
            raise base.CommandError(str(e)) from e

        api.get_logger().info('Managed company "%s" removed. ID=%s', current.mc_enterprise_name, eid)
        return eid


class MspConvertNodeCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='msp-convert-node',
            description='Convert an MSP enterprise subtree (node and descendants) into a managed company.',
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('-s', '--seats', dest='seats', action='store', type=int,
                            help='Number of seats when registering a new managed company (defaults to subtree user count)')
        parser.add_argument('-p', '--plan', dest='plan', action='store', choices=_MSP_PLAN_CHOICES,
                            help=f'License plan when registering a new MC (default: business). Options: {", ".join(_MSP_PLAN_CHOICES)}')
        parser.add_argument('node', action='store', help='Node name or node ID (subtree root)')
    
    def execute(self, context: KeeperParams, **kwargs):
        base.require_login(context)
        base.require_enterprise_admin(context)
        enterprise_loader = context.enterprise_loader
        enterprise_data = context.enterprise_data

        node_arg = str(kwargs.get('node') or '').strip()
        if not node_arg:
            raise base.CommandError('Node name or node ID is required')
        node = enterprise_utils.NodeUtils.resolve_single_node(enterprise_data, node_arg)

        try:
            mc_id = msp_auth.msp_convert_node(
                enterprise_loader,
                node_id=node.node_id,
                seats=kwargs.get('seats'),
                plan=kwargs.get('plan'),
            )
        except sdk_errors.KeeperError as e:
            raise base.CommandError(str(e)) from e

        api.get_logger().info('Node "%s" was converted to managed company id=%s', node.name or node.node_id, mc_id)
        return mc_id


class SwitchToManagedCompanyCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(prog='switch-to-mc', description='Switch to a managed company context')
    parser.add_argument('mc_id', type=int, help='Managed company ID')
    
    def __init__(self):
        super().__init__(SwitchToManagedCompanyCommand.parser)
    
    def execute(self, context: KeeperParams, **kwargs):
        base.require_login(context)
        base.require_enterprise_admin(context)
        logger = api.get_logger()

        mc_id = kwargs.get('mc_id')
        if not isinstance(mc_id, int):
            raise base.CommandError('The managed company ID must be an integer')

        prompt_utils.output_text(f'Switching to managed company {mc_id}...')
        mc_auth, tree_key = msp_auth.login_to_managed_company(context.enterprise_loader, mc_id)
        mc_auth.auth_context.is_enterprise_admin = True
        mc_auth.auth_context.is_mc_superadmin = True
        mc_auth.auth_context.enterprise_id = mc_id

        mc_context = KeeperParams(context.keeper_config)
        mc_context.set_auth(mc_auth, tree_key=tree_key, skip_vault=True)

        logger.info('Successfully switched to managed company %s', mc_id)
        logger.info('Use "q" to return to the previous context')
            
        return mc_context
