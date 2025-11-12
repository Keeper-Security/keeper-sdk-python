import argparse

from keepersdk.enterprise import msp_auth
from . import base
from .. import prompt_utils, api
from ..params import KeeperParams


class SwitchToManagedCompanyCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(prog='switch-to-mc', description='Switch to a managed company context')
    parser.add_argument('mc_id', type=int, help='Managed company ID')
    
    def __init__(self):
        super().__init__(SwitchToManagedCompanyCommand.parser)
    
    def execute(self, context: KeeperParams, **kwargs):
        assert context.enterprise_data is not None
        assert context.auth is not None
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
