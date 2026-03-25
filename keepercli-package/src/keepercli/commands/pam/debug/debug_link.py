import argparse

from ....params import KeeperParams
from keepersdk.helpers.keeper_dag.constants import PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY
from keepersdk.helpers.keeper_dag.record_link import RecordLink
from ..discovery.__init__ import GatewayContext, PAMGatewayActionDiscoverCommandBase
from .... import api

logger = api.get_logger()

class PAMDebugLinkCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam action debug link')
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action debug link')
        PAMDebugLinkCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                            help='Gateway name or UID.')
        parser.add_argument('--configuration-uid', "-c", required=False, dest='configuration_uid',
                            action='store', help='PAM configuration UID, if gateway has multiple.')
        parser.add_argument('--resource-uid', '-r', required=True, dest='resource_uid', action='store',
                            help='Resource record UID.')
        parser.add_argument('--debug-gs-level', required=False, dest='debug_level', action='store',
                            help='GraphSync debug level. Default is 0', type=int, default=0)

    def execute(self, context: KeeperParams, **kwargs):
        gateway = kwargs.get("gateway")
        resource_uid = kwargs.get("resource_uid")
        debug_level = int(kwargs.get("debug_level", 0))

        logger.info("")

        configuration_uid = kwargs.get('configuration_uid')

        gateway_context = GatewayContext.from_gateway(context=context,
                                                        gateway=gateway,
                                                        configuration_uid=configuration_uid)
        if gateway_context is None:
            logger.error(f"Could not find the gateway configuration for {gateway}.")
            return

        record_link = RecordLink(record=gateway_context.configuration,
                                 context=context,
                                 logger=logger,
                                 debug_level=debug_level)

        resource_record = context.vault.vault_data.load_record(resource_uid)
        if resource_record is None:
            logger.error(f"The parent record does not exists.")
            return

        if resource_record.record_type not in [PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY]:
            logger.error(f"The resource record type, {resource_record.record_type} "
                  f"is not allowed.")
            return

        try:
            record_link.belongs_to(resource_uid, gateway_context.configuration_uid, )
            record_link.save()
            logger.info(f"Added link between '{resource_uid}' and "
                  f"{gateway_context.configuration_uid}")
        except Exception as err:
            logger.error(f"Could not add LINK: {err}")
            raise err
