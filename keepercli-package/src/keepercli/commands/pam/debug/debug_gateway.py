import argparse

from ....params import KeeperParams
from keepersdk.helpers.keeper_dag.constants import PAM_USER, PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY
from keepersdk.helpers.keeper_dag.record_link import RecordLink
from keepersdk.helpers.keeper_dag.infrastructure import Infrastructure
from keepersdk.helpers.keeper_dag.user_service import UserService
from ..discovery.__init__ import GatewayContext, PAMGatewayActionDiscoverCommandBase
from .... import api
from .debug_graph import PAMDebugGraphCommand

logger = api.get_logger()

class PAMDebugGatewayCommand(PAMGatewayActionDiscoverCommandBase):

    type_name_map = {
        PAM_USER: "PAM User",
        PAM_MACHINE: "PAM Machine",
        PAM_DATABASE: "PAM Database",
        PAM_DIRECTORY: "PAM Directory",
    }

    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action debug gateway')
        PAMDebugGatewayCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                            help='Gateway name or UID')
        parser.add_argument('--configuration-uid', "-c", required=False, dest='configuration_uid',
                            action='store', help='PAM configuration UID, if gateway has multiple.')

    def execute(self, context: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        debug_level = kwargs.get("debug_level", False)

        configuration_uid = kwargs.get('configuration_uid')
        vault = context.vault

        gateway_context = GatewayContext.from_gateway(context=context,
                                                        gateway=gateway,
                                                        configuration_uid=configuration_uid)
        if gateway_context is None:
            logger.error(f"Could not find the gateway configuration for {gateway}.")
            return

        infra = Infrastructure(record=gateway_context.configuration, vault=vault, fail_on_corrupt=False)
        infra.load()

        record_link = RecordLink(record=gateway_context.configuration, vault=vault, fail_on_corrupt=False)
        user_service = UserService(record=gateway_context.configuration, vault=vault, fail_on_corrupt=False)

        if gateway_context is None:
            logger.error(f"Cannot get gateway information. Gateway may not be up.")
            return

        logger.info("")
        logger.info(f"Gateway Information")
        logger.info(f"  Gateway UID: {gateway_context.gateway_uid}")
        logger.info(f"  Gateway Name: {gateway_context.gateway_name}")
        if gateway_context.configuration is not None:
            logger.info(f"  Configuration UID: {gateway_context.configuration_uid}")
            logger.info(f"  Configuration Title: {gateway_context.configuration.title}")
            logger.info(f"  Configuration Key Bytes Hex: {gateway_context.configuration.record_key.hex()}")
        else:
            logger.error(f"The gateway appears to not have a configuration.")
        logger.info("")

        graph = PAMDebugGraphCommand()

        if infra.dag.has_graph is True:
            logger.info(f"Infrastructure Graph")
            graph.do_list(context=context, gateway_context=gateway_context, graph_type="infra", debug_level=debug_level,
                          indent=1)
        else:
            logger.error(f"The gateway configuration does not have a infrastructure graph.")

        logger.info("")

        if record_link.dag.has_graph is True:
            logger.info(f"Record Linking Graph")
            graph.do_list(context=context, gateway_context=gateway_context, graph_type="rl", debug_level=debug_level,
                          indent=1)
        else:
            logger.error(f"The gateway configuration does not have a record linking graph.")

        logger.info("")

        if user_service.dag.has_graph is True:
            logger.info(f"User to Service/Task Graph")
            graph.do_list(context=context, gateway_context=gateway_context, graph_type="service", debug_level=debug_level,
                          indent=1)
        else:
            logger.error(f"The gateway configuration does not have a user to service/task graph.")

        logger.info("")
