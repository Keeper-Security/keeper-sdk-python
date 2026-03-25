
import logging
import re
import argparse
import time

from ....params import KeeperParams
from keepersdk.helpers.keeper_dag.constants import PAM_USER, PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY
from keepersdk.helpers.keeper_dag.record_link import RecordLink
from keepersdk.helpers.keeper_dag.dag_types import UserAcl
from keepersdk.helpers.keeper_dag.dag import EdgeType
from keepersdk.helpers.keeper_dag.dag_types import DiscoveryObject
from keepersdk.helpers.keeper_dag.infrastructure import Infrastructure
from keepersdk.helpers.keeper_dag.user_service import UserService
from ..discovery.__init__ import GatewayContext, PAMGatewayActionDiscoverCommandBase
from .... import api

logger = api.get_logger()

class PAMDebugACLCommand(PAMGatewayActionDiscoverCommandBase):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action debug acl')
        PAMDebugACLCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                            help='Gateway name or UID.')
        parser.add_argument('--configuration-uid', "-c", required=False, dest='configuration_uid',
                            action='store', help='PAM configuration UID, if gateway has multiple.')
        parser.add_argument('--user-uid', '-u', required=True, dest='user_uid', action='store',
                            help='User UID.')
        parser.add_argument('--parent-uid', '-r', required=True, dest='parent_uid', action='store',
                            help='Resource or Configuration UID.')
        parser.add_argument('--debug-gs-level', required=False, dest='debug_level', action='store',
                            help='GraphSync debug level. Default is 0', type=int, default=0)

    def execute(self, context: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        user_uid = kwargs.get("user_uid")
        parent_uid = kwargs.get("parent_uid")
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

        user_record = context.vault.vault_data.load_record(user_uid)
        if user_record is None:
            logger.error(f"The user record does not exists.")
            return

        logger.info(f"The user record is {user_record.title}")

        if user_record.record_type != PAM_USER:
            logger.error(f"The user record is not a PAM User record.")
            return

        parent_record = context.vault.vault_data.load_record(parent_uid)
        if parent_record is None:
            logger.error(f"The parent record does not exists.")
            return

        logger.info(f"The parent record is {parent_record.title}")

        if parent_record.record_type.startswith("pam") is False:
            logger.error(f"The parent record is not a PAM record.")
            return

        if parent_record.record_type == PAM_USER:
            logger.error(f"The parent record cannot be a PAM User record.")
            return

        parent_is_config = parent_record.record_type.endswith("Configuration")

        # Get the ACL between the user and the parent.
        # It might not exist.
        acl_exists = True
        acl = record_link.get_acl(user_uid, parent_uid)
        if acl is None:
            logger.info("No existing ACL, creating an ACL.")
            acl = UserAcl()
            acl_exists = False

        # Make sure the ACL for cloud user is set.
        if parent_is_config is True:
            logger.info("Is an IAM user.")
            acl.is_iam_user = True

        rl_parent_vertex = record_link.dag.get_vertex(parent_uid)
        if rl_parent_vertex is None:
            logger.info("Parent record linking vertex did not exists, creating one.")
            rl_parent_vertex = record_link.dag.add_vertex(parent_uid)

        rl_user_vertex = record_link.dag.get_vertex(user_uid)
        if rl_user_vertex is None:
            logger.info("User record linking vertex did not exists, creating one.")
            rl_user_vertex = record_link.dag.add_vertex(user_uid)

        has_admin_uid = record_link.get_admin_record_uid(parent_uid)
        if has_admin_uid is not None:
            logger.info("Parent record already has an admin.")
        else:
            logger.info("Parent record does not have an admin.")

        belongs_to_vertex = record_link.acl_has_belong_to_record_uid(user_uid)
        if belongs_to_vertex is None:
            logger.info("User record does not belong to any resource, or provider.")
        else:
            if not belongs_to_vertex.active:
                logger.info("User record belongs to an inactive parent.")
            else:
                logger.info("User record belongs to another record.")

        logger.info("")

        while True:
            res = input(f"Does this user belong to {parent_record.title} Y/N >").lower()
            if res == "y":
                acl.belongs_to = True
                break
            elif res == "n":
                acl.belongs_to = False
                break

        if has_admin_uid is None:
            while True:
                res = input(f"Is this user the admin of {parent_record.title} Y/N >").lower()
                if res == "y":
                    acl.is_admin = True
                    break
                elif res == "n":
                    acl.is_admin = False
                    break

        try:
            record_link.belongs_to(user_uid, parent_uid, acl=acl)
            record_link.save()
            logger.info(f"Updated/added ACL between {user_record.title} and "
                  f"{parent_record.title}")
        except Exception as err:
            logger.error(f"Could not update ACL: {err}")
