import argparse
import re
from types import SimpleNamespace

from ....params import KeeperParams
from keepersdk.helpers.keeper_dag.constants import PAM_USER, PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY
from keepersdk.helpers.keeper_dag.record_link import RecordLink
from keepersdk.helpers.keeper_dag.dag_types import UserAcl, UserAclRotationSettings
from keepersdk.proto import router_pb2
from ..discovery.__init__ import PAMGatewayActionDiscoverCommandBase
from .... import api
from ....helpers import router_utils
from keepersdk import utils

logger = api.get_logger()

class PAMDebugRotationSettingsCommand(PAMGatewayActionDiscoverCommandBase):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action debug rotation')
        PAMDebugRotationSettingsCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--user-record-uid', '-i', required=True, dest='user_record_uid', action='store',
                            help='PAM user record UID.')
        parser.add_argument('--configuration-record-uid', '-c', required=False,
                            dest='configuration_record_uid', action='store', help='PAM configuration record UID.')
        parser.add_argument('--resource-record-uid', '-r', required=False,
                            dest='resource_record_uid',  action='store', help='PAM resource record UID.')
        parser.add_argument('--noop', required=False, dest='noop', action='store_true',
                            help='User is part of a No Operation.')
        parser.add_argument('--force', required=False, dest='force', action='store_true',
                            help='Force reset of the rotation settings.')
        parser.add_argument('--dry-run', required=False, dest='dry_run', action='store_true',
                            help='Do not create or update anything.')
    
    def execute(self, context: KeeperParams, **kwargs):
        user_record_uid = kwargs.get("user_record_uid")
        resource_record_uid = kwargs.get("resource_record_uid")
        configuration_record_uid = kwargs.get("configuration_record_uid")
        noop = kwargs.get("noop", False)
        force = kwargs.get("force", False)
        dry_run = kwargs.get("dry_run", False)
        vault = context.vault

        logger.info("")

        user_record = vault.vault_data.get_record(user_record_uid)
        if user_record is None:
            logger.error(f"The PAM user record does not exists.")
            return

        if user_record.record_type != PAM_USER:
            logger.error(f"The PAM user record is a {PAM_USER}. "
                  f"The record is {user_record.record_type}")
            return

        record_rotation = context.get_record_rotation(user_record_uid)
        if record_rotation is None:
            logger.warning(f"The protobuf rotation settings are missing. Attempting to create.")

            if configuration_record_uid is None:
                logger.error(f"Cannot determine PAM configuration, please set the "
                      f"-c, --configuration-record-uid parameter for this command.")
                return

            configuration_record = vault.vault_data.get_record(configuration_record_uid)
            if configuration_record is None:
                logger.error(f"Configuration record does not exists.")
                return

            if re.search(r'^pam.+Configuration$', configuration_record.record_type) is None:
                logger.error(
                    f"The configuration record is not a configuration record. "
                    f"It's {configuration_record.record_type} record.")
                return

            if resource_record_uid is None:
                while True:
                    yn = input("The resource record UID was not set. "
                               "This user does not belongs to a machine, database, or directory; "
                               "It's an IAM, Azure, or Domain Controller user? [Y/N]").lower()
                    if yn == "n":
                        logger.error(f"Since a resource is needed, please set --resource-record-uid, -r "
                              f"parameter for the this command.")
                        return
                    elif yn == "y":
                        break

            if resource_record_uid is not None:

                resource_record = vault.vault_data.get_record(resource_record_uid)
                if resource_record is None:
                    logger.error(f"The resource record does not exists.")
                    return

                if resource_record.record_type not in [PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY]:
                    logger.error(f"The resource is NOT a "
                          f"{PAM_MACHINE}, {PAM_DATABASE}, or {PAM_DIRECTORY} record. "
                          f"It's a {resource_record.record_type}.")
                    return

            parent_uid = resource_record_uid or configuration_record_uid

            rq = router_pb2.RouterRecordRotationRequest()
            rq.recordUid = utils.base64_url_encode(user_record_uid)
            rq.revision = 0
            rq.configurationUid = utils.base64_url_encode(configuration_record_uid)
            rq.resourceUid = utils.base64_url_encode(parent_uid)
            rq.schedule = ''
            rq.pwdComplexity = b''
            rq.disabled = False

            if not dry_run:
                router_utils.router_set_record_rotation_information(context.vault, rq)

                context.sync_data = True
                vault.sync_down()
                context.refresh_record_rotations()

                record_rotation = context.get_record_rotation(user_record_uid)
                if record_rotation is None:
                    logger.error(f"Protobuf rotation settings did not create.")
                    return
            else:
                logger.info(f"DRY RUN: Would have created the protobuf rotation settings.")
                record_rotation = SimpleNamespace(
                    configuration_uid=configuration_record_uid,
                    resource_uid=resource_record_uid,
                )

        configuration_record_uid = record_rotation.configuration_uid
        if configuration_record_uid is None:
            logger.error(f"Record does not have the PAM Configuration set.")
            return

        logger.info(f"Configuration Record UID: {configuration_record_uid}")

        configuration_record = vault.vault_data.load_record(configuration_record_uid)
        if configuration_record is None:
            logger.error(f"Configuration record does not exists.")
            return

        resource_record_uid = record_rotation.resource_uid
        if resource_record_uid is not None:

            logger.info(f"Resource Record UID: {resource_record_uid}")

            resource_record = vault.vault_data.get_record(resource_record_uid)
            if resource_record is None:
                logger.error(f"The resource record does not exists.")
                return

            if resource_record.record_type not in [PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY]:
                logger.error(f"The resource is a {PAM_MACHINE}, {PAM_DATABASE}, or {PAM_DIRECTORY} record. "
                      f"It's a {resource_record.record_type}.")
                return

        record_link = RecordLink(record=configuration_record, context=context)

        parent_uid = resource_record_uid or configuration_record_uid
        parent_vertex = record_link.get_record_link(parent_uid)
        if parent_vertex is None:
            parent_type = "configuration"
            if resource_record_uid is not None:
                parent_type = "resource"
            logger.error(f"Could not find the parent linking vertex for the {parent_type}.")
            return

        logger.info(f"User Record UID: {user_record_uid}")

        user_vertex = record_link.get_record_link(user_record_uid)
        if user_vertex is None:
            logger.warning(f"The user vertex is missing; creating.")
            record_link.dag.add_vertex(uid=user_record_uid)

        user_acl = record_link.get_acl(user_record_uid, parent_uid)
        if user_acl is None:
            logger.warning(f"No ACL exists between the user and the parent; creating.")
            user_acl = UserAcl.default()
            user_acl.belongs_to = True

        logger.info("")
        if user_acl.rotation_settings is not None:
            if (force is False and (
                    user_acl.rotation_settings.schedule != ""
                    or user_acl.rotation_settings.pwd_complexity != ""
                    or (user_acl.rotation_settings.saas_record_uid_list is not None
                        and len(user_acl.rotation_settings.saas_record_uid_list) != 0))):
                logger.error(f"{user_acl.model_dump_json(indent=4)}")
                logger.error(f"Rotation settings exist in graph, use --force to reset.")
                return

        user_acl.rotation_settings = UserAclRotationSettings()
        user_acl.rotation_settings.noop = noop
        if resource_record_uid is None:
            user_acl.is_iam_user = True

        record_link.belongs_to(user_record_uid, parent_uid, acl=user_acl)

        if parent_uid != configuration_record_uid:
            if record_link.get_parent_record_uid(parent_uid) is None:
                logger.warning(f"Resource record has no LINK to configuration record; "
                      f"creating.")
                record_link.belongs_to(configuration_record_uid, parent_uid)

        if not dry_run:
            record_link.save()

            logger.info(f"{user_acl.model_dump_json(indent=4)}")
            logger.info(f"Updated the ACL for the user.")
        else:
            logger.info(f"DRY RUN: Would have created this ACL.")
            logger.info(f"{user_acl.model_dump_json(indent=4)}")
