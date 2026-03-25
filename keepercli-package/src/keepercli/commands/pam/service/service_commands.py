import argparse
from ..discovery.__init__ import GatewayContext, PAMGatewayActionDiscoverCommandBase
from ....params import KeeperParams
from .... import api
from ....__init__ import __version__
from ....commands import base

from keepersdk.helpers.keeper_dag.user_service import UserService
from keepersdk.helpers.keeper_dag.dag_types import EdgeType, ServiceAcl, RefType
from keepersdk.helpers.keeper_dag.constants import PAM_MACHINE, PAM_USER
from keepersdk.helpers.keeper_dag.record_link import RecordLink


logger = api.get_logger()


class PAMActionServiceListCommand(PAMGatewayActionDiscoverCommandBase):
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam-action-service-list')
        PAMActionServiceListCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                            help='Gateway name or UID')
        parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                            action='store', help='PAM configuration UID, if gateway has multiple.')

    def execute(self, context: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        vault = context.vault
        gateway_context = GatewayContext.from_gateway(vault=vault,
                                                        gateway=gateway,
                                                        configuration_uid=kwargs.get('configuration_uid'))
        if gateway_context is None:
            logger.error(f"Could not find the gateway configuration for {gateway}.")
            return

        user_service = UserService(record=gateway_context.configuration, context=context, fail_on_corrupt=False,
                                   agent=f"Cmdr/{__version__}")

        service_map = {}
        for resource_vertex in user_service.dag.get_root.has_vertices(edge_type=EdgeType.LINK):
            resource_record = vault.vault_data.load_record(resource_vertex.uid)
            if resource_record is None or resource_record.record_type != PAM_MACHINE:
                continue
            user_vertices = user_service.get_user_vertices(resource_vertex.uid)
            if len(user_vertices) > 0:
                for user_vertex in user_vertices:
                    user_record = vault.vault_data.load_record(user_vertex.uid)
                    if user_record is None:
                        continue
                    acl = user_service.get_acl(resource_record.record_uid, user_record.record_uid)
                    if acl is None or (acl.is_service is False and acl.is_task is False):
                        continue
                    if user_record.record_uid not in service_map:
                        service_map[user_record.record_uid] = {
                            "title": user_record.title,
                            "machines": []
                        }
                    text = f"{resource_record.title} ({resource_record.record_uid}) :"
                    comma = ""
                    if acl.is_service:
                        text += f" Services"
                        comma = ","
                    if acl.is_task:
                        text += f"{comma} Scheduled Tasks"
                    if acl.is_iis_pool:
                        text += f"{comma} IIS Pools"
                    service_map[user_record.record_uid]["machines"].append(text)

        logger.info("")
        printed_something = False
        logger.info("User Mapping")
        for user_uid in service_map:
            user = service_map[user_uid]
            printed_something = True
            logger.info(f"  {user['title']} ({user_uid})")
            for machine in user["machines"]:
                logger.info(f"    * {machine}")
            logger.info("")
        if not printed_something:
            logger.error(f"There are no service mappings.")



class PAMActionServiceAddCommand(PAMGatewayActionDiscoverCommandBase):
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam-action-service-add')
        PAMActionServiceAddCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                            help='Gateway name or UID')
        parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                            action='store', help='PAM configuration UID, if gateway has multiple.')
        parser.add_argument('--machine-uid', '-m', required=True, dest='machine_uid', action='store',
                            help='The UID of the Windows Machine record')
        parser.add_argument('--user-uid', '-u', required=True, dest='user_uid', action='store',
                            help='The UID of the User record')
        parser.add_argument('--type', '-t', required=True, choices=['service', 'task', 'iis'], dest='type',
                            action='store', help='Relationship to add [service, task, iis]')

    def execute(self, context: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        machine_uid = kwargs.get("machine_uid")
        user_uid = kwargs.get("user_uid")
        rel_type = kwargs.get("type")

        logger.info("")
        vault = context.vault

        gateway_context = GatewayContext.from_gateway(vault=vault,
                                                        gateway=gateway,
                                                        configuration_uid=kwargs.get('configuration_uid'))
        if gateway_context is None:
            logger.error(f"Could not find the gateway configuration for {gateway}.")
            return

        if gateway_context is None:
            logger.error(f"Cannot get gateway information. Gateway may not be up.")
            return

        user_service = UserService(record=gateway_context.configuration, context=context, fail_on_corrupt=False,
                                   agent=f"Cmdr/{__version__}")
        record_link = RecordLink(record=gateway_context.configuration, context=context, fail_on_corrupt=False,
                                 agent=f"Cmdr/{__version__}")

        ###############

        # Check to see if the record exists.
        machine_record = vault.vault_data.load_record(machine_uid)
        if machine_record is None:
            logger.error(f"The machine record does not exists.")
            return

        # Make sure the record is a PAM Machine.
        if machine_record.record_type != PAM_MACHINE:
            logger.error(f"The machine record is not a PAM Machine.")
            return

        # Make sure this machine is linked to the configuration record.
        machine_rl = record_link.get_record_link(machine_record.record_uid)
        if machine_rl is None:
            logger.error(f"The machine record does not exists in the graph.")
            return

        # Edges from provider and machine might be wrong.
        # Should be a LINK edge, could be an ACL edge.
        if (machine_rl.get_edge(record_link.dag.get_root, edge_type=EdgeType.LINK) is None and
                machine_rl.get_edge(record_link.dag.get_root, edge_type=EdgeType.ACL) is None):
            logger.error(f"The machine record does not belong to this gateway.")
            return

        ###############

        # Check to see if the record exists.
        user_record = vault.vault_data.load_record(user_uid)
        if user_record is None:
            logger.error(f"The user record does not exists.")
            return

        # Make sure this user is a PAM User.
        if user_record.record_type != PAM_USER:
            logger.error(f"The user record is not a PAM User.")
            return

        record_rotation = params.record_rotation_cache.get(user_record.record_uid)
        if record_rotation is not None:
            controller_uid = record_rotation.get("configuration_uid")
            if controller_uid is None or controller_uid != gateway_context.configuration_uid:
                logger.error(f"The user record does not belong to this gateway. Cannot use this user.")
                return
        else:
            logger.error(f"The user record does not have any rotation settings.")
            return

        ########

        # Make sure we are setting up a Windows machine.
        # Linux and Mac do not use passwords in services and cron jobs; no need to link.
        os_field = next((x for x in machine_record.fields if x.label == "operatingSystem"), None)
        if os_field is None:
            logger.error(f"Cannot find the operating system field in this record.")
            return
        os_type = None
        if len(os_field.value) > 0:
            os_type = os_field.value[0]
        if os_type is None:
            logger.error(f"The operating system field of the machine record is blank.")
            return
        if os_type != "windows":
            logger.error(f"The operating system is not Windows. "
                          "PAM can only rotate the services and scheduled task password on Windows.")
            return

        # Get the machine service vertex.
        # If it doesn't exist, create one.
        machine_vertex = user_service.get_record_link(machine_record.record_uid)
        if machine_vertex is None:
            machine_vertex = user_service.dag.add_vertex(
                uid=machine_record.record_uid,
                name=machine_record.title,
                vertex_type=RefType.PAM_MACHINE)

        # Get the user service vertex.
        # If it doesn't exist, create one.
        user_vertex = user_service.get_record_link(user_record.record_uid)
        if user_vertex is None:
            user_vertex = user_service.dag.add_vertex(
                uid=user_record.record_uid,
                name=user_record.title,
                vertex_type=RefType.PAM_USER)

        # Get the existing service ACL and set the proper attribute.
        acl = user_service.get_acl(machine_vertex.uid, user_vertex.uid)
        if acl is None:
            acl = ServiceAcl()
        if rel_type == "service":
            acl.is_service = True
        elif rel_type == "task":
            acl.is_task = True
        else:
            acl.is_iis_pool = True

        # Make sure the machine has a LINK connection to the configuration.
        if not user_service.dag.get_root.has(machine_vertex):
            user_service.belongs_to(gateway_context.configuration_uid, machine_vertex.uid)

        # Add our new ACL edge between the machine and the yser.
        user_service.belongs_to(machine_vertex.uid, user_vertex.uid, acl=acl)

        user_service.save()

        if rel_type == "service":
            logger.info(
                f"Success: Services running on this machine, using this user, will be updated and restarted after "
                "password rotation."
            )
        elif rel_type == "task":
            logger.info(
                f"Success: Scheduled tasks running on this machine, using this user, will be updated after "
                "password rotation."
            )
        else:
            logger.info(
                f"Success: IIS pools running on this machine, using this user, will be updated after "
                "password rotation."
            )


class PAMActionServiceRemoveCommand(PAMGatewayActionDiscoverCommandBase):

    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam-action-service-remove')
        PAMActionServiceRemoveCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                            help='Gateway name or UID')
        parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                            action='store', help='PAM configuration UID, if gateway has multiple.')
        parser.add_argument('--machine-uid', '-m', required=True, dest='machine_uid', action='store',
                            help='The UID of the Windows Machine record')
        parser.add_argument('--user-uid', '-u', required=True, dest='user_uid', action='store',
                            help='The UID of the User record')
        parser.add_argument('--type', '-t', required=True, choices=['service', 'task', 'iis'], dest='type',
                            action='store', help='Relationship to remove [service, task, iis]')

    def execute(self, context: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        machine_uid = kwargs.get("machine_uid")
        user_uid = kwargs.get("user_uid")
        rel_type = kwargs.get("type")

        logger.info("")
        if not context.vault:
            raise base.CommandError("Vault not found. Login to initialize the vault.")
        vault = context.vault

        gateway_context = GatewayContext.from_gateway(vault=vault,
                                                        gateway=gateway,
                                                        configuration_uid=kwargs.get('configuration_uid'))
        if gateway_context is None:
            logger.error(f"Could not find the gateway configuration for {gateway}.")
            return

        if gateway_context is None:
            logger.error(f"Cannot get gateway information. Gateway may not be up.")
            return

        user_service = UserService(record=gateway_context.configuration, context=context, fail_on_corrupt=False,
                                   agent=f"Cmdr/{__version__}")

        machine_record = vault.vault_data.load_record(machine_uid)
        if machine_record is None:
            logger.error(f"The machine record does not exists.")
            return

        if machine_record.record_type != PAM_MACHINE:
            logger.error(f"The machine record is not a PAM Machine.")
            return

        user_record = vault.vault_data.load_record(user_uid)
        if user_record is None:
            logger.error(f"The user record does not exists.")
            return

        if user_record.record_type != PAM_USER:
            logger.error(f"The user record is not a PAM User.")
            return

        machine_vertex = user_service.get_record_link(machine_record.record_uid)
        if machine_vertex is None:
            logger.error(f"The machine does not exist in the mapping.")
            return

        user_vertex = user_service.get_record_link(user_record.record_uid)
        if user_vertex is None:
            logger.error(f"The user does not exist in the mapping.")
            return

        acl = user_service.get_acl(machine_vertex.uid, user_vertex.uid)
        if acl is None:
            logger.error(f"The user did not control any services, scheduled tasks, or IIS pools on the machine.")
            return

        if rel_type == "service":
            acl.is_service = False
        elif rel_type == "task":
            acl.is_task = False
        else:
            acl.is_iis_pool = False

        if not user_service.dag.get_root.has(machine_vertex):
            user_service.belongs_to(gateway_context.configuration_uid, machine_vertex.uid)

        user_service.belongs_to(machine_vertex.uid, user_vertex.uid, acl=acl)
        user_service.save()

        if rel_type == "service":
            logger.info(
                f"Success: Services running on this machine will no longer have their password changed when this "
                "user's password is rotated."
            )
        elif rel_type == "task":
            logger.info(
                f"Success: Scheduled tasks running on this machine will no longer have their password changed "
                "when this user's password is rotated."
            )
        else:
            logger.info(
                f"Success: IIP pools running on this machine will no longer have their password changed "
                    "when this user's password is rotated."
            )
