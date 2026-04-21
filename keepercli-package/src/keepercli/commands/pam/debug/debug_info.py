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


class PAMDebugInfoCommand(PAMGatewayActionDiscoverCommandBase):

    type_name_map = {
        PAM_USER: "PAM User",
        PAM_MACHINE: "PAM Machine",
        PAM_DATABASE: "PAM Database",
        PAM_DIRECTORY: "PAM Directory",
    }

    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action debug info')
        PAMDebugInfoCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--record-uid', '-i', required=True, dest='record_uid', action='store',
                            help='Keeper PAM record UID.')

    def execute(self, context: KeeperParams, **kwargs):

        record_uid = kwargs.get("record_uid")
        vault = context.vault
        record = vault.vault_data.load_record(record_uid)
        if record is None:
            logger.error(f"Record does not exists.")
            return

        if record.record_type not in ["pamUser", "pamMachine", "pamDatabase", "pamDirectory"]:
            if re.search(r'^pam.+Configuration$', record.record_type) is None:
                logger.error(f"The record is a {record.record_type}. This is not a PAM record.")
                return

        resource_uid = None
        controller_uid = None

        record_rotation = context.get_record_rotation(record_uid)

        # Rotation setting don't exist, check each configuration for an active record.
        if record_rotation is None:
            logger.warning(f"PAM record does not have protobuf rotation settings, "
                  f"checking all configurations.")

            # Get all the PAM configuration records in the Vault; configurations are version 6
            configuration_records = GatewayContext.get_configuration_records(vault=vault)
            if len(configuration_records) == 0:
                logger.error(f"Cannot find any PAM configuration records in the Vault")

            for configuration_record in configuration_records:

                record_link = RecordLink(record=configuration_record, vault=vault)
                record_vertex = record_link.dag.get_vertex(record.record_uid)
                if record_vertex is not None and record_vertex.active is True:
                    controller_uid = configuration_record.record_uid
                    break
            if controller_uid is None:
                logger.error(f"Could not find the record in any record linking graph; "
                      f"checked all configuration records.")
                return

        # Else just get information from the rotation settings
        else:

            controller_uid = record_rotation.configuration_uid
            if controller_uid is None:
                logger.error(f"Record does not have the PAM Configuration set.")
                return

            resource_uid = record_rotation.resource_uid

        configuration_record = vault.vault_data.load_record(controller_uid)
        if configuration_record is None:
            logger.error(f"The configuration record {controller_uid} does not exist.")
            return

        gateway_context = GatewayContext.from_configuration_uid(vault=vault, configuration_uid=controller_uid)
        if gateway_context is None:
            logger.error(f"Could not find the gateway for configuration record.{controller_uid}")
            return

        infra = Infrastructure(record=configuration_record, vault=vault)
        infra.load()
        record_link = RecordLink(record=configuration_record, vault=vault)
        user_service = UserService(record=configuration_record, vault=vault)

        logger.info("")
        logger.info(f"Record Information")
        logger.info(f"  {('Record UID')}: {record_uid}")
        logger.info(f"  {('Record Title')}: {record.title}")
        logger.info(f"  {('Record Type')}: {record.record_type}")
        logger.info(f"  {('Configuration UID')}: {configuration_record.record_uid}")
        logger.info(f"  {('Configuration Key Bytes Hex')}: {configuration_record.record_key.hex()}")
        if resource_uid is not None:
            logger.info(f"  {('Resource UID')}: {resource_uid}")

        if gateway_context is not None:
            logger.info(f"  {('Gateway Name')}: {gateway_context.gateway_name}")
            logger.info(f"  {('Gateway UID')}: {gateway_context.gateway_uid}")
        else:
            logger.error(f"  {('Cannot get gateway information. Gateway may not be up.')}")
        logger.info("")

        def _print_field(f):
            if f.type == "password":
                display_value = f"Password is set"
                if f.value == 0 or len(f.value) == 0:
                    display_value = f"Password IS NOT set"
                logger.info(f"   * Type: {f.type}, Label: {f.label or 'NO LABEL'}, "
                      f"Value(s): {display_value}")
            elif f.label == "privatePEMKey":
                display_value = f"Private Key is set"
                if field.value == 0 or len(f.value) == 0:
                    display_value = f"Private Key IS NOT set"
                logger.info(f"   * Type: {f.type}, Label: {f.label or 'NO LABEL'}, "
                      f"Value(s): {display_value}")
            elif f.type == "secret":
                display_value = f"Secret value is set"
                if field.value == 0 or len(f.value) == 0:
                    display_value = f"Secret value IS NOT set"
                logger.info(f"   * Type: {f.type}, Label: {f.label or 'NO LABEL'}, "
                      f"Value(s): {display_value}")
            else:
                logger.info(f"   * Type: {f.type}, Label: {f.label or 'NO LABEL'}, "
                      f"Value(s): {f.value}")

        logger.info(f"Fields")
        logger.info(f"  Record Type Fields")
        if record.fields is not None and len(record.fields) > 0:
            for field in record.fields:
                _print_field(field)
        else:
            logger.error(f"    Record does not have record type fields!")
        logger.info("")
        logger.info(f"  Custom Fields")
        if record.custom is not None and len(record.custom) > 0:
            for field in record.custom:
                _print_field(field)
        else:
            logger.error(f"    Record does not have custom fields.")
        logger.info("")

        discovery_vertices = infra.dag.search_content({"record_uid": record.record_uid})
        record_vertex = record_link.dag.get_vertex(record.record_uid)

        if record_vertex is not None:
            logger.info(f"Record Linking")
            record_parent_vertices = record_vertex.belongs_to_vertices()
            logger.info(f"  Parent Records")
            if len(record_parent_vertices) > 0:
                for record_parent_vertex in record_parent_vertices:

                    parent_record = vault.vault_data.load_record(
                                                            record_parent_vertex.uid)
                    if parent_record is None:
                        logger.error(f"   * Parent record {record_parent_vertex.uid} "
                              f"does not exists.")
                        continue

                    acl_edge = record_vertex.get_edge(record_parent_vertex, EdgeType.ACL)
                    if acl_edge is not None:
                        acl_content = acl_edge.content_as_object(UserAcl)  # type: UserAcl
                        logger.info(f"    * ACL to {parent_record.record_type}; {parent_record.title}; "
                              f"{record_parent_vertex.uid}")
                        if acl_content.is_admin:
                            logger.info(f"      . Is Admin")
                        if acl_content.belongs_to:
                            logger.info(f"      . Belongs")
                        else:
                            logger.info(f"      . Is Remote user")

                        if acl_content.rotation_settings is None:
                            logger.error(f"      . There are no rotation settings!")
                        else:
                            if (acl_content.rotation_settings.schedule is None
                                    or acl_content.rotation_settings.schedule == ""):
                                logger.info(f"      . No Schedule")
                            else:
                                logger.info(f"      . Schedule = {acl_content.rotation_settings.get_schedule()}")

                            if (acl_content.rotation_settings.pwd_complexity is None
                                    or acl_content.rotation_settings.pwd_complexity == ""):
                                logger.info(f"      . No Password Complexity")
                            else:
                                key_bytes = record.record_key
                                logger.info(f"      . Password Complexity = "
                                      f"{acl_content.rotation_settings.get_pwd_complexity(key_bytes)}")
                            logger.info(f"      . Disabled = {acl_content.rotation_settings.disabled}")
                            logger.info(f"      . NOOP = {acl_content.rotation_settings.noop}")
                            logger.info(f"      . SaaS Config Records = {acl_content.rotation_settings.saas_record_uid_list}")

                    elif record.record_type == PAM_USER:
                        logger.error(f"    * PAM User has NO acl!!!!!!")

                    link_edge = record_vertex.get_edge(record_parent_vertex, EdgeType.LINK)
                    if link_edge is not None:
                        logger.info(f"    * LINK to {parent_record.record_type}; {parent_record.title}; "
                              f"{record_parent_vertex.uid}")
            else:
                # This really should not happen
                logger.error(f"   Record does not have a parent record.")
            logger.info("")

            record_child_vertices = record_vertex.has_vertices()
            logger.info(f"  Child Records")
            if len(record_child_vertices) > 0:
                for record_child_vertex in record_child_vertices:
                    child_record = vault.vault_data.load_record(
                                                           record_child_vertex.uid)

                    if child_record is None:
                        logger.error(f"    * Child record {record_child_vertex.uid} "
                              f"does not exists.")
                        continue

                    acl_edge = record_child_vertex.get_edge(record_vertex, EdgeType.ACL)
                    link_edge = record_child_vertex.get_edge(record_vertex, EdgeType.LINK)
                    if acl_edge is not None:
                        acl_content = acl_edge.content_as_object(UserAcl)
                        logger.info(f"    * ACL from {child_record.record_type}; {child_record.title}; "
                              f"{record_child_vertex.uid}")
                        if acl_content.is_admin:
                            logger.info(f"      . Is Admin")
                        if acl_content.belongs_to:
                            logger.info(f"      . Belongs")
                        else:
                            logger.info(f"      . Is Remote user")
                    elif link_edge is not None:
                        logger.info(f"    * LINK from {child_record.record_type}; {child_record.title}; "
                              "{record_child_vertex.uid}")
                    else:
                        for edge in record_vertex.edges:
                            logger.info(f"    * {edge.edge_type}?")

            else:
                # This is OK
                logger.error(f"    Record does not have any children.")
            logger.info("")

        else:
            logger.error(f"Cannot find record in record linking.")

        # Only PAM User and PAM Machine can have services and tasks.
        # This is really only Windows machines.
        if record.record_type == PAM_USER or record.record_type == PAM_MACHINE:

            # Get the user to service/task vertex.
            user_service_vertex = user_service.dag.get_vertex(record_uid)

            if user_service_vertex is not None:

                # If the record is a PAM User
                if record.record_type == PAM_USER:

                    user_results = {
                        "is_task": [],
                        "is_service": []
                    }

                    # Get a list of all the resources the user is the username/password on service/task.
                    for us_machine_vertex in user_service.get_resource_vertices(record_uid):

                        # Get the resource record
                        us_machine_record = (
                            vault.vault_data.load_record(us_machine_vertex.uid))

                        acl = user_service.get_acl(us_machine_vertex.uid, user_service_vertex.uid)
                        for attr in ["is_task", "is_service"]:
                            value = getattr(acl, attr)
                            if value is True:

                                # If the resource record does not exist.
                                if us_machine_record is None:

                                    # Default the title to Unknown (in red).
                                    # See if we have an infrastructure vertex with this record UID.
                                    # If we do have it, use the title inside the first vertex's data content.
                                    title = "Unknown"
                                    infra_resource_vertices = infra.dag.search_content(
                                        {"record_uid": us_machine_vertex.uid})
                                    if len(infra_resource_vertices) > 0:
                                        infra_resource_vertex = infra_resource_vertices[0]
                                        if infra_resource_vertex.has_data is True:
                                            content = DiscoveryObject.get_discovery_object(infra_resource_vertex)
                                            title = content.title

                                    user_results[attr].append(f"  * Record {us_machine_vertex.uid}, "
                                                              f"{title} does not exists.")

                                # Record exists; just use information from the record.
                                else:
                                    user_results[attr].append(f"  * {us_machine_record.title}, "
                                                              f"{us_machine_vertex.uid}")

                    logger.info(f"Service on Machines")
                    if len(user_results["is_service"]) > 0:
                        for service in user_results["is_service"]:
                            logger.info(service)
                    else:
                        logger.info("  PAM User is not used for any services.")
                    logger.info("")

                    logger.info(f"Scheduled Tasks on Machines")
                    if len(user_results["is_task"]) > 0:
                        for task in user_results["is_task"]:
                            logger.info(task)
                    else:
                        logger.info("  PAM User is not used for any scheduled tasks.")
                    logger.info("")

                # If the record is a PAM Machine
                else:
                    user_results = {
                        "is_task": [],
                        "is_service": []
                    }

                    # Get the users that are used for tasks/services on this machine.
                    for us_user_vertex in user_service.get_user_vertices(record_uid):

                        us_user_record = vault.vault_data.load_record(
                                                                 us_user_vertex.uid)
                        acl = user_service.get_acl(user_service_vertex.uid, us_user_vertex.uid)
                        for attr in ["is_task", "is_service"]:
                            value = getattr(acl, attr)
                            if value is True:

                                # If the user record does not exist.
                                if us_user_record is None:

                                    # Default the title to Unknown (in red).
                                    # See if we have an infrastructure vertex with this record UID.
                                    # If we do have it, use the title inside the first vertex's data content.
                                    title = "Unknown"
                                    infra_resource_vertices = infra.dag.search_content(
                                        {"record_uid": us_user_vertex.uid})
                                    if len(infra_resource_vertices) > 0:
                                        infra_resource_vertex = infra_resource_vertices[0]
                                        if infra_resource_vertex.has_data is True:
                                            content = DiscoveryObject.get_discovery_object(infra_resource_vertex)
                                            title = content.title

                                    user_results[attr].append(f"  * Record {us_user_vertex.uid}, "
                                                              f"{title} does not exists.")

                                # Record exists; just use information from the record.
                                else:
                                    user_results[attr].append(f"  * {us_user_record.title}, "
                                                              f"{us_user_vertex.uid}")

                    logger.info(f"Users that are used for Services")
                    if len(user_results["is_service"]) > 0:
                        for service in user_results["is_service"]:
                            logger.info(service)
                    else:
                        logger.info("  Machine does not use any non-builtin users for services.")
                    logger.info("")

                    logger.info(f"Users that are used for Scheduled Tasks")
                    if len(user_results["is_task"]) > 0:
                        for task in user_results["is_task"]:
                            logger.info(task)
                    else:
                        logger.info("  Machine does not use any non-builtin users for scheduled tasks.")
                    logger.info("")
            else:
                logger.error(f"There are no services or schedule tasks associated with this record.")
                logger.info("")
        try:
            if len(discovery_vertices) == 0:
                logger.error(f"Could not find any discovery infrastructure vertices for "
                      f"{record.record_uid}")
            elif len(discovery_vertices) > 0:

                if len(discovery_vertices) > 1:
                    logger.error(f"Found multiple vertices with the record UID of "
                          f"{record.record_uid}")
                    for vertex in discovery_vertices:
                        logger.info(f" * Infrastructure Vertex UID: {vertex.uid}")
                    logger.info("")

                discovery_vertex = discovery_vertices[0]
                content = DiscoveryObject.get_discovery_object(discovery_vertex)

                missing_since = "NA"
                if content.missing_since_ts is not None:
                    missing_since = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(content.missing_since_ts))

                logger.info(f"Discovery Object Information")
                logger.info(f"  Vertex UID: {content.uid}")
                logger.info(f"  Object ID: {content.id}")
                logger.info(f"  Record UID: {content.record_uid}")
                logger.info(f"  Parent Record UID: {content.parent_record_uid}")
                logger.info(f"  Shared Folder UID: {content.shared_folder_uid}")
                logger.info(f"  Record Type: {content.record_type}")
                logger.info(f"  Object Type: {content.object_type_value}")
                logger.info(f"  Ignore Object: {content.ignore_object}")
                logger.info(f"  Rule Engine Result: {content.action_rules_result}")
                logger.info(f"  Name: {content.name}")
                logger.info(f"  Generated Title: {content.title}")
                logger.info(f"  Generated Description: {content.description}")
                logger.info(f"  Missing Since: {missing_since}")
                logger.info(f"  Discovery Notes:")
                for note in content.notes:
                    logger.info(f" * {note}")
                if content.error is not None:
                    logger.error(f"    Error: {content.error}")
                    if content.stacktrace is not None:
                        logger.error(f"    Stack Trace:")
                        logger.error(f"{content.stacktrace}")
                logger.info("")
                logger.info(f"Record Type Specifics")

                if record.record_type == PAM_USER:
                    logger.info(f"  User: {content.item.user}")
                    logger.info(f"  DN: {content.item.dn}")
                    logger.info(f"  Database: {content.item.database}")
                    logger.info(f"  Active: {content.item.active}")
                    logger.info(f"  Expired: {content.item.expired}")
                    logger.info(f"  Source: {content.item.source}")
                elif record.record_type == PAM_MACHINE:
                    logger.info(f"  Host: {content.item.host}")
                    logger.info(f"  IP: {content.item.ip}")
                    logger.info(f"  Port: {content.item.port}")
                    logger.info(f"  Operating System: {content.item.os}")
                    logger.info(f"  Provider Region: {content.item.provider_region}")
                    logger.info(f"  Provider Group: {content.item.provider_group}")
                    logger.info(f"  Is the Gateway: {content.item.is_gateway}")
                    logger.info(f"  Allows Admin: {content.item.allows_admin}")
                    logger.info(f"  Admin Reason: {content.item.admin_reason}")
                    logger.info("")
                    # If facts are not set, inside discover may not have been performed for the machine.
                    if content.item.facts.id is not None and content.item.facts.name is not None:
                        logger.info(f"  Machine Name: {content.item.facts.name}")
                        logger.info(f"  Machine ID: {content.item.facts.id.machine_id}")
                        logger.info(f"  Product ID: {content.item.facts.id.product_id}")
                        logger.info(f"  Board Serial: {content.item.facts.id.board_serial}")
                        logger.info(f"  Directories:")
                        if content.item.facts.directories is not None and len(content.item.facts.directories) > 0:
                            for directory in content.item.facts.directories:
                                logger.info(f"    * Directory Domain: {directory.domain}")
                                logger.info(f"      Software: {directory.software}")
                                logger.info(f"      Login Format: {directory.login_format}")
                        else:
                            logger.info("    Machines is not using any directories.")

                        logger.info("")
                        logger.info(f"  Services (Non Builtin Users):")
                        if len(content.item.facts.services) > 0:
                            for service in content.item.facts.services:
                                logger.info(f"    * {service.name} = {service.user}")
                        else:
                            logger.info("    Machines has no services that are using non-builtin users.")

                        logger.info(f"  Scheduled Tasks (Non Builtin Users)")
                        if len(content.item.facts.tasks) > 0:
                            for task in content.item.facts.tasks:
                                logger.info(f"    * {task.name} = {task.user}")
                        else:
                            logger.info("    Machines has no schedules tasks that are using non-builtin users.")

                        logger.info(f"  IIS Pools (Non Builtin Users)")
                        if len(content.item.facts.iis_pools) > 0:
                            for iis_pool in content.item.facts.iis_pools:
                                logger.info(f"    * {iis_pool.name} = {iis_pool.user}")
                        else:
                            logger.info("    Machines has no IIS Pools that are using non-builtin users.")
                    else:
                        logger.error(f"    Machine facts are not set. Discover inside may not have been "
                              f"performed.")
                elif record.record_type == PAM_DATABASE:
                    logger.info(f"  Host: {content.item.host}")
                    logger.info(f"  IP: {content.item.ip}")
                    logger.info(f"  Port: {content.item.port}")
                    logger.info(f"  Database Type: {content.item.type}")
                    logger.info(f"  Database: {content.item.database}")
                    logger.info(f"  Use SSL: {content.item.use_ssl}")
                    logger.info(f"  Provider Region: {content.item.provider_region}")
                    logger.info(f"  Provider Group: {content.item.provider_group}")
                    logger.info(f"  Allows Admin: {content.item.allows_admin}")
                    logger.info(f"  Admin Reason: {content.item.admin_reason}")
                elif record.record_type == PAM_DIRECTORY:
                    logger.info(f"  Host: {content.item.host}")
                    logger.info(f"  IP: {content.item.ip}")
                    logger.info(f"  Port: {content.item.port}")
                    logger.info(f"  Directory Type: {content.item.type}")
                    logger.info(f"  Use SSL: {content.item.use_ssl}")
                    logger.info(f"  Provider Region: {content.item.provider_region}")
                    logger.info(f"  Provider Group: {content.item.provider_group}")
                    logger.info(f"  Allows Admin: {content.item.allows_admin}")
                    logger.info(f"  Admin Reason: {content.item.admin_reason}")
                else:
                    for k, v in content.item:
                        logger.info(f"  {k}: {v}")

                # Configuration records do not belong to other record; don't show.
                if record.version != 6:
                    logger.info("")
                    logger.info(f"Belongs To Vertices (Parents)")
                    vertices = discovery_vertex.belongs_to_vertices()
                    for vertex in vertices:
                        try:
                            content = DiscoveryObject.get_discovery_object(vertex)
                            logger.info(f"  * {content.description} ({vertex.uid})")
                            for edge_type in [EdgeType.LINK, EdgeType.ACL, EdgeType.KEY, EdgeType.DELETION]:
                                edge = discovery_vertex.get_edge(vertex, edge_type=edge_type)
                                if edge is not None:
                                    logger.info(f"    . {edge_type}, active: {edge.active}")
                        except Exception as err:
                            logger.error(f"Could not get belongs to information: {err}")

                    if len(vertices) == 0:
                        logger.error(f"  Does not belong to anyone")

                print("")
                logger.info(f"Vertices Belonging To (Children)")
                vertices = discovery_vertex.has_vertices()
                for vertex in vertices:
                    try:
                        content = DiscoveryObject.get_discovery_object(vertex)
                        logger.info(f"  * {content.description} ({vertex.uid})")
                        for edge_type in [EdgeType.LINK, EdgeType.ACL, EdgeType.KEY, EdgeType.DELETION]:
                            edge = vertex.get_edge(discovery_vertex, edge_type=edge_type)
                            if edge is not None:
                                logger.info(f"    . {edge_type}, active: {edge.active}")
                    except Exception as err:
                        logger.error(f"Could not get belonging to information: {err}")
                if len(vertices) == 0:
                    logger.error(f"  Does not have any children.")

                logger.info("")
            else:
                logger.error(f"Could not find infrastructure vertex.")
        except Exception as err:
            logger.error(f"Could not get information on infrastructure: {err}")
