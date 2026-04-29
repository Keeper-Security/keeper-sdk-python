import argparse
import re
import time

from keepersdk.helpers.keeper_dag.user_service import Infrastructure

from ....params import KeeperParams
from keepersdk.helpers.keeper_dag.constants import PAM_USER, PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY
from keepersdk.helpers.keeper_dag.dag_types import DiscoveryObject
from keepersdk.helpers.keeper_dag.dag import EdgeType
from ..discovery.__init__ import GatewayContext, PAMGatewayActionDiscoverCommandBase
from .... import api

logger = api.get_logger()

class PAMDebugVertexCommand(PAMGatewayActionDiscoverCommandBase):
    type_name_map = {
        PAM_USER: "PAM User",
        PAM_MACHINE: "PAM Machine",
        PAM_DATABASE: "PAM Database",
        PAM_DIRECTORY: "PAM Directory",
    }
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action debug vertex')
        PAMDebugVertexCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID')
        parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                        action='store', help='PAM configuration UID, if gateway has multiple.')
        parser.add_argument('--vertex', '-i', required=True, dest='vertex_uid', action='store',
                        help='Vertex in infrastructure graph')
    
    def execute(self, context: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        debug_level = kwargs.get("debug_level", False)

        configuration_uid = kwargs.get('configuration_uid')

        gateway_context = GatewayContext.from_gateway(vault=context.vault,
                                                        gateway=gateway,
                                                        configuration_uid=configuration_uid)
        if gateway_context is None:
            logger.error(f"Could not find the gateway configuration for {gateway}.")
            return

        infra = Infrastructure(record=gateway_context.configuration, context=context, fail_on_corrupt=False,
                               debug_level=debug_level)
        infra.load()

        vertex_uid = kwargs.get("vertex_uid")
        vertex = infra.dag.get_vertex(vertex_uid)
        if vertex is None:
            logger.error(f"Could not find the vertex in the graph for {gateway}.")
            return

        content = DiscoveryObject.get_discovery_object(vertex)
        missing_since = "NA"
        if content.missing_since_ts is not None:
            missing_since = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(content.missing_since_ts))

        logger.info(f"Discovery Object Information")
        logger.info(f"Vertex UID: {content.uid}")
        logger.info(f"Object ID: {content.id}")
        logger.info(f"Record UID: {content.record_uid}")
        logger.info(f"Parent Record UID: {content.parent_record_uid}")
        logger.info(f"Shared Folder UID: {content.shared_folder_uid}")
        logger.info(f"Record Type: {content.record_type}")
        logger.info(f"Object Type: {content.object_type_value}")
        logger.info(f"Ignore Object: {content.ignore_object}")
        logger.info(f"Rule Engine Result: {content.action_rules_result}")
        logger.info(f"Name: {content.name}")
        logger.info(f"Generated Title: {content.title}")
        logger.info(f"Generated Description: {content.description}")
        logger.info(f"Missing Since: {missing_since}")
        logger.info(f"Discovery Notes:")
        for note in content.notes:
            logger.info(f" * {note}")
        if content.error is not None:
            logger.error(f"    Error: {content.error}")
            if content.stacktrace is not None:
                logger.error(f"    Stack Trace:")
                logger.error(f"{content.stacktrace}")
        logger.info("")
        logger.info(f"Record Type Specifics")

        if content.record_type == PAM_USER:
            logger.info(f"User: {content.item.user}")
            logger.info(f"DN: {content.item.dn}")
            logger.info(f"Database: {content.item.database}")
            logger.info(f"Active: {content.item.active}")
            logger.info(f"Expired: {content.item.expired}")
            logger.info(f"Source: {content.item.source}")
        elif content.record_type == PAM_MACHINE:
            logger.info(f"Host: {content.item.host}")
            logger.info(f"IP: {content.item.ip}")
            logger.info(f"Port: {content.item.port}")
            logger.info(f"Operating System: {content.item.os}")
            logger.info(f"Provider Region: {content.item.provider_region}")
            logger.info(f"Provider Group: {content.item.provider_group}")
            logger.info(f"Is the Gateway: {content.item.is_gateway}")
            logger.info(f"Allows Admin: {content.item.allows_admin}")
            logger.info(f"Admin Reason: {content.item.admin_reason}")
            logger.info("")

            if content.item.facts.id is not None and content.item.facts.name is not None:
                logger.info(f"Machine Name: {content.item.facts.name}")
                logger.info(f"Machine ID: {content.item.facts.id.machine_id}")
                logger.info(f"Product ID: {content.item.facts.id.product_id}")
                logger.info(f"Board Serial: {content.item.facts.id.board_serial}")
                logger.info(f"Directories:")
                if content.item.facts.directories is not None and len(content.item.facts.directories) > 0:
                    for directory in content.item.facts.directories:
                        logger.info(f"    * Directory Domain: {directory.domain}")
                        logger.info(f"      Software: {directory.software}")
                        logger.info(f"      Login Format: {directory.login_format}")
                else:
                    logger.info("    Machines is not using any directories.")

                logger.info("")
                logger.info(f"Services (Non Builtin Users):")
                if len(content.item.facts.services) > 0:
                    for service in content.item.facts.services:
                        logger.info(f"    * {service.name} = {service.user}")
                else:
                    logger.info("    Machines has no services that are using non-builtin users.")

                logger.info(f"Scheduled Tasks (Non Builtin Users)")
                if len(content.item.facts.tasks) > 0:
                    for task in content.item.facts.tasks:
                        logger.info(f"    * {task.name} = {task.user}")
                else:
                    logger.info("    Machines has no schedules tasks that are using non-builtin users.")

                logger.info(f"IIS Pools (Non Builtin Users)")
                if len(content.item.facts.iis_pools) > 0:
                    for iis_pool in content.item.facts.iis_pools:
                        logger.info(f"    * {iis_pool.name} = {iis_pool.user}")
                else:
                    logger.info("    Machines has no IIS Pools that are using non-builtin users.")

            else:
                logger.error(f"    Machine facts are not set. Discover inside may not have been "
                      f"performed.")
        elif content.record_type == PAM_DATABASE:
            logger.info(f"Host: {content.item.host}")
            logger.info(f"IP: {content.item.ip}")
            logger.info(f"Port: {content.item.port}")
            logger.info(f"Database Type: {content.item.type}")
            logger.info(f"Database: {content.item.database}")
            logger.info(f"Use SSL: {content.item.use_ssl}")
            logger.info(f"Provider Region: {content.item.provider_region}")
            logger.info(f"Provider Group: {content.item.provider_group}")
            logger.info(f"Allows Admin: {content.item.allows_admin}")
            logger.info(f"Admin Reason: {content.item.admin_reason}")
        elif content.record_type == PAM_DIRECTORY:
            logger.info(f"Host: {content.item.host}")
            logger.info(f"IP: {content.item.ip}")
            logger.info(f"Port: {content.item.port}")
            logger.info(f"Directory Type: {content.item.type}")
            logger.info(f"Use SSL: {content.item.use_ssl}")
            logger.info(f"Provider Region: {content.item.provider_region}")
            logger.info(f"Provider Group: {content.item.provider_group}")
            logger.info(f"Allows Admin: {content.item.allows_admin}")
            logger.info(f"Admin Reason: {content.item.admin_reason}")

        logger.info("")
        logger.info(f"Belongs To Vertices (Parents)")
        vertices = vertex.belongs_to_vertices()
        for vertex in vertices:
            content = DiscoveryObject.get_discovery_object(vertex)
            logger.info(f"  * {content.description} ({vertex.uid})")
            for edge_type in [EdgeType.LINK, EdgeType.ACL, EdgeType.KEY, EdgeType.DELETION]:
                edge = vertex.get_edge(vertex, edge_type=edge_type)
                if edge is not None:
                    logger.info(f"    . {edge_type}, active: {edge.active}")

        if len(vertices) == 0:
            logger.error(f"  Does not belong to anyone")

        logger.info("")
        logger.info(f"Vertices Belonging To (Children)")
        vertices = vertex.has_vertices()
        for vertex in vertices:
            content = DiscoveryObject.get_discovery_object(vertex)
            logger.info(f"  * {content.description} ({vertex.uid})")
            for edge_type in [EdgeType.LINK, EdgeType.ACL, EdgeType.KEY, EdgeType.DELETION]:
                edge = vertex.get_edge(vertex, edge_type=edge_type)
                if edge is not None:
                    logger.info(f"    . {edge_type}, active: {edge.active}")
        if len(vertices) == 0:
            logger.info(f"  Does not have any children.")

        logger.info("")
