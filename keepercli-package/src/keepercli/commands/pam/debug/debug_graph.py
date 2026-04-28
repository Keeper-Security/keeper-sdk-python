import argparse
import logging
from typing import Optional

from keepersdk.helpers.keeper_dag.jobs import Jobs
from keepersdk.helpers.keeper_dag.process import VERTICES_SORT_MAP, DiscoveryObject

from ....params import KeeperParams
from keepersdk.helpers.keeper_dag.constants import PAM_USER, PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY
from keepersdk.helpers.keeper_dag.record_link import RecordLink
from keepersdk.helpers.keeper_dag.infrastructure import Infrastructure
from keepersdk.helpers.keeper_dag.user_service import UserService
from keepersdk.helpers.keeper_dag.dag_types import DiscoveryUser, DiscoveryDirectory, DiscoveryMachine, DiscoveryDatabase, JobContent
from keepersdk.helpers.keeper_dag.dag import DAGVertex, DAG
from keepersdk.helpers.keeper_dag.constants import DIS_INFRA_GRAPH_ID, RECORD_LINK_GRAPH_ID, USER_SERVICE_GRAPH_ID, DIS_JOBS_GRAPH_ID
from keepersdk.helpers.keeper_dag.dag_sort import sort_infra_vertices
from ..discovery.__init__ import GatewayContext, PAMGatewayActionDiscoverCommandBase
from .... import api
from . import get_connection

logger = api.get_logger()

class PAMDebugGraphCommand(PAMGatewayActionDiscoverCommandBase):

    NO_RECORD = "NO RECORD"
    OTHER = "OTHER"

    mapping = {
        PAM_USER: {"order": 1, "sort": "_sort_name", "item": DiscoveryUser, "key": "user"},
        PAM_DIRECTORY: {"order": 1, "sort": "_sort_name", "item": DiscoveryDirectory, "key": "host_port"},
        PAM_MACHINE: {"order": 2, "sort": "_sort_host", "item": DiscoveryMachine, "key": "host"},
        PAM_DATABASE: {"order": 3, "sort": "_sort_host", "item": DiscoveryDatabase, "key": "host_port"},
    }

    graph_id_map = {
        "infra": DIS_INFRA_GRAPH_ID,
        "rl": RECORD_LINK_GRAPH_ID,
        "service": USER_SERVICE_GRAPH_ID,
        "jobs": DIS_JOBS_GRAPH_ID
    }
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action debug graph')
        PAMDebugGraphCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                            help='Gateway name or UID.')
        parser.add_argument('--configuration-uid', "-c", required=False, dest='configuration_uid',
                            action='store', help='PAM configuration UID, if gateway has multiple.')
        parser.add_argument('--type', '-t', required=True, choices=['infra', 'rl', 'service', 'jobs'],
                            dest='graph_type', action='store', help='Graph type', default='infra')
        parser.add_argument('--raw', required=False, dest='raw', action='store_true',
                            help='Render raw graph. Will render corrupt graphs.')
        parser.add_argument('--list', required=False, dest='do_text_list', action='store_true',
                            help='List items in a list.')
        parser.add_argument('--render', required=False, dest='do_render', action='store_true',
                            help='Render a graph')
        parser.add_argument('--file', '-f', required=False, dest='filepath', action='store',
                            default="keeper_graph", help='Base name for the graph file.')
        parser.add_argument('--format', required=False, choices=['raw', 'dot', 'twopi', 'patchwork'],
                            dest='format', default="dot", action='store', help='The format of the graph.')
        parser.add_argument('--debug-gs-level', required=False, dest='debug_level', action='store',
                            help='GraphSync debug level. Default is 0', type=int, default=0)

    def _do_text_list_infra(self, context: KeeperParams, gateway_context: GatewayContext, debug_level: int = 0,
                            indent: int = 0):

        infra = Infrastructure(record=gateway_context.configuration, context=context, logger=logging,
                               debug_level=debug_level)
        infra.load(sync_point=0)

        try:
            configuration = infra.get_root.has_vertices()[0]
        except (Exception,):
            logger.error(f"Could not find the configuration in the infrastructure graph. "
                  f"Has discovery been run for this gateway?")

            return

        line_start = {
            0: "",
            1: "* ",
            2: "- ",
        }

        def _handle(current_vertex: DAGVertex, indent: int = 0, last_record_type: Optional[str] = None):

            if not current_vertex.active:
                return

            pad = ""
            if indent > 0:
                pad = "".ljust(4 * indent, ' ')

            text = ""
            ls = line_start.get(indent, "  ")

            if not current_vertex.active:
                text += f"{pad}{current_vertex.uid} (Inactive)"
            elif not current_vertex.corrupt:
                current_content = DiscoveryObject.get_discovery_object(current_vertex)
                if current_content.record_uid is None:
                    text += f"{pad}{ls}{current_vertex.uid}; {current_content.title} does not have a record."
                else:
                    record = context.vault.vault_data.load_record(current_content.record_uid)
                    if record is not None:
                        text += f"{pad}{ls}" + (f"{current_vertex.uid}; {record.title}; {record.record_uid}")
                    else:
                        text += f"{pad}{ls}" + (f"{current_vertex.uid}; {current_content.title}; have record uid, record does not exists, might have to sync.")
            else:
                text += f"{pad}{current_vertex.uid} (Corrupt)"

            logger.info(text)

            record_type_to_vertices_map = sort_infra_vertices(current_vertex)

            for record_type in sorted(record_type_to_vertices_map, key=lambda i: VERTICES_SORT_MAP[i]['order']):
                for vertex in record_type_to_vertices_map[record_type]:
                    if last_record_type is None or last_record_type != record_type:
                        if indent == 0:
                            logger.info(f"{pad}  {record_type}")
                        last_record_type = record_type

                    _handle(vertex, indent=indent+1)

        logger.info("")
        _handle(configuration, indent=indent)
        logger.info("")

    def _do_text_list_rl(self, context: KeeperParams, gateway_context: GatewayContext, debug_level: int = 0,
                         indent: int = 0):

        logger.info("")

        pad = ""
        if indent > 0:
            pad = "".ljust(4 * indent, ' ')

        record_link = RecordLink(record=gateway_context.configuration,
                                 context=context,
                                 logger=logging,
                                 debug_level=debug_level)
        configuration = record_link.dag.get_root
        
        record = context.vault.vault_data.get_record(record_uid=configuration.uid)
        if record is None:
            logger.error(f"Configuration record does not exists.")
            return
        
        logger.info(f"{pad}{record.record_type}, {record.title}, {record.record_uid}")

        if configuration.has_data:
            try:
                data = configuration.content_as_dict
                logger.info(f"{pad}  . data")
                for k, v in data.items():
                    logger.info(f"{pad}    + {k} = {v}")
            except Exception as err:
                logger.error(f"{pad}    ! data not JSON: {err}")

        def _group(configuration_vertex: DAGVertex) -> dict:

            group = {
                PAM_USER: [],
                PAM_DIRECTORY: [],
                PAM_DATABASE: [],
                PAM_MACHINE: [],
                PAMDebugGraphCommand.NO_RECORD: [],
                PAMDebugGraphCommand.OTHER: []
            }

            for vertex in configuration_vertex.has_vertices():
                record = context.vault.vault_data.get_record(record_uid=vertex.uid)
                if record is None:
                    group[PAMDebugGraphCommand.NO_RECORD].append({
                        "v": vertex
                    })
                    continue
                rt = record.record_type
                if rt not in group:
                    rt = PAMDebugGraphCommand.OTHER
                group[rt].append({
                    "v": vertex,
                    "r": record
                })

            return group
        
        group = _group(configuration)
        
        for record_type in [PAM_USER, PAM_DIRECTORY, PAM_MACHINE, PAM_DATABASE]:
            if len(group[record_type]) > 0:
                logger.info(f"{pad}  {record_type}")
                for item in group[record_type]:
                    vertex = item.get("v")
                    record = item.get("r")
                    text = f"{record.title}; {record.record_uid}"
                    if not vertex.active:
                        text += " Inactive"
                    logger.info(f"{pad}    * {text}")

                    if record_type == PAM_USER:
                        acl = record_link.get_acl(vertex.uid, configuration.uid)
                        if acl is None:
                            logger.info(f"{pad}      missing ACL")
                        else:
                            if acl.is_iam_user:
                                logger.info(f"{pad}      . is IAM user")
                            if acl.is_admin:
                                logger.info(f"{pad}        . is the Admin")
                            if acl.belongs_to:
                                logger.info(f"{pad}      . belongs to this resource")
                            else:
                                logger.info(f"{pad}      . looks like directory user")

                            if acl.rotation_settings:
                                if acl.rotation_settings.noop:
                                    logger.info(f"{pad}      . is a NOOP")
                                if acl.rotation_settings.disabled:
                                    logger.info(f"{pad}      . rotation is disabled")

                                if (acl.rotation_settings.saas_record_uid_list is not None
                                        and len(acl.rotation_settings.saas_record_uid_list) > 0):
                                    logger.info(f"{pad}      . has SaaS rotation: "
                                          f"{acl.rotation_settings.saas_record_uid_list[0]}")

                        continue

                    if vertex.has_data:
                        try:
                            data = vertex.content_as_dict
                            logger.info(f"{pad}      . data")
                            for k, v in data.items():
                                logger.info(f"{pad}        + {k} = {v}")
                        except Exception as err:
                            logger.error(f"{pad}        ! data not JSON: {err}")

                    children = vertex.has_vertices()
                    if len(children) > 0:
                        bad = []
                        for child in children:
                            child_record = context.vault.vault_data.load_record(record_uid=child.uid)
                            if child_record is None:
                                if child.active:
                                    bad.append(f"- Record UID {child.uid} does not exists.")
                                continue
                            else:
                                logger.info(f"{pad}      - {child_record.title}; {child_record.record_uid}")
                                acl = record_link.get_acl(child.uid, vertex.uid)
                                if acl is None:
                                    logger.info(f"{pad}        missing ACL")
                                else:
                                    if acl.is_admin:
                                        logger.info(f"{pad}        . is the Admin")
                                    if acl.belongs_to:
                                        logger.info(f"{pad}        . belongs to this resource")
                                    else:
                                        logger.info(f"{pad}        . looks like directory user")

                                if child.has_data:
                                    try:
                                        data = child.content_as_dict
                                        logger.info(f"{pad}        . data")
                                        for k, v in data.items():
                                            logger.info(f"{pad}          + {k} = {v}")
                                    except Exception as err:
                                        logger.info(f"{pad}          ! data not JSON: {err}")
                        for i in bad:
                            logger.error(f"{pad}      {i}")

        if len(group[PAMDebugGraphCommand.OTHER]) > 0:
            logger.info(f"{pad}  Other PAM Types")
            for item in group[PAMDebugGraphCommand.OTHER]:
                vertex = item.get("v")
                record = item.get("r")
                text = f"{record.record_type}; {record.title}; {record.record_uid}"
                if not vertex.active:
                    text += " Inactive"
                logger.info(f"{pad}    * {text}")

        if len(group[PAMDebugGraphCommand.NO_RECORD]) > 0:

            logger.info(f"{pad}  In Graph, No Vault Record")
            for item in group[PAMDebugGraphCommand.NO_RECORD]:
                vertex = item.get("v")
                logger.info(f"{pad}    * {vertex.uid}")

    def _do_text_list_service(self, context: KeeperParams, gateway_context: GatewayContext, debug_level: int = 0,
                              indent: int = 0):

        user_service = UserService(record=gateway_context.configuration, context=context, logger=logging,
                                   debug_level=debug_level)
        configuration = user_service.dag.get_root

        def _handle(current_vertex: DAGVertex, parent_vertex: Optional[DAGVertex] = None, indent: int = 0):

            pad = ""
            if indent > 0:
                pad = "".ljust(2 * indent, ' ') + "* "

            record = context.vault.vault_data.get_record(record_uid=current_vertex.uid)
            if record is None:
                if not current_vertex.active:
                    logger.info(f"{pad}Record {current_vertex.uid} does not exists, inactive in the graph.")
                else:
                    logger.info(f"{pad}Record {current_vertex.uid} does not exists, active in the graph.")
                return
            elif not current_vertex.active:
                logger.info(f"{pad}{record.record_type}, {record.title}, {record.record_uid} exists, "
                      "inactive in the graph.")
                return

            acl_text = ""
            if parent_vertex is not None:
                acl = user_service.get_acl(resource_uid=parent_vertex.uid, user_uid=current_vertex.uid)
                if acl is not None:
                    acl_text = "No Services"
                    acl_parts = []
                    if acl.is_service:
                        acl_parts.append("Service")
                    if acl.is_task:
                        acl_parts.append("Task")
                    if acl.is_iis_pool:
                        acl_parts.append("Task")
                    if len(acl_parts) > 0:
                        acl_text = ", ".join(acl_parts)
                    acl_text = f" -> {acl_text}"

            logger.info(f"{pad}{record.record_type}, {record.title}, {record.record_uid}{acl_text}")

            for vertex in current_vertex.has_vertices():
                _handle(current_vertex=vertex, parent_vertex=current_vertex, indent=indent+1)

        _handle(current_vertex=configuration, parent_vertex=None, indent=indent)

    def _do_text_list_jobs(self, context: KeeperParams, gateway_context: GatewayContext, debug_level: int = 0,
                           indent: int = 0):

        infra = Infrastructure(record=gateway_context.configuration, context=context, logger=logging,
                               debug_level=debug_level, fail_on_corrupt=False)
        infra.load(sync_point=0)

        pad = ""
        if indent > 0:
            pad = "".ljust(2 * indent, ' ') + "* "

        conn = get_connection(context=context)
        graph_sync = DAG(conn=conn, record=gateway_context.configuration, logger=logging, debug_level=debug_level,
                         graph_id=DIS_JOBS_GRAPH_ID)
        graph_sync.load(0)
        configuration = graph_sync.get_root
        vertices = configuration.has_vertices()
        if len(vertices) == 0:
            logger.error(f"The jobs graph has not been initialized. Only has root vertex.")
            return

        vertex = vertices[0]
        if not vertex.has_data:
            logger.error(f"The job vertex does not contain any data")
            return

        current_json = vertex.content_as_str
        if current_json is None:
            logger.error(f"The current job vertex content is None")
            return

        content = JobContent.model_validate_json(current_json)
        logger.info(f"{pad}Active Job ID: {content.active_job_id}")
        logger.info("")
        logger.info(f"{pad}History")
        logger.info("")
        for job in content.job_history:
            logger.info(f"{pad}  --------------------------------------")
            logger.info(f"{pad}  Job Id: {job.job_id}")
            logger.info(f"{pad}  Started: {job.start_ts_str}")
            logger.info(f"{pad}  Ended: {job.end_ts_str}")
            logger.info(f"{pad}  Duration: {job.duration_sec_str}")
            logger.info(f"{pad}  Infra Sync Point: {job.sync_point}")
            if job.success:
                logger.info(f"{pad}  Status: Success")
            else:
                logger.info(f"{pad}  Status: Fail")
            if job.error is not None:
                logger.info(f"{pad}  Error: {job.error}")

            logger.info("")

            if job.delta is None:
                logger.error(f"{pad}The job is missing a delta, never finished discovery.")
            else:
                if len(job.delta.added) > 0:
                    logger.info(f"{pad}  Added")
                    for added in job.delta.added:
                        vertex = infra.dag.get_vertex(added.uid)
                        if vertex is None:
                            logger.info(f"{pad}  * Vertex {added.uid} does not exists.")
                        else:
                            if not vertex.active:
                                logger.info(f"{pad}  * Vertex {added.uid} is inactive.")
                            elif vertex.corrupt:
                                logger.info(f"{pad}  * Vertex {added.uid} is corrupt.")
                            else:
                                content = DiscoveryObject.get_discovery_object(vertex)
                                logger.info(f"{pad}  * {content.description}; Record UID: {content.record_uid}")
                    logger.info("")

                if len(job.delta.changed) > 0:
                    logger.info(f"{pad}  Changed")
                    for changed in job.delta.changed:
                        vertex = infra.dag.get_vertex(changed.uid)
                        if vertex is None:
                            logger.info(f"{pad}  * Vertex {changed.uid} does not exists.")
                        else:
                            if not vertex.active:
                                logger.info(f"{pad}  * Vertex {changed.uid} is inactive.")
                            elif vertex.corrupt:
                                logger.info(f"{pad}  * Vertex {changed.uid} is corrupt.")
                            else:
                                content = DiscoveryObject.get_discovery_object(vertex)
                                logger.info(f"{pad}  * {content.description}; Record UID: {content.record_uid}")
                                if changed.changes is not None:
                                    for k, v in changed.changes.items():
                                        logger.info(f"{pad}    {k} = {v}")
                    logger.info("")

                if len(job.delta.deleted) > 0:
                    logger.info(f"{pad}  Deleted")
                    for deleted in job.delta.deleted:
                        logger.info(f"{pad}  * Removed vertex {deleted.uid}.")
                    logger.info("")

    def _do_render_infra(self, context: KeeperParams, gateway_context: GatewayContext, filepath: str, graph_format: str,
                         debug_level: int = 0):

        infra = Infrastructure(record=gateway_context.configuration, context=context, logger=logging,
                               debug_level=debug_level)
        infra.load(sync_point=0)

        logger.info("")
        dot_instance = infra.to_dot(
            graph_type=graph_format if graph_format != "raw" else "dot",
            show_only_active_vertices=False,
            show_only_active_edges=False
        )
        if graph_format == "raw":
            logger.info(dot_instance)
        else:
            try:
                dot_instance.render(filepath)
                logger.info(f"Infrastructure graph rendered to {filepath}")
            except Exception as err:
                logger.error(f"Could not generate graph: {err}")
                raise err
        logger.info("")

    def _do_render_rl(self, context: KeeperParams, gateway_context: GatewayContext, filepath: str, graph_format: str,
                      debug_level: int = 0):

        rl = RecordLink(record=gateway_context.configuration,
                        context=context,
                        logger=logging,
                        debug_level=debug_level)

        logger.info("")
        dot_instance = rl.to_dot(
            graph_type=graph_format if graph_format != "raw" else "dot",
            show_only_active_vertices=False,
            show_only_active_edges=False
        )
        if graph_format == "raw":
            logger.info(dot_instance)
        else:
            try:
                dot_instance.render(filepath)
                logger.info(f"Record linking graph rendered to {filepath}")
            except Exception as err:
                logger.error(f"Could not generate graph: {err}")
                raise err
        logger.info("")

    def _do_render_service(self, context: KeeperParams, gateway_context: GatewayContext, filepath: str,
                           graph_format: str, debug_level: int = 0):

        service = UserService(record=gateway_context.configuration, context=context, logger=logging,
                              debug_level=debug_level)

        logger.info("")
        dot_instance = service.to_dot(
            graph_type=graph_format if graph_format != "raw" else "dot",
            show_only_active_vertices=False,
            show_only_active_edges=False
        )
        if graph_format == "raw":
            logger.info(dot_instance)
        else:
            try:
                dot_instance.render(filepath)
                logger.info(f"User service/tasks graph rendered to {filepath}")
            except Exception as err:
                logger.error(f"Could not generate graph: {err}")
                raise err
        logger.info("")

    def _do_render_jobs(self, context: KeeperParams, gateway_context: GatewayContext, filepath: str,
                        graph_format: str, debug_level: int = 0):

        jobs = Jobs(record=gateway_context.configuration, context=context, logger=logging, debug_level=debug_level)

        logger.info("")
        dot_instance = jobs.dag.to_dot()
        if graph_format == "raw":
            logger.info(dot_instance)
        else:
            try:
                dot_instance.render(filepath)
                logger.info(f"Job graph rendered to {filepath}")
            except Exception as err:
                logger.error(f"Could not generate graph: {err}")
                raise err
        logger.info("")

    def _do_raw_text_list(self, context: KeeperParams, gateway_context: GatewayContext, graph_id: int = 0,
                          debug_level: int = 0):

        logging.debug(f"loading graph id {graph_id}, for record uid {gateway_context.configuration.record_uid}")

        conn = get_connection(context=context)
        dag = DAG(conn=conn, record=gateway_context.configuration, graph_id=graph_id, fail_on_corrupt=False,
                  logger=logging, debug_level=debug_level)
        dag.load(sync_point=0)
        logger.info("")
        if dag.is_corrupt is True:
            logger.error(f"The graph is corrupt at Vertex UIDs: {', '.join(dag.corrupt_uids)}")
            logger.error("")

        logger.debug("DAG DOT -------------------------------")
        logger.debug(str(dag.to_dot()))
        logger.debug("DAG DOT -------------------------------")

        line_start = {
            0: "",
            1: "* ",
            2: "- ",
            3: ". ",
        }

        def _handle(current_vertex: DAGVertex, last_vertex: Optional[DAGVertex] = None, indent: int = 0):

            pad = ""
            if indent > 0:
                pad = "".ljust(4 * indent, ' ')

            ls = line_start.get(indent, "  ")
            text = f"{pad}{ls}{current_vertex.uid}"

            edge_types = []
            if last_vertex is not None:
                for edge in current_vertex.edges:
                    if not edge.active:
                        continue
                    if edge.head_uid == last_vertex.uid:
                        edge_types.append(edge.edge_type.value)
            if len(edge_types) > 0:
                text += f"; edges: {', '.join(edge_types)}"

            if not current_vertex.active:
                text += " Inactive"
            if current_vertex.corrupt:
                text += " Corrupt"

            logger.info(text)

            if not current_vertex.active:
                logger.debug(f"vertex {current_vertex.uid} is not active, will not get children.")
                return

            vertices = current_vertex.has_vertices()
            if len(vertices) == 0:
                logger.debug(f"vertex {current_vertex.uid} does not have any children.")
                return

            for vertex in vertices:
                _handle(vertex, current_vertex, indent=indent + 1)

        logger.info("")
        _handle(dag.get_root)
        logger.info("")

    def _do_raw_render_graph(self, context: KeeperParams, gateway_context: GatewayContext, filepath: str,
                             graph_format: str, graph_id: int = 0, debug_level: int = 0):

        conn = get_connection(context=context)
        dag = DAG(conn=conn, record=gateway_context.configuration, graph_id=graph_id, fail_on_corrupt=False,
                  logger=logging, debug_level=debug_level)
        dag.load(sync_point=0)
        dot = dag.to_dot(graph_format=graph_format)
        if graph_format == "raw":
            logger.info(dot)
        else:
            try:
                dot.render(filepath)
                logger.info(f"Graph rendered to {filepath}")
            except Exception as err:
                logger.error(f"Could not generate graph: {err}")
                raise err

        logger.info("")

    def do_list(self, context: KeeperParams, gateway_context: GatewayContext, graph_type: str, debug_level: int = 0,
                indent: int = 0):
        list_func = getattr(self, f"_do_text_list_{graph_type}")
        list_func(context=context,
                  gateway_context=gateway_context,
                  debug_level=debug_level,
                  indent=indent)

    def execute(self, context: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        raw = kwargs.get("raw", False)
        graph_type = kwargs.get("graph_type")
        do_text_list = kwargs.get("do_text_list")
        do_render = kwargs.get("do_render")
        debug_level = int(kwargs.get("debug_level", 0))

        configuration_uid = kwargs.get('configuration_uid')

        vault = context.vault

        gateway_context = GatewayContext.from_gateway(vault=vault,
                                                        gateway=gateway,
                                                        configuration_uid=configuration_uid)
        if gateway_context is None:
            logger.error(f"Could not find the gateway configuration for {gateway}.")
            return

        if raw:
            if do_text_list:
                self._do_raw_text_list(context=context,
                                       gateway_context=gateway_context,
                                       graph_id=PAMDebugGraphCommand.graph_id_map.get(graph_type),
                                       debug_level=debug_level)
            if do_render:
                filepath = kwargs.get("filepath")
                graph_format = kwargs.get("format")
                self._do_raw_render_graph(context=context,
                                          gateway_context=gateway_context,
                                          filepath=filepath,
                                          graph_format=graph_format,
                                          graph_id=PAMDebugGraphCommand.graph_id_map.get(graph_type),
                                          debug_level=debug_level)
        else:
            if do_text_list:
                self.do_list(
                    context=context,
                    gateway_context=gateway_context,
                    graph_type=graph_type,
                    debug_level=debug_level
                )
            if do_render:
                filepath = kwargs.get("filepath")
                graph_format = kwargs.get("format")
                render_func = getattr(self, f"_do_render_{graph_type}")
                render_func(context=context,
                            gateway_context=gateway_context,
                            filepath=filepath,
                            graph_format=graph_format,
                            debug_level=debug_level)
