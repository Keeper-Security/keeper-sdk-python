import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel

from keepersdk import crypto, utils

from ... import base
from ....params import KeeperParams
from ....helpers import router_utils
from .... import api
from .__init__ import GatewayContext, MultiConfigurationException, multi_conf_msg, PAMGatewayActionDiscoverCommandBase
from ..pam_dto import GatewayAction, GatewayActionDiscoverJobStartInputs, GatewayActionDiscoverJobStart, GatewayActionDiscoverJobRemoveInputs, GatewayActionDiscoverJobRemove
from .rule_commands import PAMGatewayActionDiscoverRuleAddCommand, PAMGatewayActionDiscoverRuleListCommand, PAMGatewayActionDiscoverRuleRemoveCommand, PAMGatewayActionDiscoverRuleUpdateCommand

from keepersdk.helpers.pam_user_record_facade import PamUserRecordFacade
from keepersdk.helpers.keeper_dag.jobs import Jobs
from keepersdk.helpers.keeper_dag.dag_types import (CredentialBase, DiscoveryDelta, DiscoveryObject, JobItem, UserAcl, DirectoryInfo, 
                BulkRecordConvert, BulkRecordAdd, BulkRecordSuccess, BulkRecordFail, BulkProcessResults, NormalizedRecord, BulkRecordFail, PromptResult,
                PromptActionEnum)
from keepersdk.helpers.keeper_dag.dag_vertex import DAGVertex
from keepersdk.helpers.keeper_dag.dag import DAG
from keepersdk.helpers.keeper_dag.dag_sort import sort_infra_vertices
from keepersdk.helpers.keeper_dag.constants import VERTICES_SORT_MAP, DIS_INFRA_GRAPH_ID, PAM_USER
from keepersdk.helpers.keeper_dag.infrastructure import Infrastructure
from keepersdk.helpers.keeper_dag.process import Process, NoDiscoveryDataException, QuitException
from keepersdk.helpers.keeper_dag.record_link import RecordLink
from keepersdk.vault import record_types, vault_extensions, vault_online, vault_record
from keepersdk.proto import pam_pb2, record_pb2, router_pb2

logger = api.get_logger()


class PAMGatewayActionDiscoverJobStatusCommand(PAMGatewayActionDiscoverCommandBase):
    """
    Get the status of discovery jobs.

    If no parameters are given, it will check all gateways for discovery job status.

    """

    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action discover status')
        PAMGatewayActionDiscoverJobStatusCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=False, dest='gateway', action='store',
                            help='Show only discovery jobs from a specific gateway.')
        parser.add_argument('--job-id', '-j', required=False, dest='job_id', action='store',
                            help='Detailed information for a specific discovery job.')
        parser.add_argument('--history', required=False, dest='show_history', action='store_true',
                            help='Show history')
        parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                            action='store', help='PAM configuration UID is using --history')

    @staticmethod
    def print_job_table(jobs: List[Dict],
                        max_gateway_name: int,
                        show_history: bool = False):

        """
        Print jobs in a table.

        This method takes a list of dictionary item which contains the cooked job information.

        """

        logger.info("")
        logger.info(f"{'Job ID'.ljust(14, ' ')} "
              f"{'Gateway Name'.ljust(max_gateway_name, ' ')} "
              f"{'Gateway UID'.ljust(22, ' ')} "
              f"{'Configuration UID'.ljust(22, ' ')} "
              f"{'Status'.ljust(12, ' ')} "
              f"{'Resource UID'.ljust(22, ' ')} "
              f"{'Started'.ljust(19, ' ')} "
              f"{'Completed'.ljust(19, ' ')} "
              f"{'Duration'.ljust(19, ' ')} "
              f"")

        logger.info(f"{''.ljust(14, '=')} "
              f"{''.ljust(max_gateway_name, '=')} "
              f"{''.ljust(22, '=')} "
              f"{''.ljust(22, '=')} "
              f"{''.ljust(12, '=')} "
              f"{''.ljust(22, '=')} "
              f"{''.ljust(19, '=')} "
              f"{''.ljust(19, '=')} "
              f"{''.ljust(19, '=')}")

        completed_jobs = []
        running_jobs = []
        failed_jobs = []

        for job in jobs:
            job_id = job['job_id']
            if job['status'] == "COMPLETE":
                completed_jobs.append(job_id)
            elif job['status'] == "RUNNING":
                running_jobs.append(job_id)
            elif job['status'] == "FAILED":
                failed_jobs.append(job_id)
            logger.info(f"{job_id} "
                  f"{job['gateway'].ljust(max_gateway_name, ' ')} "
                  f"{job['gateway_uid']} "
                  f"{job['configuration_uid']} "
                  f"{job['status'].ljust(12, ' ')} "
                  f"{(job.get('resource_uid') or 'NA').ljust(22, ' ')} "
                  f"{(job.get('start_ts_str') or 'NA').ljust(19, ' ')} "
                  f"{(job.get('end_ts_str') or 'NA').ljust(19, ' ')} "
                  f"{(job.get('duration') or 'NA').ljust(19, ' ')} "
                  f"")

        if len(completed_jobs) > 0 and show_history is False:
            logger.info("")
            if len(completed_jobs) == 1:
                logger.info(f"There is one COMPLETED job. To process, use the following command.")
            else:
                logger.info(f"There are {len(completed_jobs)} COMPLETED jobs. "
                      "To process, use one of the the following commands.")
            for job_id in completed_jobs:
                logger.info(f"  pam action discover process -j {job_id}")

        if len(running_jobs) > 0 and show_history is False:
            logger.info("")
            if len(running_jobs) == 1:
                logger.info(f"There is one RUNNING job. "
                      "If there is a problem, use the following command to cancel/remove the job.")
            else:
                logger.info(f"There are {len(running_jobs)} RUNNING jobs. "
                      "If there is a problem, use one of the following commands to cancel/remove the job.")
            for job_id in running_jobs:
                logger.info(f"  pam action discover remove -j {job_id}")

        if len(failed_jobs) > 0 and show_history is False:
            logger.info("")
            if len(failed_jobs) == 1:
                logger.info(f"There is one FAILED job. "
                      "If there is a problem, use the following command to get more information.")
            else:
                logger.info(f"There are {len(failed_jobs)} FAILED jobs. "
                      "If there is a problem, use one of the following commands to get more information.")
            for job_id in failed_jobs:
                logger.info(f"  pam action discover status -j {job_id}")
            logger.info("")
            if len(failed_jobs) == 1:
                logger.info(f"To remove the job, use the following command.")
            else:
                logger.info(f"To remove the FAILED job, use one of the following commands.")
            for job_id in failed_jobs:
                logger.info(f"  pam action discover remove -j {job_id}")

        logger.info("")

    @staticmethod
    def print_job_detail(vault: vault_online.VaultOnline,
                         all_gateways: List,
                         job_id: str):

        def _find_job(configuration_record) -> Optional[Dict]:
            jobs_obj = Jobs(record=configuration_record)
            job_item = jobs_obj.get_job(job_id)
            if job_item is not None:
                return {
                    "jobs": jobs_obj,
                }
            return None

        gateway_context, payload = GatewayContext.find_gateway(vault=vault,
                                                               find_func=_find_job,
                                                               gateways=all_gateways)

        if gateway_context is not None:
            jobs = payload["jobs"]
            job = jobs.get_job(job_id)
            infra = Infrastructure(record=gateway_context.configuration)

            status = "RUNNING"
            if job.end_ts is not None and not job.error:
                if job.success is None:
                    status = "CANCELLED"
                else:
                    status = "COMPLETE"
            elif job.error:
                status = "FAILED"

            logger.info("")
            logger.info(f"Job ID: {job.job_id}")
            logger.info(f"Sync Point: {job.sync_point}")
            logger.info(f"Gateway Name: {gateway_context.gateway_name}")
            logger.info(f"Gateway UID: {gateway_context.gateway_uid}")
            logger.info(f"Configuration UID: {gateway_context.configuration_uid}")
            logger.info(f"Status: {status}")
            logger.info(f"Resource UID: {job.resource_uid or 'NA'}")
            logger.info(f"Started: {job.start_ts_str}")
            logger.info(f"Completed: {job.end_ts_str}")
            logger.info(f"Duration: {job.duration_sec_str}")

            # If it failed, show the error and stacktrace.
            if status == "FAILED":
                logger.info("")
                logger.info(f"Gateway Error:")
                logger.info(f"{job.error}")
                logger.info("")
                logger.info(f"Gateway Stacktrace:")
                logger.info(f"{job.stacktrace}")
            # If it finished, show information about what was discovered.
            elif job.end_ts is not None:

                try:
                    infra.load(sync_point=0)
                    logger.info("")
                    delta_json = job.delta
                    if delta_json is not None:
                        delta = DiscoveryDelta.model_validate(delta_json)
                        logger.info(f"Added - {len(delta.added)} count")
                        for item in delta.added:
                            vertex = infra.dag.get_vertex(item.uid)
                            if vertex is None or vertex.active is False or vertex.has_data is False:
                                logger.debug("added: vertex is none, inactive or has no data")
                                continue
                            discovery_object = DiscoveryObject.get_discovery_object(vertex)
                            logger.info(f"  * {discovery_object.description}")

                        logger.info("")
                        logger.info(f"Changed - {len(delta.changed)} count")
                        for item in delta.changed:
                            vertex = infra.dag.get_vertex(item.uid)
                            if vertex is None or vertex.active is False or vertex.has_data is False:
                                logger.debug("changed: vertex is none, inactive or has no data")
                                continue
                            discovery_object = DiscoveryObject.get_discovery_object(vertex)
                            logger.info(f"  * {discovery_object.description}")
                            if item.changes is None:
                                logger.info(f"    no changed, may be a object not added in prior discoveries.")
                            else:
                                for key, value in item.changes.items():
                                    logger.info(f"    - {key} = {value}")

                        logger.info("")
                        logger.info(f"Deleted - {len(delta.deleted)} count")
                        for item in delta.deleted:
                            logger.info(f"  * discovery vertex {item.uid}")
                    else:
                        logger.info(f"There are no available delta changes for this job.")

                except Exception as err:
                    logger.info(f"Could not load delta from infrastructure: {str(err)}")
                    logger.info("Fall back to raw graph.")
                    logger.info("")
                    dag = DAG(conn=infra.conn, record=infra.record, graph_id=DIS_INFRA_GRAPH_ID)
                    logger.info(dag.to_dot_raw(sync_point=job.sync_point, rank_dir="RL"))

        else:
            logger.info(f"Could not find the gateway with job {job_id}.")

    def execute(self, context: KeeperParams, **kwargs):
        if not context.vault:
            raise base.CommandError('Vault is not initialized. Login to initialize the vault.')
        
        vault = context.vault

        # If this is set, only show status for this gateway and history for this gateway.
        gateway_filter = kwargs.get("gateway")

        # If this is set, only show detailed information about this job.
        job_id = kwargs.get("job_id")

        # Show the history for the gateway.
        # gateway_filter needs to be set for
        show_history = kwargs.get("show_history")

        # Get all the gateways here so we don't have to keep calling this method.
        # It gets passed into find_gateway, and find_gateway will pass it around.
        all_gateways = GatewayContext.all_gateways(vault)

        # If we are showing all gateways, disable show history.
        # History is shown for a specific gateway.
        if gateway_filter is None:
            show_history = False

        # This is used to format the table. Start with a length of 12 characters for the gateway.
        max_gateway_name = 12

        # If we have a job id, only display information about the one job
        if job_id:
            self.print_job_detail(vault=vault,
                                  all_gateways=all_gateways,
                                  job_id=job_id)

        # Else show jobs in a table
        else:

            # Based on parameters set by user, select specific jobs to be displayed.
            selected_jobs = []  # type: List[Dict]

            # For each configuration/ gateway, we are going to get all jobs.
            # We are going to query the gateway for any updated status.

            configuration_records = list(vault.vault_data.find_records("pam.*Configuration"))
            for configuration_record in configuration_records:

                gateway_context = GatewayContext.from_configuration_uid(
                    vault=vault,
                    configuration_uid=configuration_record.record_uid,
                    gateways=all_gateways)

                if gateway_context is None:
                    continue

                # If we are using a gateway filter, and this gateway is not the one, then go onto the next conf/gateway.
                if gateway_filter is not None and gateway_context.is_gateway(gateway_filter) is False:
                    continue

                # If the gateway name is longer that the prior, set the max length to this gateway's name.
                if len(gateway_context.gateway_name) > max_gateway_name:
                    max_gateway_name = len(gateway_context.gateway_name)

                jobs = Jobs(record=configuration_record)
                if show_history is True:
                    job_list = reversed(jobs.history)
                else:
                    job_list = []
                    if jobs.current_job is not None:
                        job_list = [jobs.current_job]

                for job_item in job_list:
                    job = job_item.model_dump()
                    job["status"] = "RUNNING"
                    if job_item.start_ts is not None:
                        job["start_ts_str"] = job_item.start_ts_str
                    if job_item.end_ts is not None:
                        job["end_ts_str"] = job_item.end_ts_str
                        job["status"] = "COMPLETE"

                    job["duration"] = job_item.duration_sec_str

                    job["gateway"] = gateway_context.gateway_name
                    job["gateway_uid"] = gateway_context.gateway_uid
                    job["configuration_uid"] = gateway_context.configuration_uid

                    # This is needs for details
                    job["gateway_context"] = gateway_context
                    job["job_item"] = job_item

                    if job_item.success is None and job_item.end_ts:
                        job["status"] = "CANCELLED"
                    elif job_item.success is False:
                        job["status"] = "FAILED"

                    selected_jobs.append(job)

            if len(selected_jobs) == 0:
                logger.info(f"There are no discovery jobs. Use 'pam action discover start' to start a "
                      f"discovery job.")
                return

            self.print_job_table(jobs=selected_jobs,
                                 max_gateway_name=max_gateway_name,
                                 show_history=show_history)


class PAMGatewayActionDiscoverJobStartCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action discover start')
        PAMGatewayActionDiscoverJobStartCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                            help='Gateway name of UID.')
        parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                            action='store', help='PAM configuration UID, if gateway has multiple.')
        parser.add_argument('--resource', '-r', required=False, dest='resource_uid', action='store',
                            help='UID of the resource record. Set to discover specific resource.')

        parser.add_argument('--lang', required=False, dest='language', action='store', default="en_US",
                            help='Language')
        parser.add_argument('--include-machine-dir-users', required=False, dest='include_machine_dir_users',
                            action='store_false', default=True, help='Include directory users found on the machine.')
        parser.add_argument('--inc-azure-aadds', required=False, dest='include_azure_aadds',
                            action='store_true', help='Include Azure Active Directory Domain Service.')
        parser.add_argument('--skip-rules', required=False, dest='skip_rules',
                            action='store_true', help='Skip running the rule engine.')
        parser.add_argument('--skip-machines', required=False, dest='skip_machines',
                            action='store_true', help='Skip discovering machines.')
        parser.add_argument('--skip-databases', required=False, dest='skip_databases',
                            action='store_true', help='Skip discovering databases.')
        parser.add_argument('--skip-directories', required=False, dest='skip_directories',
                            action='store_true', help='Skip discovering directories.')
        parser.add_argument('--skip-cloud-users', required=False, dest='skip_cloud_users',
                            action='store_true', help='Skip discovering cloud users.')
    
    def execute(self, context: KeeperParams, **kwargs):
        if not context.vault:
            raise base.CommandError('Vault is not initialized. Login to initialize the vault.')
        
        vault = context.vault

        # Load the configuration record and get the gateway_uid from the facade.
        gateway = kwargs.get('gateway')
        gateway_context = None
        try:
            gateway_context = GatewayContext.from_gateway(vault=vault,
                                                          gateway=gateway,
                                                          configuration_uid=kwargs.get('configuration_uid'))
            if gateway_context is None:
                logger.error(f"Could not find the gateway configuration for {gateway}.")
                return
        except MultiConfigurationException as err:
            multi_conf_msg(gateway, err)
            return

        jobs = Jobs(record=gateway_context.configuration)
        current_job_item = jobs.current_job
        removed_prior_job = None
        if current_job_item is not None:
            if current_job_item.is_running is True:
                logger.warning("A discovery job is currently running. Cannot start another until it is finished.")
                logger.warning("To check the status, use the command 'pam action discover status'.")
                logger.warning(f"To stop and remove the current job, use the command 'pam action discover remove -j {current_job_item.job_id}'.")
                return

            logger.error(f"An active discovery job exists for this gateway.")
            logger.info("")
            status = PAMGatewayActionDiscoverJobStatusCommand()
            status.execute(context=context)
            logger.info("")

            yn = input("Do you wish to remove the active discovery job and run a new one [Y/N]> ").lower()
            while True:
                if yn[0] == "y":
                    jobs.cancel(current_job_item.job_id)
                    removed_prior_job = current_job_item.job_id
                    break
                elif yn[0] == "n":
                    logger.error(f"Not starting a discovery job.")
                    return

        # Get the credentials passed in via the command line
        credentials = []
        creds = kwargs.get('credentials')
        if creds is not None:
            for cred in creds:
                parts = cred.split("|")
                c = CredentialBase()
                for item in parts:
                    kv = item.split("=")
                    if len(kv) != 2:
                        logger.error(f"A '--cred' is invalid. It does not have a value.")
                        return
                    if not hasattr(c, kv[0]):
                        logger.error(f"A '--cred' is invalid. The key '{kv[0]}' is invalid.")
                        return
                    if hasattr(c, kv[1]) == "":
                        logger.error(f"A '--cred' is invalid. The value is blank.")
                        return
                    setattr(c, kv[0], kv[1])
                credentials.append(c.model_dump())

        # Get the credentials passed in via a credential file.
        credential_files = kwargs.get('credential_file')
        if credential_files is not None:
            with open(credential_files, "r") as fh:
                try:
                    creds = json.load(fh)
                except FileNotFoundError:
                    logger.error(f"Could not find the file {credential_files}")
                    return
                except json.JSONDecoder:
                    logger.error(f"The file {credential_files} is not valid JSON.")
                    return
                except Exception as err:
                    logger.error(f"The JSON file {credential_files} could not be imported: {err}")
                    return

                if not isinstance(creds, list):
                    logger.error(f"Credential file is invalid. Structure is not an array.")
                    return
                num = 1
                for obj in creds:
                    c = CredentialBase()
                    for key in obj:
                        if not hasattr(c, key):
                            logger.error(f"Object {num} has the invalid key {key}.")
                            return
                        setattr(c, key, obj[key])
                    credentials.append(c.model_dump())

        action_inputs = GatewayActionDiscoverJobStartInputs(
            configuration_uid=gateway_context.configuration_uid,
            resource_uid=kwargs.get('resource_uid'),
            user_map=gateway_context.encrypt(
                self.make_protobuf_user_map(
                    context=context,
                    gateway_context=gateway_context
                )
            ),

            shared_folder_uid=gateway_context.default_shared_folder_uid,
            languages=[kwargs.get('language')],

            # Settings
            include_machine_dir_users=kwargs.get('include_machine_dir_users', True),
            include_azure_aadds=kwargs.get('include_azure_aadds', False),
            skip_rules=kwargs.get('skip_rules', False),
            skip_machines=kwargs.get('skip_machines', False),
            skip_databases=kwargs.get('skip_databases', False),
            skip_directories=kwargs.get('skip_directories', False),
            skip_cloud_users=kwargs.get('skip_cloud_users', False),
            credentials=credentials
        )

        conversation_id = GatewayAction.generate_conversation_id()
        router_response = router_utils.router_send_action_to_gateway(
            context=context,
            gateway_action=GatewayActionDiscoverJobStart(
                inputs=action_inputs,
                conversation_id=conversation_id),
            message_type=pam_pb2.CMT_DISCOVERY,
            is_streaming=False,
            destination_gateway_uid_str=gateway_context.gateway_uid
        )

        data = self.get_response_data(router_response)
        if data is None:
            logger.error(f"The router returned a failure.")
            return

        if "has been queued" in data.get("Response", ""):

            if removed_prior_job is None:
                logger.info("The discovery job is currently running.")
            else:
                logger.info(f"Active discovery job {removed_prior_job} has been removed and new discovery job is running.")
            logger.info(f"To check the status, use the command 'pam action discover status'.")
            logger.info(f"To stop and remove the current job, use the command 'pam action discover remove -j <Job ID>'.")
        else:
            router_utils.print_router_response(router_response, "job_info", conversation_id, gateway_uid=gateway_context.gateway_uid)

    @staticmethod
    def make_protobuf_user_map(context: KeeperParams, gateway_context: GatewayContext) -> List[dict]:
        """
        Make a user map for PAM Users.

        The map is used to find existing records.
        Since KSM cannot read the rotation settings using protobuf,
          it cannot match a vault record to a discovered users.
        This map will map a login/DN and parent UID to a record UID.
        """

        vault = context.vault
        user_map = []
        for record in vault.vault_data.find_records("pamUser"):
            user_record = vault.vault_data.load_record(record.record_uid)
            user_facade = PamUserRecordFacade()
            user_facade.record = user_record

            info = context.get_record_rotation(user_record.record_uid)
            if info is None:
                continue

            # Make sure this user is part of this gateway.
            if info.configuration_uid != gateway_context.configuration_uid:
                continue

            # If the user Admin Cred Record (i.e., parent) is blank, skip the mapping item
            # This will be a UID string, not 16 bytes.
            if info.resource_uid is None or info.resource_uid == "":
                continue

            user_map.append({
                "user": user_facade.login if user_facade.login != "" else None,
                "dn": user_facade.distinguishedName if user_facade.distinguishedName != "" else None,
                "record_uid": user_record.record_uid,
                "parent_record_uid": info.resource_uid
            })

        logger.debug(f"found {len(user_map)} user map items")

        return user_map

class PAMGatewayActionDiscoverJobRemoveCommand(PAMGatewayActionDiscoverCommandBase):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action discover remove')
        PAMGatewayActionDiscoverJobRemoveCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--job-id', '-j', required=True, dest='job_id', action='store',
                        help='Discovery job id.')
    
    def execute(self, context: KeeperParams, **kwargs):
        if not context.vault:
            raise base.CommandError('Vault is not initialized. Login to initialize the vault.')
        
        vault = context.vault

        job_id = kwargs.get("job_id")

        # Get all the gateways here so we don't have to keep calling this method.
        # It gets passed into find_gateway, and find_gateway will pass it around.
        all_gateways = GatewayContext.all_gateways(vault)

        def _find_job(configuration_record) -> Optional[Dict]:
            jobs_obj = Jobs(record=configuration_record)
            job_item = jobs_obj.get_job(job_id)
            if job_item is not None:
                return {
                    "jobs": jobs_obj,
                }
            return None

        gateway_context, payload = GatewayContext.find_gateway(vault=vault,
                                                               find_func=_find_job,
                                                               gateways=all_gateways)

        if gateway_context is not None:
            jobs = payload["jobs"]

            try:
                # First, cancel the running discovery job if it is running.
                logger.debug("cancel job on the gateway, if running")
                action_inputs = GatewayActionDiscoverJobRemoveInputs(
                    configuration_uid=gateway_context.configuration_uid,
                    job_id=job_id
                )

                conversation_id = GatewayAction.generate_conversation_id()
                router_response = router_utils.router_send_action_to_gateway(
                    context=context,
                    gateway_action=GatewayActionDiscoverJobRemove(
                        inputs=action_inputs,
                        conversation_id=conversation_id),
                    message_type=pam_pb2.CMT_DISCOVERY,
                    is_streaming=False,
                    destination_gateway_uid_str=gateway_context.gateway_uid
                )

                data = self.get_response_data(router_response)
                if data is None:
                    raise Exception("The router returned a failure.")
                elif data.get("success") is False:
                    error = data.get("error")
                    raise Exception(f"Discovery job was not removed: {error}")
            except Exception as err:
                logger.debug(f"gateway return error removing discovery job: {err}")

            jobs.cancel(job_id)
            jobs.close()

            logger.info(f"Discovery job has been removed or cancelled.")
            return

        logger.error(f'Discovery job not found. Cannot get remove the job.')
        return


# This is used for the admin user search
class AdminSearchResult(BaseModel):
    record: Any
    is_directory_user: bool
    is_pam_user: bool
    being_used: bool = False


class PAMGatewayActionDiscoverResultProcessCommand(PAMGatewayActionDiscoverCommandBase):

    EDITABLE = [
        "login",
        "password",
        "distinguishedName",
        "alternativeIPs",
        "database",
        "privatePEMKey",
        "connectDatabase",
        "operatingSystem"
    ]

    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action discover process')
        PAMGatewayActionDiscoverResultProcessCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--job-id', '-j', required=True, dest='job_id', action='store',
                            help='Discovery job to process.')
        parser.add_argument('--add-all', required=False, dest='add_all', action='store_true',
                            help='Respond with ADD for all prompts.')
        parser.add_argument('--preview', required=False, dest='do_preview', action='store_true',
                            help='Preview the results')
        parser.add_argument('--debug-gs-level', required=False, dest='debug_level', action='store',
                            help='GraphSync debug level. Default is 0', type=int, default=0)
    

    @staticmethod
    def _is_directory_user(record_type: str) -> bool:
        # pamAzureConfiguration has tenant users what are like a directory.
        return (record_type == "pamDirectory" or
                record_type == "pamAzureConfiguration")

    @staticmethod
    def _get_shared_folder(vault: vault_online.VaultOnline, pad: str, gateway_context: GatewayContext) -> str:
        while True:
            shared_folders = gateway_context.get_shared_folders(vault)
            index = 0
            for folder in shared_folders:
                logger.info(f"{pad}* {str(index+1)} - {folder.get('uid')}  {folder.get('name')}")
                index += 1
            selected = input(f"{pad}Enter number of the shared folder>")
            try:
                return shared_folders[int(selected) - 1].get("uid")
            except ValueError:
                logger.error(f"{pad}Input was not a number.")

    @staticmethod
    def get_field_values(record: vault_record.TypedRecord, field_type: str) -> List[Any]:
        return next(
            (f.value
             for f in record.fields
             if f.type == field_type),
            None
        )

    def get_keys_by_record(self, context: KeeperParams, gateway_context: GatewayContext,
                           record: vault_record.TypedRecord) -> List[str]:
        """
        For the record, get the values of fields that are key for this record type.

        :param params:
        :param gateway_context:
        :param record:
        :return:
        """

        key_field = Process.get_key_field(record.record_type)
        keys = []
        if key_field == "host_port":
            values = self.get_field_values(record, "pamHostname")  # type: List[dict]
            if len(values) == 0:
                return []

            host = values[0].get("hostName")
            port = values[0].get("port")
            if port is not None:
                if host is not None:
                    keys.append(f"{host}:{port}".lower())

        elif key_field == "host":
            values = self.get_field_values(record, "pamHostname")
            if len(values) == 0:
                return []

            host = values[0].get("hostName")
            if host is not None:
                keys.append(host.lower())

        elif key_field == "user":

            # This is user protobuf values.
            # We could make this also use record linking if we stop using protobuf.

            record_rotation = context.get_record_rotation(record.record_uid)
            if record_rotation is not None:
                controller_uid = record_rotation.configuration_uid
                if controller_uid is None or controller_uid != gateway_context.configuration_uid:
                    return []

                resource_uid = record_rotation.resource_uid
                # If the resource uid is None, the Admin Cred Record has not been set.
                if resource_uid is None:
                    return []

                values = self.get_field_values(record, "login")
                if len(values) == 0:
                    return []

                keys.append(f"{resource_uid}:{values[0]}".lower())

        return keys

    @staticmethod
    def _record_lookup(record_uid: str,  context:KeeperParams) -> Optional[NormalizedRecord]:

        """
        Get the record from the Vault, normalize it, and return it.

        Since common code is using this method we want to flatten/abstract the KeeperRecord/TypedRecord.
        """

        vault = context.vault
        record = vault.vault_data.load_record(record_uid)
        if record is None:
            return None

        normalized_record = NormalizedRecord(
            record_uid=record.record_uid,
            record_type=record.record_type,
            title=record.title,
        )
        for field in record.fields:
            normalized_record.fields.append(
                record_types.RecordField(
                    type=field.type,
                    label=field.label,
                    value=field.value,
                )
            )
        if record.custom is not None:
            for field in record.custom:
                normalized_record.fields.append(
                    record_types.RecordField(
                        type=field.type,
                        label=field.label,
                        value=field.value,
                    )
                )
        return normalized_record

    def _build_record_cache(self, context: KeeperParams, gateway_context: GatewayContext) -> dict:

        """
        Make a lookup cache for all the records.

        This is used to flag discovered items as existing if the record has already been added. This is used to
        prevent duplicate records being added.
        """

        logger.debug(f"building the PAM record cache")

        # Make a cache of existing record by the criteria per record type
        cache = {
            "pamUser": {},
            "pamMachine": {},
            "pamDirectory": {},
            "pamDatabase": {}
        }

        vault = context.vault

        # Set all the PAM Records
        records = vault.vault_data.find_records(criteria="pam*", record_type=None, record_version=None)
        for record in records:
            # If the record type is not part of the cache, skip the record
            if record.record_type not in cache:
                continue

            # Load the full record
            record = vault.vault_data.load_record(record.record_uid)

            cache_keys = self.get_keys_by_record(
                context=context,
                gateway_context=gateway_context,
                record=record
            )
            if len(cache_keys) == 0:
                continue

            for cache_key in cache_keys:
                cache[record.record_type][cache_key] = record.record_uid

        return cache

    def _edit_record(self, content: DiscoveryObject, pad: str, editable: List[str]) -> bool:

        edit_label = input(f"{pad}Enter 'title' or the name of the Label to edit, RETURN to cancel> ")

        # Just pressing return exits the edit
        if edit_label == "":
            return False

        # If the "title" is entered, then edit the title of the record.
        if edit_label.lower() == "title":
            new_title = input(f"{pad}Enter new title> ")
            content.title = new_title

        # If a field label is entered, and it's in the list of editable fields, then allow the user to edit.
        elif edit_label in editable:
            new_value = None
            if edit_label in self.FIELD_MAPPING:
                type_hint = self.FIELD_MAPPING[edit_label].get("type")
                if type_hint == "dict":
                    field_input_format = self.FIELD_MAPPING[edit_label].get("field_input")
                    new_value = {}
                    for field in field_input_format:
                        new_value[field.get('key')] = input(f"{pad}Enter {field_input_format.get('prompt')} value> ")
                elif type_hint == "csv":
                    new_value = input(f"{pad}Enter {edit_label} values, separate with a comma > ")
                    new_values = map(str.strip, new_value.split(','))
                    new_value = "\n".join(new_values)
                elif type_hint == "multiline":
                    logger.info(f"{pad}Enter multilines of text or a path, on the first line, "
                             "to a file that contains the value.")
                    logger.info(f"{pad}To end, type 'END' at the start of a new line. You can paste text.")
                    new_value = ""
                    first_line = True
                    while True:
                        line = input(f"> ").rstrip()
                        if line == "END":
                            break

                        # If this is the first line, check if line is a path to a file.
                        if first_line:
                            try:
                                test_file = line.strip()
                                logger.debug(f"is first line, check for file path for '{test_file}'")
                                if os.path.exists(test_file):
                                    with open(test_file, "r") as fh:
                                        new_value = fh.read()
                                        fh.close()
                                        break
                                else:
                                    logger.debug(f"first line is not a file path")
                            except Exception as err:
                                logger.debug(f"exception checking if file: {err}")
                        first_line = False
                        new_value += line + "\n"
                elif type_hint == "choice":

                    values = self.FIELD_MAPPING[edit_label].get("values")
                    text_values = [x for x in values]
                    new_value = input(f"{pad}Enter one of the follow values: {', '.join(text_values)}> ")
                    new_value = new_value.strip().lower()
                    if new_value not in values:
                        logger.error(f"{pad}The value {new_value} is not one of the values allowed.")
                        return False
            else:
                new_value = input(f"{pad}Enter new value, or path to a file that contains the value > ")

                # Is the value a path to a file, i.e., a private key file.
                try:
                    if os.path.exists(new_value):
                        with open(new_value, "r") as fh:
                            new_value = fh.read()
                            fh.close()
                except (Exception,):
                    pass

            for edit_field in content.fields:
                if edit_field.label == edit_label:
                    edit_field.value = [new_value]

        # Else, the label they entered cannot be edited.
        else:
            logger.error(f"{pad}The field is not editable.")
            return False

        return True

    @staticmethod
    def _add_all_preprocess(vertex: DAGVertex, content: DiscoveryObject, parent_vertex: DAGVertex,
                            acl: Optional[UserAcl] = None) -> Optional[PromptResult]:
        """
        This is client side check if we should skip prompting the user.

        The checks are
        * A directory with the same domain already has a record.

        """

        _ = vertex
        _ = acl

        # Check if the directory for a domain exists.
        # From the parent, find any directory objects.
        # If they already have a record UID, don't prompt about this one.
        # Once a directory for the domain exists, the user should not be prompted about this domain anymore.
        if content.record_type == "pamDirectory":
            for v in parent_vertex.has_vertices():
                other_content = DiscoveryObject.get_discovery_object(v)
                if other_content.record_uid is not None and other_content.name == content.name:
                    return PromptResult(action=PromptActionEnum.SKIP)
        return None

    def _prompt_display_fields(self, content: DiscoveryObject, pad: str) -> List[str]:

        editable = []
        for field in content.fields:
            has_editable = False
            if field.label in PAMGatewayActionDiscoverResultProcessCommand.EDITABLE:
                editable.append(field.label)
                has_editable = True
            value = field.value

            # If there is a value, and it's not just [], also make sure the
            if len(value) > 0 and value[0] is not None:
                # PAM records will have only 1 item in the value array.
                value = value[0]
                if field.label in self.FIELD_MAPPING:
                    type_hint = self.FIELD_MAPPING[field.label].get("type")
                    formatted_value = []
                    if type_hint == "dict":
                        field_input_format = self.FIELD_MAPPING[field.label].get("field_format")
                        for format_field in field_input_format:
                            formatted_value.append(f"{format_field.get('label')}: "
                                                   f"{value.get(format_field.get('key'))}")
                    elif type_hint == "csv":
                        formatted_value.append(", ".join(value.split("\n")))
                    elif type_hint == "multiline":
                        formatted_value.append(value)
                    elif type_hint == "choice":
                        formatted_value.append(value)
                    value = ", ".join(formatted_value)
            else:
                if has_editable:
                    value = "MISSING"
                else:
                    value = "None"

            rows = str(value).split("\n")
            if len(rows) > 1:
                value = rows[0] + f"... {len(rows)} rows."

            logger.info(f"{pad}  "
                  f"Label: {field.label}, "
                  f"Type: {field.type}, "
                  f"Value: {value}")

        if len(content.notes) > 0:
            logger.info("")
            for note in content.notes:
                logger.info(f"{pad}* {note}")

        return editable

    @staticmethod
    def _prompt_display_relationships(vertex: DAGVertex, content: DiscoveryObject, pad: str):

        if vertex is None:
            return

        if content.record_type == "pamUser":
            belongs_to = []
            for v in vertex.belongs_to_vertices():
                resource_content = DiscoveryObject.get_discovery_object(v)
                belongs_to.append(resource_content.name)
            count = len(belongs_to)
            logger.info("")
            logger.info(f"{pad}This user is found on {count} resource{'s' if count > 1 else ''}")

    def _prompt(self,
                content: DiscoveryObject,
                acl: UserAcl,
                vertex: Optional[DAGVertex] = None,
                parent_vertex: Optional[DAGVertex] = None,
                resource_has_admin: bool = True,
                item_count: int = 0,
                items_left: int = 0,
                indent: int = 0,
                block_auto_add: bool = False,
                dry_run: bool = False,
                add_all: bool = False,
                vault: Optional[vault_online.VaultOnline] = None,
                gateway_context: Optional[GatewayContext] = None
                ) -> PromptResult:

        if gateway_context is None:
            raise Exception("Context not set for processing the discovery results")

        parent_content = DiscoveryObject.get_discovery_object(parent_vertex)

        logger.info("")

        if block_auto_add:
            add_all = False

        # If auto add is True, there are sometime we don't want to add the object.
        # If we get a result, we want to return it.
        # Skip the prompt.
        if add_all is True and vertex is not None:
            result = self._add_all_preprocess(vertex, content, parent_vertex, acl)
            if result is not None:
                return result

        # If the record type is a pamUser, then include parent description.
        if content.record_type == "pamUser" and parent_vertex is not None:
            parent_pad = ""
            if indent - 1 > 0:
                parent_pad = "".ljust(2 * indent, ' ')

            logger.info(f"{parent_pad}{parent_content.description}")

        pad = ""
        if indent > 0:
            pad = "".ljust(2 * indent, ' ')

        logger.info(f"{pad}{content.description}")

        show_current_object = True
        while show_current_object:
            logger.info(f"{pad}Record Title: {content.title}")

            logger.debug(f"Fields: {content.fields}")

            # Display the fields and return a list of fields are editable.
            editable = self._prompt_display_fields(content=content, pad=pad)
            if vertex is not None:
                self._prompt_display_relationships(vertex=vertex, content=content, pad=pad)

            while True:

                shared_folder_uid = content.shared_folder_uid
                if shared_folder_uid is None:
                    shared_folder_uid = gateway_context.default_shared_folder_uid

                count_prompt = ""
                if item_count > 0:
                    count_prompt = f"[{item_count - items_left + 1}/{item_count}]"
                edit_add_prompt = f"{count_prompt} "
                if len(editable) > 0:
                    edit_add_prompt += f"(E)dit, "

                shared_folders = gateway_context.get_shared_folders(vault)
                if dry_run is False:
                    if len(shared_folders) > 1:
                        folder_name = next((x['name']
                                            for x in shared_folders
                                            if x['uid'] == shared_folder_uid),
                                           None)
                        edit_add_prompt += f"(A)dd to {folder_name}, "\
                                           f"Add to (F)older, "
                    else:
                        if dry_run is False:
                            edit_add_prompt += f"(A)dd, "
                prompt = f"{edit_add_prompt}(S)kip, (I)gnore, (Q)uit"

                command = "a"
                if add_all is False:
                    command = input(f"{pad}{prompt}> ").lower()
                if (command == "a" or command == "f") and dry_run is False:

                    logger.info(f"{pad}Adding record to save queue.")
                    logger.info("")

                    if command == "f":
                        shared_folder_uid = self._get_shared_folder(vault, pad, gateway_context)

                    content.shared_folder_uid = shared_folder_uid

                    # This happens when the record is a pamUser and parent resource record does not have an
                    #   administrator.
                    # It's like the reverse of creating an admin after adding the resource.
                    # It would make this user the admin for the parent resource.
                    # This condition would be really rare, since to get the users, the resource would have to have an
                    #  admin user.
                    if content.record_type == "pamUser" and resource_has_admin is False:

                        logger.info(f"{parent_content.description} does not have an administrator.")
                        if (hasattr(parent_content.item, "admin_reason") and
                                parent_content.item.admin_reason is not None):
                            logger.info("")
                            logger.info(parent_content.item.admin_reason)
                            logger.info("")

                        while True:

                            yn = input("Do you want to make this user the administrator? [Y/N]> ").lower()
                            if yn == "":
                                continue
                            if yn[0] == "n":
                                break
                            if yn[0] == "y":
                                acl.is_admin = True
                                break

                    return PromptResult(
                        action=PromptActionEnum.ADD,
                        acl=acl,
                        content=content
                    )

                elif command == "e" and dry_run is False:
                    self._edit_record(content, pad, editable)
                    break

                elif command == "i":

                    logger.info(f"{pad}Creating an ignore rule for record.")
                    return PromptResult(
                        action=PromptActionEnum.IGNORE,
                        acl=acl,
                        content=content
                    )

                elif command == "s":
                    logger.info(f"{pad}Skipping record.")

                    return PromptResult(
                        action=PromptActionEnum.SKIP,
                        acl=acl,
                        content=content
                    )
                elif command == "q":
                    raise QuitException()
            logger.info("")

        return PromptResult(
            action=PromptActionEnum.SKIP,
            acl=acl,
            content=content
        )

    def _find_user_record(self,
                          bulk_convert_records: List[BulkRecordConvert],
                          context: Optional[KeeperParams] = None,
                          gateway_context: Optional[GatewayContext] = None,
                          record_link: Optional[RecordLink] = None) -> Tuple[Optional[vault_record.TypedRecord], bool]:

        vault = context.vault

        # Get the latest records
        vault.vault_data.sync_data = True

        # Make a list of all records in the shared folders.
        # We will use this to check if a selected user is in the shared folders.
        shared_record_uids = []
        for shared_folder in gateway_context.get_shared_folders(vault):
            folder = shared_folder.get("folder")
            if "records" in folder:
                for record in folder["records"]:
                    shared_record_uids.append(record.get("record_uid"))

        # Make a list of record we are already converting so we don't show them again.
        converting_list = [x.record_uid for x in bulk_convert_records]

        logger.debug(f"shared folders record uid {shared_record_uids}")

        while True:
            user_search = input("Enter an user to search for [ENTER/RETURN to quit]> ")
            if user_search == "":
                logger.error(f"No search terms, not performing search.")
                return None, False

            # Search for record with the search string.
            # Currently, this only works with TypedRecord, version 3.
            user_record = vault.vault_data.find_records(
                criteria=user_search,
                record_version=3,
                record_type=None
            )
            # If not record are returned by the search just return None,
            if len(user_record) == 0:
                logger.error(f"Could not find any records that contain the search text.")
                return None, False

            # Find usable admin records.
            admin_search_results = []
            for record in user_record:

                user_record = vault.vault_data.get_record(record.record_uid)
                if user_record.record_type == "pamUser":
                    logger.debug(f"{record.record_uid} is a pamUser")

                    # If we are already converting this pamUser record, then don't show it.
                    if record.record_uid in converting_list:
                        logger.debug(f"pamUser {user_record.title}, {user_record.record_uid} is being converted; "
                                      "BAD for search")
                        admin_search_results.append(
                            AdminSearchResult(
                                record=user_record,
                                is_directory_user=False,
                                is_pam_user=True,
                                being_used=True
                            )
                        )
                        continue

                    # Does the record exist in the gateway shared folder?
                    # We want to filter our other gateway's pamUser, or it will get overwhelming.
                    if user_record.record_uid not in shared_record_uids:
                        logger.debug(f"pamUser {record.title}, {user_record.record_uid} not in shared "
                                      "folder, BAD for search")
                        continue

                    # If the record does not exist in the record linking, it's orphaned; accept it
                    # If it does exist, then check if it belonged to a directory.
                    # Very unlikely a user that belongs to a database or another machine can be used.

                    record_vertex = record_link.get_record_link(user_record.record_uid)
                    is_directory_user = False
                    if record_vertex is not None:
                        parent_record_uid = record_link.get_parent_record_uid(user_record.record_uid)
                        parent_record = vault.vault_data.get_record(parent_record_uid)
                        if parent_record is not None:
                            is_directory_user = self._is_directory_user(parent_record.record_type)
                            if not is_directory_user:
                                logger.debug(f"pamUser parent for {user_record.title}, "
                                              "{user_record.record_uid} is not a directory; BAD for search")
                                continue

                            logger.debug(f"pamUser {user_record.title}, {user_record.record_uid} is a directory user; "
                                          "good for search")

                        else:
                            logger.debug(f"pamUser {user_record.title}, {user_record.record_uid} does not a parent; "
                                          "good for search")
                    else:
                        logger.debug(f"pamUser {user_record.title}, {user_record.record_uid} does not have record "
                                      "linking vertex; good for search")

                    admin_search_results.append(
                        AdminSearchResult(
                            record=user_record,
                            is_directory_user=is_directory_user,
                            is_pam_user=True,
                            being_used=False
                        )
                    )

                # Else this is a non-PAM record.
                # Make sure it has a login, password, private key
                else:
                    logger.debug(f"{record.record_uid} is NOT a pamUser")
                    login_field = next((x for x in record.fields if x.type == "login"), None)
                    password_field = next((x for x in record.fields if x.type == "password"), None)
                    private_key_field = next((x for x in record.fields if x.type == "keyPair"), None)

                    if login_field is not None and (password_field is not None or private_key_field is not None):
                        admin_search_results.append(
                            AdminSearchResult(
                                record=record,
                                is_directory_user=False,
                                is_pam_user=False
                            )
                        )
                        logger.debug(f"{record.title} is has credentials, good for search")
                    else:
                        logger.debug(f"{record.title} is missing full credentials, BAD for search")

            # If all the users have been filtered out, then just return None
            if len(admin_search_results) == 0:
                logger.error(f"Could not find any available records.")
                return None, False

            user_index = 1
            admin_search_results = sorted(admin_search_results,
                                          key=lambda x: x.is_pam_user,
                                          reverse=True)

            has_local_user = False
            for admin_search_result in admin_search_results:
                is_local_user = False
                if admin_search_result.record.record_type != "pamUser":
                    has_local_user = True
                    is_local_user = True

                index_str = user_index
                if admin_search_result.being_used:
                    index_str = "-" * len(str(index_str))

                logger.info(f"[{index_str}] "
                      f"{'* ' if is_local_user is True else ''}"
                      f"{admin_search_result.record.title} "
                      f'{"(Directory User) " if admin_search_result.is_directory_user is True else ""}'
                      f'{"(Already taken)" if admin_search_result.being_used is True else ""}')
                user_index += 1

            if has_local_user:
                logger.info(f"* Not a PAM User record. "
                      f"A PAM User would be generated from this record.")

            select = input("Enter line number of user record to use, enter/return to refine the search, "
                           f"or (Q) to quit search. > ").lower()
            if select == "":
                continue
            elif select[0] == "q":
                return None, False
            else:
                try:
                    selected = admin_search_results[int(select) - 1]
                    if selected.being_used:
                        logger.error(f"Cannot select a record that has already been taken. "
                              f"Another record is using this local user as its administrator.")
                        return None, False
                    admin_record = selected.record
                    return admin_record, selected.is_directory_user
                except IndexError:
                    logger.error(f"Entered row index does not exists.")
                    continue

        return None, False

    @staticmethod
    def _handle_admin_record_from_record(record: vault_record.TypedRecord,
                                         content: DiscoveryObject,
                                         context: Optional[KeeperParams] = None,
                                         gateway_context: Optional[GatewayContext] = None) -> Optional[PromptResult]:

        vault = context.vault

        # Is this a pamUser record?
        # Return the record UID and set its ACL to be the admin.
        if record.record_type == "pamUser":
            return PromptResult(
                action=PromptActionEnum.ADD,
                acl=UserAcl(is_admin=True),
                record_uid=record.record_uid,
            )

        # If we are here, this was not a pamUser
        # We need to duplicate the record.
        # But confirm first

        # Get fields from the old record.
        # Copy them into the fields.
        login_field = next((x for x in record.fields if x.type == "login"), None)
        password_field = next((x for x in record.fields if x.type == "password"), None)
        private_key_field = next((x for x in record.fields if x.type == "keyPair"), None)

        content.set_field_value("login", login_field.value)
        if password_field is not None:
            content.set_field_value("password", password_field.value)
        if private_key_field is not None:
            value = private_key_field.value
            if value is not None and len(value) > 0:
                value = value[0]
                private_key = value.get("privateKey")
                if private_key is not None:
                    content.set_field_value("private_key", private_key)

        # Check if we have more than one shared folder.
        # If we have one, confirm about adding the user.
        # If multiple shared folders, allow user to select which one.
        shared_folders = gateway_context.get_shared_folders(vault)
        if len(shared_folders) == 0:
            while True:
                yn = input(f"Create a PAM User record from {record.title}? [Y/N]> ").lower()
                if yn == "":
                    continue
                elif yn[0] == "n":
                    return None
                elif yn[0] == "y":
                    content.shared_folder_uid = gateway_context.default_shared_folder_uid
        else:
            folder_name = next((x['name']
                                for x in shared_folders
                                if x['uid'] == gateway_context.default_shared_folder_uid),
                               None)
            while True:
                shared_folders = gateway_context.get_shared_folders(vault)
                if len(shared_folders) > 1:
                    afq = input(f"(A)dd user to {folder_name}, "
                                f"Add user to (F)older, "
                                f"(Q)uit > ").lower()
                else:
                    afq = input(f"(A)dd user, "
                                f"(Q)uit > ").lower()

                if afq == "":
                    continue
                if afq[0] == "a":
                    content.shared_folder_uid = gateway_context.default_shared_folder_uid
                    break
                elif afq[0] == "f":
                    shared_folder_uid = PAMGatewayActionDiscoverResultProcessCommand._get_shared_folder(
                        vault, "", gateway_context)
                    if shared_folder_uid is not None:
                        content.shared_folder_uid = shared_folder_uid
                        break

        return PromptResult(
            action=PromptActionEnum.ADD,
            acl=UserAcl(is_admin=True),
            content=content,
            note=f"This record replaces record {record.title} ({record.record_uid}). "
                 "The password on that record will not be rotated."
        )

    def _prompt_admin(self,
                      parent_vertex: DAGVertex,
                      content: DiscoveryObject,
                      acl: UserAcl,
                      bulk_convert_records: List[BulkRecordConvert],
                      indent: int = 0,
                      context: Optional[KeeperParams] = None,
                      gateway_context: Optional[GatewayContext] = None) -> Optional[PromptResult]:

        if content is None:
            raise Exception("The admin content was not passed in to prompt the user.")

        parent_content = DiscoveryObject.get_discovery_object(parent_vertex)

        logger.info("")
        vault = context.vault
        while True:

            logger.info(f"{parent_content.description} does not have an administrator user.")
            if hasattr(parent_content.item, "admin_reason") is True and parent_content.item.admin_reason is not None:
                logger.info("")
                logger.info(parent_content.item.admin_reason)
            logger.info("")

            action = input("Would you like to (A)dd new administrator user, (F)ind an existing admin, or (S)kip add? > ").lower()

            if action == "":
                continue

            if action[0] == 'a':
                prompt_result = self._prompt(
                    vault=vault,
                    gateway_context=gateway_context,
                    vertex=None,
                    parent_vertex=parent_vertex,
                    content=content,
                    acl=acl,
                    indent=indent + 2,
                    block_auto_add=True
                )
                login = content.get_field_value("login")
                if login is None or login == "":
                    logger.error("A value is needed for the login field.")
                    continue

                logger.info(f"Adding admin record to save queue.")
                return prompt_result
            elif action[0] == 'f':
                logger.info("")
                record, is_directory_user = self._find_user_record(context=context,
                                                                   gateway_context=gateway_context,
                                                                   bulk_convert_records=bulk_convert_records)
                if record is not None:
                    admin_prompt_result = self._handle_admin_record_from_record(
                        record=record,
                        content=content,
                        context=context,
                        gateway_context=gateway_context
                    )
                    if admin_prompt_result is not None:
                        if admin_prompt_result.action == PromptActionEnum.ADD:
                            admin_prompt_result.is_directory_user = is_directory_user
                            logger.info(f"Adding admin record to save queue.")
                        return admin_prompt_result
            elif action[0] == 's':
                return PromptResult(
                    action=PromptActionEnum.SKIP
                )
            logger.info("")

    @staticmethod
    def _display_auto_add_results(bulk_add_records: List[BulkRecordAdd]):

        """
        Display the number of record created from rule engine ADD results and smart add function.
        """

        add_count = len(bulk_add_records)
        if add_count > 0:
            logger.info("")
            logger.info(f"From the rules, automatically queued {add_count} "
                  f"record{'' if add_count == 1 else 's'} to be added.")

    @staticmethod
    def _prompt_confirm_add(bulk_add_records: List[BulkRecordAdd]):

        """
        If we quit, we want to ask the user if they want to add record for discovery objects that they selected
        for addition.
        """

        logger.info("")
        count = len(bulk_add_records)
        if count == 1:
            msg = (f"There is 1 record queued to be added to your vault. "
                   f"Do you wish to add it? [Y/N]> ")
        else:
            msg = (f"There are {count} records queued to be added to your vault. "
                   f"Do you wish to add them? [Y/N]> ")
        while True:
            yn = input(msg).lower()
            if yn == "":
                continue
            if yn[0] == "y":
                return True
            elif yn[0] == "n":
                return False
            logger.error("Did not get 'Y' or 'N'")

    @staticmethod
    def _prepare_record(content: DiscoveryObject, context: Optional[KeeperParams] = None) -> Tuple[Any, str]:

        """
        Prepare the Vault record side.

        It's not created here.
        It will be created at the end of the processing run in bulk.
        We to build a record to get a record UID.

        :params content: The discovery object instance.
        :params context: Optionally, it will contain information set from the run() method.
        :returns: Returns an unsaved Keeper record instance.
        """

        # DEFINE V3 RECORD

        # Create an instance of a vault record to structure the data
        record = vault_record.TypedRecord()
        record.type_name = content.record_type
        record.record_uid = utils.generate_uid()
        record.record_key = utils.generate_aes_key()
        record.title = content.title
        for field in content.fields:
            field_args = {
                "field_type": field.type,
                "field_value": field.value
            }
            if field.type != field.label:
                field_args["field_label"] = field.label
            record_field = vault_record.TypedField.new_field(**field_args)
            record_field.required = field.required
            record.fields.append(record_field)

        vault = context.vault
        folder = vault.vault_data.get_folder(content.shared_folder_uid)
        folder_key = None
        if folder.folder_type == 'shared_folder_folder':
            shared_folder_uid = folder.folder_scope_uid
        elif folder.folder_type == 'shared_folder':
            shared_folder_uid = folder.folder_uid
        else:
            shared_folder_uid = None
        if shared_folder_uid and shared_folder_uid in vault.vault_data._shared_folders:
            shared_folder = vault.vault_data.get_folder(shared_folder_uid)
            folder_key = shared_folder.folder_key

        # DEFINE PROTOBUF FOR RECORD

        record_add_protobuf = record_pb2.RecordAdd()
        record_add_protobuf.record_uid = utils.base64_url_decode(record.record_uid)
        record_add_protobuf.record_key = crypto.encrypt_aes_v2(record.record_key, context.vault.keeper_auth.auth_context.data_key)
        record_add_protobuf.client_modified_time = utils.current_milli_time()
        record_add_protobuf.folder_type = record_pb2.user_folder
        if folder:
            record_add_protobuf.folder_uid = utils.base64_url_decode(folder.folder_uid)
            if folder.folder_type == 'shared_folder':
                record_add_protobuf.folder_type = record_pb2.shared_folder
            elif folder.folder_type == 'shared_folder_folder':
                record_add_protobuf.folder_type = record_pb2.shared_folder_folder
            if folder_key:
                record_add_protobuf.folder_key = crypto.encrypt_aes_v2(record.record_key, folder_key)

        data = vault_extensions.extract_typed_record_data(record, vault.vault_data.get_record_type_by_name(record.record_type))
        json_data = vault_extensions.get_padded_json_bytes(data)
        record_add_protobuf.data = crypto.encrypt_aes_v2(json_data, record.record_key)

        if context.vault.keeper_auth.auth_context.enterprise_ec_public_key:
            audit_data = vault_extensions.extract_audit_data(record)
            if audit_data:
                record_add_protobuf.audit.version = 0
                record_add_protobuf.audit.data = crypto.encrypt_ec(
                    json.dumps(audit_data).encode('utf-8'), context.vault.keeper_auth.auth_context.enterprise_ec_public_key)

        return record_add_protobuf, record.record_uid

    @classmethod
    def _create_records(cls, bulk_add_records: List[BulkRecordAdd], context: KeeperParams, gateway_context: GatewayContext) -> BulkProcessResults:

        """
        Create Vault records, setup rotation settings, and configure the resource (if resource).
        """

        if len(bulk_add_records) == 1:
            logger.info("Adding the record to the Vault ...")
        else:
            logger.info(f"Adding {len(bulk_add_records)} records to the Vault ...")

        build_process_results = BulkProcessResults()

        ##############################################################################################################
        #
        # STEP 1 - Batch add new records

        # Generate a list of RecordAdd instance.
        # In BulkRecordAdd they will be the record instance.
        record_add_list = [r.record for r in bulk_add_records]  # type: List[record_pb2.RecordAdd]

        records_per_request = 999

        add_results = []
        logger.debug("adding record in batches")
        logger.info("batch record create: ", end="")
        sys.stdout.flush()
        while record_add_list:
            logger.info(".", end="")
            sys.stdout.flush()
            logger.debug(f"* adding batch")
            rq = record_pb2.RecordsAddRequest()
            rq.records.extend(record_add_list[:records_per_request])
            record_add_list = record_add_list[records_per_request:]
            rs = context.vault.keeper_auth.execute_auth_rest('vault/records_add', rq, response_type=record_pb2.RecordsModifyResponse)
            add_results.extend(rs.records)
        logger.info("")
        sys.stdout.flush()

        logger.debug(f"add_result: {add_results}")

        if len(add_results) != len(bulk_add_records):
            logger.debug(f"attempted to batch add {len(bulk_add_records)} record(s), "
                          f"only have {len(add_results)} results.")

        ##############################################################################################################
        #
        # STEP 2 - Add rotation settings for user  and resource configuration for resources
        #          At this point the all the records have been created.

        # Keep track of each record we create a rotation for to avoid version problems, if there was a dup.
        created_cache = []

        # TODO: There is a bulk version of the following code, it's not live.
        #       Wait until live, then switch code to use that.

        # For the records passed in to be created.
        logger.info("add rotation settings: ", end="")
        sys.stdout.flush()
        for bulk_record in bulk_add_records:
            if bulk_record.record_uid in created_cache:
                logger.debug(f"found a duplicate of record uid: {bulk_record.record_uid}")
                continue
            logger.info(".", end="")
            sys.stdout.flush()

            # Grab the type Keeper record instance, and title from that record.
            pb_add_record = bulk_record.record
            title = bulk_record.title

            rotation_disabled = False

            # Find the result for this record.
            result = None
            for x in add_results:
                logger.debug(f"{pb_add_record.record_uid} vs {x.record_uid}")
                if pb_add_record.record_uid == x.record_uid:
                    result = x
                    break

            # If we didn't get a result, then don't add the rotation settings.
            if result is None:
                build_process_results.failure.append(
                    BulkRecordFail(
                        title=title,
                        error="No status on addition to Vault. Cannot determine if added or not."
                    )
                )
                logger.debug(f"Did not get a result when adding record {title}")
                continue

            # Check if addition failed. If it did fail, don't add the rotation settings.
            success = (result.status == record_pb2.RecordModifyResult.DESCRIPTOR.values_by_name['RS_SUCCESS'].number)
            status = record_pb2.RecordModifyResult.DESCRIPTOR.values_by_number[result.status].name

            if not success:
                build_process_results.failure.append(
                    BulkRecordFail(
                        title=title,
                        error=status
                    )
                )
                logger.debug(f"Had problem adding record for {title}: {status}")
                continue

            # Only set the rotation setting if the record is a PAM User.
            if bulk_record.record_type == PAM_USER:

                rq = router_pb2.RouterRecordRotationRequest()
                rq.recordUid = utils.base64_url_decode(bulk_record.record_uid)
                rq.revision = 0

                # Set the gateway/configuration that this record should be connected.
                rq.configurationUid = utils.base64_url_decode(gateway_context.configuration_uid)

                if bulk_record.parent_record_uid is not None:
                    rq.resourceUid = utils.base64_url_decode(bulk_record.parent_record_uid)

                # Right now, the schedule and password complexity are not set. This would be part of a rule engine.
                rq.schedule = ''
                rq.pwdComplexity = b''
                rq.disabled = rotation_disabled

                router_utils.router_set_record_rotation_information(context, rq)

            # This will be a resource.
            # A LINK edge will be created between the configuration and resource.
            # If there is an admin user, it will be set on the resource.
            else:

                # This will create a LINK between the PAM Configuration and the resource.
                rq = pam_pb2.PAMResourceConfig()
                rq.recordUid = utils.base64_url_decode(bulk_record.record_uid)
                rq.networkUid = utils.base64_url_decode(gateway_context.configuration_uid)
                if bulk_record.admin_uid:
                    rq.adminUid = utils.base64_url_decode(bulk_record.admin_uid)

                router_utils.router_configure_resource(context, rq)

            created_cache.append(bulk_record.record_uid)

            build_process_results.success.append(
                BulkRecordSuccess(
                    title=title,
                    record_uid=bulk_record.record_uid
                )
            )
        logger.info("")
        sys.stdout.flush()

        context.sync_data = True

        return build_process_results

    @classmethod
    def _convert_records(cls, bulk_convert_records: List[BulkRecordConvert], context: KeeperParams, gateway_context: Optional[GatewayContext] = None):

        vault = context.vault
        for bulk_convert_record in bulk_convert_records:

            record = vault.vault_data.load_record(bulk_convert_record.record_uid)

            rotation_disabled = False

            rq = router_pb2.RouterRecordRotationRequest()
            rq.recordUid = utils.base64_url_decode(bulk_convert_record.record_uid)

            # We can't set the version to 0 if it's greater than 0, look up prior version.
            record_rotation_revision = context.get_record_rotation(bulk_convert_record.record_uid)
            rq.revision = record_rotation_revision.revision if record_rotation_revision else 0

            # Set the gateway/configuration that this record should be connected.
            rq.configurationUid = utils.base64_url_decode(gateway_context.configuration_uid)

            # Only set the resource if the record type is a PAM User.
            # Machines, databases, and directories have a login/password in the record that indicates who the admin is.
            if record.record_type == "pamUser" and bulk_convert_record.parent_record_uid is not None:
                rq.resourceUid = utils.base64_url_decode(bulk_convert_record.parent_record_uid)

            # Right now, the schedule and password complexity are not set. This would be part of a rule engine.
            rq.schedule = ''
            rq.pwdComplexity = b''
            rq.disabled = rotation_disabled

            router_utils.router_set_record_rotation_information(context, rq)

        vault.sync_down(force=True)
        context.refresh_record_rotations()

    @staticmethod
    def _get_directory_info(domain: str,
                            skip_users: bool = False,
                            context: Optional[KeeperParams] = None,
                            gateway_context: Optional[GatewayContext] = None) -> Optional[DirectoryInfo]:
        """
        Get information about this record from the vault records.

        """

        directory_info = DirectoryInfo()

        vault = context.vault

        # Find the all directory records, in for this gateway, that have a domain that matches what we are looking for.
        for directory_record in vault.vault_data.find_records(criteria=None, record_type="pamDirectory", record_version=None):
            directory_record = vault.vault_data.load_record(directory_record.record_uid)

            info = context.get_record_rotation(directory_record.record_uid)
            if info is None:
                continue

            # Make sure this user is part of this gateway.
            if info.configuration_uid != gateway_context.configuration_uid:
                continue

            domain_field = directory_record.get_typed_field("text", label="domainName")
            if len(domain_field.value) == 0 or domain_field.value[0] == "":
                continue

            if domain_field.value[0].lower() != domain.lower():
                continue

            directory_info.directory_record_uids.append(directory_record.record_uid)

        if directory_info.has_directories is True and skip_users is False:

            for user_record in vault.vault_data.find_records(criteria=None, record_type="pamUser", record_version=None):
                info = context.get_record_rotation(user_record.record_uid)
                if info is None:
                    continue

                if info.resource_uid is None or info.resource_uid == "":
                    continue

                # If the user's belongs to a directory, and add it to the directory user list.
                if info.resource_uid in directory_info.directory_record_uids:
                    directory_info.directory_user_record_uids.append(user_record.record_uid)

        return directory_info

    @staticmethod
    def remove_job(context: KeeperParams, configuration_record: vault_record.KeeperRecord, job_id: str):

        try:
            jobs = Jobs(record=configuration_record, context=context)
            jobs.cancel(job_id)
            logger.info(f"No items left to process. Removing completed discovery job.")
        except Exception as err:
            logger.error(err)
            logger.error(f"No items left to process. Failed to remove discovery job.")

    def preview(self, job_item: JobItem, context: KeeperParams, gateway_context: GatewayContext, debug_level: int = 0):

        sync_point = job_item.sync_point
        infra = Infrastructure(record=gateway_context.configuration,
                               context=context,
                               logger=logger,
                               debug_level=debug_level)
        infra.load(sync_point)

        configuration = None
        try:
            configuration = infra.get_root.has_vertices()[0]
        except (Exception,):
            logger.error(f"Could not find the configuration in the infrastructure graph. "
                  f"Has discovery been run for this gateway?")

        record_type_to_vertices_map = sort_infra_vertices(configuration)

        # ------------

        def _print_resource(rt: str, rule_result: str):

            printed_something = False

            titles = {
                "pamDirectory": "Directories",
                "pamMachine": "Machines",
                "pamDatabase": "Databases"
            }

            for rv in record_type_to_vertices_map[rt]:
                if not rv.active or not rv.has_data:
                    continue
                user_vertices = rv.has_vertices()

                user_list = []
                for user_vertex in user_vertices:
                    if not user_vertex.active or not user_vertex.has_data:
                        continue

                    user_content = DiscoveryObject.get_discovery_object(user_vertex)
                    if user_content.ignore_object or self._record_lookup(user_content.record_uid, context, gateway_context) is not None:
                        continue

                    user_list.append(f"      . {user_content.item.user} ({user_content.name})")

                c = DiscoveryObject.get_discovery_object(rv)
                if len(user_list) == 0 and c.action_rules_result != rule_result or c.ignore_object:
                    continue

                has_record = ""
                record_uid = c.record_uid
                if record_uid is not None:
                    if self._record_lookup(record_uid, context, gateway_context):
                        has_record = f" (record exists: {record_uid})"
                        if len(user_list) == 0:
                            continue
                    else:
                        record_uid = None

                if c.action_rules_result != rule_result and not record_uid:
                    continue

                title = titles.get(c.record_type)
                if title is not None:
                    logger.info(f"  {(title)}")
                    titles[c.record_type] = None

                ip = ""
                if c.item.host != c.item.ip:
                    ip = f" ({c.item.ip})"

                with_admin = ""
                if c.admin_uid is not None and not record_uid:
                    with_admin = f" with Administrator UID {c.admin_uid}"

                logger.info(f"    * {c.description}{ip}{with_admin}{has_record}")
                printed_something = True

                if record_uid:
                    for user in user_list:
                        logger.info(user)

            return printed_something

        # ------------

        def _print_cloud_user(rt: str, rule_result: str):

            title = "Users"

            for user_vertex in record_type_to_vertices_map[rt]:
                if not user_vertex.active or not user_vertex.has_data:
                    continue

                uc = DiscoveryObject.get_discovery_object(user_vertex)

                if (uc.action_rules_result != rule_result
                        or uc.ignore_object
                        or self._record_lookup(uc.record_uid, context, gateway_context) is not None):
                    continue

                if title is not None:
                    logger.info(f"  {(title)}")
                    title = None

                logger.info(f"    * {uc.item.user} ({uc.name})")

        # ------------

        logger.info("")
        logger.info("Will Be Automatically Added")
        nothing_to_print = True
        for record_type in sorted(record_type_to_vertices_map, key=lambda i: VERTICES_SORT_MAP[i]['order']):
            if record_type == "pamUser":
                _print_cloud_user("pamUser", rule_result="add")
            else:
                if _print_resource(record_type, rule_result="add"):
                    nothing_to_print = False
        if nothing_to_print:
            logger.info(f"  {'No records will be automatically added.'}")

        logger.info("")
        logger.info("Will Be Prompted For")
        nothing_to_print = True
        for record_type in sorted(record_type_to_vertices_map, key=lambda i: VERTICES_SORT_MAP[i]['order']):
            if record_type == "pamUser":
                _print_cloud_user("pamUser", rule_result="prompt")
            else:
                if _print_resource(record_type, rule_result="prompt"):
                    nothing_to_print = False
        if nothing_to_print:
            logger.info(f"  {'No items will be prompted.'}")

        logger.info("")

    def execute(self, context: KeeperParams, **kwargs):
        if not context.vault:
            raise base.CommandError('Vault is not initialized. Login to initialize the vault.')
        
        vault = context.vault

        do_preview = kwargs.get("do_preview", False)
        job_id = kwargs.get("job_id")
        add_all = kwargs.get("add_all", False)
        debug_level = kwargs.get("debug_level", 0)

        all_gateways = GatewayContext.all_gateways(vault)

        configuration_records = GatewayContext.get_configuration_records(vault=vault)
        for configuration_record in configuration_records:

            gateway_context = GatewayContext.from_configuration_uid(vault=vault,
                                                                    configuration_uid=configuration_record.record_uid,
                                                                    gateways=all_gateways)
            if gateway_context is None:
                continue

            record_cache = self._build_record_cache(
                context=context,
                gateway_context=gateway_context
            )

            # Get the current job.
            # There can only be one active job.
            # This will give us the sync point for the delta
            jobs = Jobs(record=configuration_record, context=context, logger=logger, debug_level=debug_level)
            job_item = jobs.current_job
            if job_item is None:
                continue

            # If this is not the job we are looking for, continue to the next gateway.
            if job_item.job_id != job_id:
                continue

            if job_item.end_ts is None:
                logger.error(f'Discovery job is currently running. Cannot process.')
                return
            if job_item.success is False:
                logger.error(f'Discovery job failed. Cannot process.')
                return

            # Preview is a just a way to list which items will be added or prompted.
            if do_preview:
                self.preview(
                    job_item=job_item,
                    context=context,
                    gateway_context=gateway_context,
                )
                return

            process = Process(
                record=configuration_record,
                job_id=job_item.job_id,
                context=context,
                logger=logger,
                debug_level=debug_level,
            )

            if add_all:
                logger.info(f"The ADD ALL flag has been set. All found items will be added.")
                logger.info("")

            try:
                results = process.run(

                    # This method can get a record using the record UID
                    record_lookup_func=self._record_lookup,

                    # Prompt user the about adding records
                    prompt_func=self._prompt,

                    # Prompt user for an admin for a resource
                    prompt_admin_func=self._prompt_admin,

                    # If quit, confirm if the user wants to add records
                    prompt_confirm_add_func=self._prompt_confirm_add,

                    # Prepare records and place in queue; does not add record to vault
                    record_prepare_func=self._prepare_record,

                    # Add record to the vault, protobuf, and record-linking graph
                    record_create_func=self._create_records,

                    # This function will take existing pamUser record and make them belong to this
                    #  gateway.
                    record_convert_func=self._convert_records,

                    # A function to get directory users
                    directory_info_func=self._get_directory_info,

                    # Pass method that will display auto added records.
                    auto_add_result_func=self._display_auto_add_results,

                    # Provides a cache of the record key to record UID.
                    record_cache=record_cache,

                    # Commander-specific context.
                    # Record link will be added by Process run as "record_link"
                    context=context,
                    gateway_context=gateway_context,
                    dry_run=False,
                    add_all=add_all,
                )

                logger.debug(f"Results: {results}")

                logger.info("")
                if results is not None and results.num_results > 0:
                    logger.info(f"Successfully added {results.success_count} "
                          f"record{'s' if results.success_count != 1 else ''}.")
                    if results.has_failures:
                        logger.info(f"There were {results.failure_count} "
                              f"failure{'s' if results.failure_count != 1 else ''}.")
                        for fail in results.failure:
                            logger.info(f" * {fail.title}: {fail.error}")

                    if process.no_items_left is True:
                        self.remove_job(context=context, configuration_record=configuration_record, job_id=job_id)
                else:
                    logger.info(f"No records have been added.")

            except NoDiscoveryDataException:
                logger.info(f"All items have been added for this discovery job.")
                self.remove_job(context=context, configuration_record=configuration_record, job_id=job_id)

            except Exception as err:
                logger.error(f"Could not process discovery: {err}")
                raise err

            return

        logger.info(f"Could not find the Discovery job.")
        logger.info("")


class PAMDiscoveryRuleCommand(base.GroupCommand):

    def __init__(self):
        super().__init__('PAM Discovery Rule')
        self.register_command(PAMGatewayActionDiscoverRuleAddCommand(), 'add', 'a')
        self.register_command(PAMGatewayActionDiscoverRuleListCommand(), 'list', 'l')
        self.register_command(PAMGatewayActionDiscoverRuleRemoveCommand(), 'remove', 'r')
        self.register_command(PAMGatewayActionDiscoverRuleUpdateCommand(), 'update', 'u')
        self.default_verb = 'list'
