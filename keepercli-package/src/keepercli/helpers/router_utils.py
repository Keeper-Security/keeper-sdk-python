from datetime import datetime
import json
import logging
import os
import google
import requests
from typing import Optional

from keepersdk import utils, crypto
from keepersdk.authentication import endpoint
from keepersdk.proto import pam_pb2, router_pb2
from keepersdk.vault import vault_online
from keepersdk.errors import KeeperApiError

from ..helpers import gateway_utils
from ..commands.pam.pam_dto import GatewayAction
from ..params import KeeperParams

API_PATH_GET_CONTROLLERS = "get_controllers"
VERIFY_SSL = bool(os.environ.get("VERIFY_SSL", "TRUE") == "TRUE")


def router_get_connected_gateways(vault: vault_online.VaultOnline) -> Optional[pam_pb2.PAMOnlineControllers]:
    """Get connected gateways from the router."""
    rs = vault.keeper_auth.keeper_endpoint.execute_router_rest(
        endpoint=API_PATH_GET_CONTROLLERS, 
        session_token=vault.keeper_auth.auth_context.session_token,
        payload=b''
    )

    if isinstance(rs, bytes):
        pam_online_controllers = pam_pb2.PAMOnlineControllers()
        pam_online_controllers.ParseFromString(rs)
        if logging.getLogger().level <= logging.DEBUG:
            js = google.protobuf.json_format.MessageToJson(pam_online_controllers)
            logging.debug('>>> [GW RS] %s: %s', API_PATH_GET_CONTROLLERS, js)

        return pam_online_controllers

    return None


def router_send_action_to_gateway(context: KeeperParams, gateway_action: GatewayAction, message_type, is_streaming,
                                  destination_gateway_uid_str=None, gateway_timeout=15000, transmission_key=None,
                                  encrypted_transmission_key=None, encrypted_session_token=None):
    # Default time out how long the response from the Gateway should be
    krouter_host = context.auth.keeper_endpoint.get_router_server()

    # 1. Find connected gateway to send action to
    try:
        router_enterprise_controllers_connected = \
            [x.controllerUid for x in router_get_connected_gateways(context.vault).controllers]

    except requests.exceptions.ConnectionError as errc:
        logging.info(f"Looks like router is down. Router URL [{krouter_host}]")
        return
    except Exception as e:
        raise e

    if destination_gateway_uid_str:
        # Means that we want to get info for a specific Gateway

        destination_gateway_uid_bytes = utils.base64_url_decode(destination_gateway_uid_str)

        if destination_gateway_uid_bytes not in router_enterprise_controllers_connected:
            logging.warning(f"\tThis Gateway currently is not online.")
            return
    else:
        if not router_enterprise_controllers_connected or len(router_enterprise_controllers_connected) == 0:
            logging.warning(f"\tNo running or connected Gateways in your enterprise. "
                  f"Start the Gateway before sending any action to it.")
            return
        elif len(router_enterprise_controllers_connected) == 1:
            destination_gateway_uid_bytes = router_enterprise_controllers_connected[0]
            destination_gateway_uid_str = utils.base64_url_encode(destination_gateway_uid_bytes)
        else:  # There are more than two Gateways connected. Selecting the right one

            if not gateway_action.gateway_destination:
                logging.warning(f"There are more than one Gateways running in your enterprise. "
                      f"Only 'pam action rotate' is able to know "
                      f"which Gateway should receive a request. Any other commands should have a Gateway specified. "
                      f"See help for the command you are trying to use. To find connected gateways run action "
                      f"'pam gateway list' and provide Gateway UID or Gateway Name.")

                return

            destination_gateway_uid_bytes = gateway_utils.find_connected_gateways(router_enterprise_controllers_connected, gateway_action.gateway_destination)
            destination_gateway_uid_str = utils.base64_url_encode(destination_gateway_uid_bytes)

    msg_id = gateway_action.conversationId if gateway_action.conversationId else GatewayAction.generate_conversation_id('true')

    rq = router_pb2.RouterControllerMessage()
    rq.messageUid = utils.base64_url_decode(msg_id) if isinstance(msg_id, str) else msg_id
    rq.controllerUid = destination_gateway_uid_bytes
    rq.messageType = message_type
    rq.streamResponse = is_streaming
    rq.payload = gateway_action.toJSON().encode('utf-8')
    rq.timeout = gateway_timeout

    if not transmission_key:
        transmission_key = utils.generate_aes_key()

    response = router_send_message_to_gateway(
        context=context,
        transmission_key=transmission_key,
        rq_proto=rq,
        encrypted_transmission_key=encrypted_transmission_key,
        encrypted_session_token=encrypted_session_token)

    rs_body = response.content

    if type(rs_body) == bytes:
        router_response = router_pb2.RouterResponse()
        router_response.ParseFromString(rs_body)

        rrc = router_pb2.RouterResponseCode.Name(router_response.responseCode)
        if router_response.responseCode == router_pb2.RRC_OK:
            logging.debug("Good response...")

        elif router_response.responseCode == router_pb2.RRC_BAD_STATE:
            raise Exception(router_response.errorMessage + ' response code: ' + rrc)

        elif router_response.responseCode == router_pb2.RRC_TIMEOUT:
            # Router tried to send message to the Controller but the response didn't arrive on time
            # ex. if Router is expecting response to be within 3 sec, but the gateway didn't respond within that time
            raise Exception(router_response.errorMessage + ' response code: ' + rrc)

        elif router_response.responseCode == router_pb2.RRC_CONTROLLER_DOWN:
            # Sent an action to the Controller that is no longer online
            raise Exception(router_response.errorMessage + ' response code: ' + rrc)

        else:
            raise Exception(router_response.errorMessage + ' response code: ' + rrc)


        payload_encrypted = router_response.encryptedPayload
        if payload_encrypted:

            payload_decrypted = crypto.decrypt_aes_v2(payload_encrypted, transmission_key)

            controller_response = pam_pb2.ControllerResponse()
            controller_response.ParseFromString(payload_decrypted)

            gateway_response_payload = json.loads(controller_response.payload)
        else:
            gateway_response_payload = {}

        return {
            'response': gateway_response_payload
        }


def router_send_message_to_gateway(context: KeeperParams, transmission_key, rq_proto,
                                   encrypted_transmission_key=None, encrypted_session_token=None):

    krouter_host = context.auth.keeper_endpoint.get_router_server()

    if not encrypted_transmission_key:
        server_public_key = endpoint.SERVER_PUBLIC_KEYS[context.auth.keeper_endpoint.server_key_id]

        if context.auth.keeper_endpoint.server_key_id < 7:
            encrypted_transmission_key = crypto.encrypt_rsa(transmission_key, server_public_key)
        else:
            encrypted_transmission_key = crypto.encrypt_ec(transmission_key, server_public_key)

    encrypted_payload = b''

    if rq_proto:
        encrypted_payload = crypto.encrypt_aes_v2(rq_proto.SerializeToString(), transmission_key)
    if not encrypted_session_token:
        encrypted_session_token = crypto.encrypt_aes_v2(utils.base64_url_decode(context.auth.auth_context.session_token), transmission_key)

    rs = requests.post(
        krouter_host+"/api/user/send_controller_message",
        verify=VERIFY_SSL,

        headers={
            'TransmissionKey': utils.base64_url_encode(encrypted_transmission_key),
            'Authorization': f'KeeperUser {utils.base64_url_encode(encrypted_session_token)}',
        },
        data=encrypted_payload if rq_proto else None
    )

    if rs.status_code >= 300:
        raise Exception(str(rs.status_code) + ': error: ' + rs.reason + ', message: ' + rs.text)

    return rs


def print_router_response(router_response, response_type, original_conversation_id=None, is_verbose=False, gateway_uid=''):
    if not router_response:
        return

    router_response_response = router_response.get('response')
    router_response_response_payload_str = router_response_response.get('payload')
    router_response_response_payload_dict = json.loads(router_response_response_payload_str)

    if router_response_response_payload_dict.get('warnings'):
        for w in router_response_response_payload_dict.get('warnings'):
            if w:
                logging.warning(f'{w}')

    if original_conversation_id:
        # gateway_response_conversation_id = utils.base64_url_decode(router_response_response_payload_dict.get('conversation_id')).decode("utf-8")
        # IDs are either bytes or base64 encoded strings which may be padded
        gateway_response_conversation_id = router_response_response_payload_dict.get('conversation_id', None)
        oid = (utils.base64_url_decode(original_conversation_id)
               if isinstance(original_conversation_id, str)
               else original_conversation_id)
        gid = (utils.base64_url_decode(gateway_response_conversation_id)
               if isinstance(gateway_response_conversation_id, str)
               else gateway_response_conversation_id)

        if oid != gid:
            logging.error(f"Message ID that was sent to the server [{original_conversation_id}] and the conversation id "
                          f"received back [{gateway_response_conversation_id}] are different. That probably means that "
                          f"the gateway sent a wrong response that was not associated with the request.")

    if not (router_response_response_payload_dict.get('is_ok') or router_response_response_payload_dict.get('isOk')):
        logging.error(f"{json.dumps(router_response_response_payload_dict, indent=4)}")
        return

    if router_response_response_payload_dict.get('isScheduled') or router_response_response_payload_dict.get('is_scheduled'):
        conversation_id = router_response_response_payload_dict.get('conversation_id')

        gwinfo = f" --gateway={gateway_uid}" if gateway_uid else ""
        logging.info(f"Scheduled action id: {conversation_id}")
        logging.info(f"The action has been scheduled, use command 'pam action job-info {conversation_id}{gwinfo}' to get status of the scheduled action")
        return

    elif response_type == 'job_info':
        job_info = router_response_response_payload_dict.get('data')
        exec_response_value = job_info.get('execResponseValue')
        exec_response_value_msg = exec_response_value.get('message') if exec_response_value else None
        exec_response_value_logs = exec_response_value.get('execLog') if exec_response_value else None
        exec_duration = job_info.get('executionDuration')
        exec_status = job_info.get('status')
        exec_exception = job_info.get('execException')

        logging.info(f'Execution Details\n-------------------------')

        logging.info(f'\tStatus              : {job_info.get("reason") if job_info.get("reason") else exec_status}')

        if exec_duration:
            logging.info(f'\tDuration            : {exec_duration}')

        if exec_response_value_msg:
            logging.info(f'\tResponse Message    : {exec_response_value_msg}')

        if exec_response_value_logs:
            logging.info(f'\tPost-execution scripts logs:')
            for el in exec_response_value_logs:
                logging.info(f'\t\tscript: {el.get("name")}')
                logging.info(f'\t\treturn code: {el.get("return_code")}')
                if el.get("stdout"):
                    logging.info(f'\t\tstdout:\n---\n{el.get("stdout")}\n---')
                if el.get("stderr"):
                    logging.info(f'\t\tstderr:\n---\n{el.get("stderr")}\n---')
                logging.info(f'\n')

        if exec_exception:
            logging.info(f'\tExecution Exception : {exec_exception}')

    elif response_type == 'gateway_info':

        gateway_info = router_response_response_payload_dict.get('data')

        # Version and Gateway Details
        logging.info(f'\nGateway Details')
        gateway_config = gateway_info.get('gateway-config', {})
        version_info = gateway_config.get('version', {})
        if version_info.get("current"):
            logging.info(f'\tVersion           : {version_info.get("current")}')

        # Convert Unix timestamp to readable format
        started_time = gateway_config.get("connection_info", {}).get("started")
        try:
            if started_time:
                started_dt = datetime.fromtimestamp(float(started_time))
                local_tz = datetime.now().astimezone().tzinfo
                started_str = f"{started_dt.strftime('%Y-%m-%d %H:%M:%S')} {local_tz}"
                logging.info(f'\tStarted Time      : {started_str}')
        except (ValueError, TypeError):
            pass 

        if gateway_config.get("ws_log_file"):
            logging.info(f'\tLogs Location     : {gateway_config.get("ws_log_file")}')

        # Environment Info
        machine_env = gateway_info.get('machine', {}).get('environment', {})
        if machine_env and machine_env.get('provider'):
            logging.info(f'\nEnvironment Details')
            logging.info(f'\tProvider          : {machine_env.get("provider")}')
            if machine_env.get('provider') != 'Local/Other':
                if machine_env.get('account_id'):
                    logging.info(f'\tAccount           : {machine_env.get("account_id")}')
                if machine_env.get('region'):
                    logging.info(f'\tRegion            : {machine_env.get("region")}')
                if machine_env.get('instance_type'):
                    logging.info(f'\tInstance Type     : {machine_env.get("instance_type")}')

        # Machine Details
        machine = gateway_info.get('machine', {})
        logging.info(f'\nMachine Details')

        if machine.get("hostname"):
            logging.info(f'\tHostname          : {machine.get("hostname")}')
        if machine.get("ip_address_local") and machine.get("ip_address_local") != "unknown":
            logging.info(f'\tIP (Local)        : {machine.get("ip_address_local")}')
        if machine.get("ip_address_external"):
            logging.info(f'\tIP (External)     : {machine.get("ip_address_external")}')

        os_info = []
        if machine.get("system"): os_info.append(machine.get("system"))
        if machine.get("release"): os_info.append(machine.get("release"))
        if os_info:
            logging.info(f'\tOperating System  : {" ".join(os_info)}')

        memory = machine.get('memory', {})
        if memory.get('free_gb') is not None and memory.get('total_gb') is not None:
            logging.info(f'\tMemory            : {memory.get("free_gb")}GB free / {memory.get("total_gb")}GB total')

        # Core Package Versions - Extract from installed packages
        installed_packages = {
            pkg.split('==')[0]: pkg.split('==')[1]
            for pkg in machine.get('installed-python-packages', [])
        }

        core_packages = [
            ('KDNRM', installed_packages.get('kdnrm')),
            ('Keeper GraphSync', installed_packages.get('keeper-dag')),
            ('Discovery Common', installed_packages.get('discovery-common'))
        ]

        # Only print Core Components section if at least one core package is found
        if any(version for _, version in core_packages):
            logging.info(f'\nCore Components')
            for name, version in core_packages:
                if version:  # Only print if version is found
                    logging.info(f'\t{name:<16} : {version}')

        # KSM Details
        logging.info(f'\nKSM Application Details')
        ksm_app = gateway_info.get('ksm', {}).get('app', {})

        if ksm_app.get("title"):
            logging.info(f'\tTitle             : {ksm_app.get("title")}')
        if ksm_app.get("records-count") is not None:
            logging.info(f'\tRecords Count     : {ksm_app.get("records-count")}')
        if ksm_app.get("folders-count") is not None:
            logging.info(f'\tFolders Count     : {ksm_app.get("folders-count")}')
        if ksm_app.get("expires-on"):
            logging.info(f'\tExpires On        : {ksm_app.get("expires-on")}')
        logging.info(f'\tWarnings          : {ksm_app.get("warnings") or "None"}')

        # Router Details
        logging.info(f'\nRouter Connection')
        router_conn = gateway_info.get('router', {}).get('connection', {})
        if router_conn.get("base-url"):
            logging.info(f'\tURL               : {router_conn.get("base-url")}')
        router_status = router_conn.get("status", "UNKNOWN").lower()
        logging.info(f'\tStatus            : {router_status}')

        # PAM Configurations
        logging.info(f'\nPAM Configurations Accessible to this Gateway')
        pam_configs = gateway_info.get('pam_configurations', [])
        if pam_configs:
            for idx, config in enumerate(pam_configs, 1):
                logging.info(f'\t{idx}. {config}')
        else:
            logging.info(f'\tNo PAM Configurations found')

        # Additional details for verbose mode
        if is_verbose:
            logging.info(f'\nAdditional Details')
            if machine.get("working-dir"):
                logging.info(f'\tWorking Directory : {machine.get("working-dir")}')
            if machine.get("package-dir"):
                logging.info(f'\tPackage Directory: {machine.get("package-dir")}')
            if machine.get("executable"):
                logging.info(f'\tPython Executable: {machine.get("executable")}')

            if machine.get('installed-python-packages'):
                logging.info(f'\nInstalled Python Packages')
                for package in sorted(machine.get('installed-python-packages', [])):
                    logging.info(f'\t{package}')


def get_response_payload(router_response):

    router_response_response = router_response.get('response')
    router_response_response_payload_str = router_response_response.get('payload')
    router_response_response_payload_dict = json.loads(router_response_response_payload_str)

    return router_response_response_payload_dict


def _post_request_to_router(context: KeeperParams, path, rq_proto=None, rs_type=None, method='post',
                            raw_without_status_check_response=False, query_params=None, transmission_key=None,
                            encrypted_transmission_key=None, encrypted_session_token=None):
    krouter_host = context.auth.keeper_endpoint.get_router_server()
    path = '/api/user/' + path

    if not transmission_key:
        transmission_key = utils.generate_aes_key()
    if not encrypted_transmission_key:
        server_public_key = endpoint.SERVER_PUBLIC_KEYS[context.auth.keeper_endpoint.server_key_id]

        if context.auth.keeper_endpoint.server_key_id < 7:
            encrypted_transmission_key = crypto.encrypt_rsa(transmission_key, server_public_key)
        else:
            encrypted_transmission_key = crypto.encrypt_ec(transmission_key, server_public_key)

    encrypted_payload = b''

    if rq_proto:
        if logging.getLogger().level <= logging.DEBUG:
            js = google.protobuf.json_format.MessageToJson(rq_proto)
            logging.debug('>>> [GW RQ] %s: %s', path, js)
        encrypted_payload = crypto.encrypt_aes_v2(rq_proto.SerializeToString(), transmission_key)

    if not encrypted_session_token:
        encrypted_session_token = crypto.encrypt_aes_v2(utils.base64_url_decode(context.auth.auth_context.session_token), transmission_key)

    try:
        rs = requests.request(method,
                              krouter_host + path,
                              params=query_params,
                              verify=VERIFY_SSL,
                              headers={
                                'TransmissionKey': utils.base64_url_encode(encrypted_transmission_key),
                                'Authorization': f'KeeperUser {utils.base64_url_encode(encrypted_session_token)}'
                              },
                              data=encrypted_payload if rq_proto else None
        )
    except ConnectionError as e:
        raise KeeperApiError(-1, f"KRouter is not reachable on '{krouter_host}'. Error: ${e}")
    except Exception as ex:
        raise ex

    content_type = rs.headers.get('Content-Type') or ''

    if raw_without_status_check_response:
        return rs

    if rs.status_code < 400:
        if content_type == 'application/json':
            return rs.json()

        rs_body = rs.content
        if isinstance(rs_body, bytes):
            router_response = router_pb2.RouterResponse()
            router_response.ParseFromString(rs_body)

            rrc = router_pb2.RouterResponseCode.Name(router_response.responseCode)
            if router_response.responseCode != router_pb2.RRC_OK:
                raise Exception(router_response.errorMessage + ' Response code: ' + rrc)

            if router_response.encryptedPayload:
                payload_encrypted = router_response.encryptedPayload
                payload_decrypted = crypto.decrypt_aes_v2(payload_encrypted, transmission_key)
            else:
                payload_decrypted = None

            if rs_type:
                if payload_decrypted:
                    rs_proto = rs_type()
                    rs_proto.ParseFromString(payload_decrypted)
                    if logging.getLogger().level <= logging.DEBUG:
                        js = google.protobuf.json_format.MessageToJson(rs_proto)
                        logging.debug('>>> [GW RS] %s: %s', 'get_rotation_schedules', js)
                    return rs_proto
                else:
                    return None

            return payload_decrypted

        return rs_body
    else:
        raise KeeperApiError(rs.status_code, rs.text)


def router_set_record_rotation_information(context: KeeperParams, proto_request, transmission_key=None,
                                           encrypted_transmission_key=None, encrypted_session_token=None):
    rs = _post_request_to_router(context, 'set_record_rotation', proto_request, transmission_key=transmission_key,
                                 encrypted_transmission_key=encrypted_transmission_key,
                                 encrypted_session_token=encrypted_session_token)

    return rs


def router_configure_resource(context: KeeperParams, proto_request, transmission_key=None,
                              encrypted_transmission_key=None, encrypted_session_token=None):
    rs = _post_request_to_router(context, 'configure_resource', proto_request, transmission_key=transmission_key,
                                 encrypted_transmission_key=encrypted_transmission_key,
                                 encrypted_session_token=encrypted_session_token)

    return rs