import argparse
import re
import time
from typing import Dict
from urllib.parse import urlparse, urlunparse

from keepersdk import crypto, utils
from keepersdk.proto import APIRequest_pb2
from keepersdk.vault import vault_record, vault_online

from ...commands import base
from ... import api
from ...params import KeeperParams
from ...helpers import router_utils, timeout_utils, email_utils, record_utils
from ...commands.pam.pam_dto import GatewayAction, GatewayActionRotate, GatewayActionRotateInputs, GatewayActionJobInfoInputs, GatewayActionJobInfo
from .discovery.discover import (PAMGatewayActionDiscoverJobStartCommand, PAMGatewayActionDiscoverJobStatusCommand, 
    PAMGatewayActionDiscoverJobRemoveCommand, PAMGatewayActionDiscoverResultProcessCommand, PAMDiscoveryRuleCommand)
from .service.service_commands import PAMActionServiceListCommand, PAMActionServiceAddCommand, PAMActionServiceRemoveCommand
from .saas.saas_commands import PAMActionSaasConfigCommand, PAMActionSaasSetCommand, PAMActionSaasRemoveCommand, PAMActionSaasUserCommand, PAMActionSaasUpdateCommand
from .debug.debug_info import PAMDebugInfoCommand
from .debug.debug_gateway import PAMDebugGatewayCommand
from .debug.debug_graph import PAMDebugGraphCommand
from .debug.debug_acl import PAMDebugACLCommand
from .debug.debug_link import PAMDebugLinkCommand
from .debug.debug_rs import PAMDebugRotationSettingsCommand
from .debug.debug_vertex import PAMDebugVertexCommand

from keepersdk.proto import pam_pb2
from keepersdk.helpers import pam_config_facade, config_utils
from keepersdk.helpers.tunnel import tunnel_graph, tunnel_utils
from keepersdk.helpers.keeper_dag import record_link as record_link_utils, dag_utils

logger = api.get_logger()


class PAMGatewayActionServerInfoCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='dr-info-command')
        PAMGatewayActionServerInfoCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=False, dest='gateway_uid', action='store', help='Gateway UID')
        parser.add_argument('--verbose', '-v', required=False, dest='verbose', action='store_true', help='Verbose Output')
    
    def execute(self, context: KeeperParams, **kwargs):
        destination_gateway_uid_str = kwargs.get('gateway_uid')
        is_verbose = kwargs.get('verbose')
        router_response = router_utils.router_send_action_to_gateway(
            context=context,
            gateway_action=GatewayAction(action='server_info', is_scheduled=False),
            message_type=pam_pb2.CMT_GENERAL,
            is_streaming=False,
            destination_gateway_uid_str=destination_gateway_uid_str
        )

        router_utils.print_router_response(router_response, 'gateway_info', is_verbose=is_verbose, gateway_uid=destination_gateway_uid_str)


class PAMGatewayActionRotateCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action rotate')
        PAMGatewayActionRotateCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--record-uid', '-r', dest='record_uid', action='store', help='Record UID to rotate')
        parser.add_argument('--folder', '-f', dest='folder', action='store', help='Shared folder UID or title pattern to rotate')
        parser.add_argument('--dry-run', '-n', dest='dry_run', default=False, action='store_true', help='Enable dry-run mode')
        parser.add_argument('--self-destruct', dest='self_destruct', action='store',
                        metavar='<NUMBER>[(m)inutes|(h)ours|(d)ays]',
                        help='Create one-time share link that expires after duration')
        parser.add_argument('--email-config', dest='email_config', action='store',
                        help='Email configuration name to use for sending (required with --send-email)')
        parser.add_argument('--send-email', dest='send_email', action='store',
                        help='Email address to send credentials after rotation')
        parser.add_argument('--email-message', dest='email_message', action='store',
                       help='Custom message to include in email')
    
    def execute(self, context: KeeperParams, **kwargs):
        if context.vault is None:
            raise base.CommandError('Vault is not initialized. Login to initialize the vault.')
        
        vault = context.vault

        record_uid = kwargs.get('record_uid', '')
        folder = kwargs.get('folder', '')
        recursive = kwargs.get('recursive', False)
        pattern = kwargs.get('pattern', '')  # additional record title match pattern
        dry_run = kwargs.get('dry_run', False)

        # Store email/share arguments as instance variables
        self.self_destruct = kwargs.get('self_destruct')
        self.email_config = kwargs.get('email_config')
        self.send_email = kwargs.get('send_email')
        self.email_message = kwargs.get('email_message')

        vault = context.vault

        if self.send_email:
            if not self.email_config:
                raise base.CommandError('--send-email requires --email-config to specify email configuration')

            # Find and load email config to validate provider and dependencies
            try:
                config_uid = email_utils.find_email_config_record(vault, self.email_config)
                email_config_obj = email_utils.load_email_config_from_record(vault, config_uid)

                is_valid, error_message = email_utils.validate_email_provider_dependencies(email_config_obj.provider)

                if not is_valid:
                    raise base.CommandError(f'\n{error_message}')

            except Exception as e:
                if isinstance(e, base.CommandError):
                    raise
                raise base.CommandError(f'Failed to validate email configuration: {e}')

        if not record_uid and not folder:
            logger.info(f'the following arguments are required: --record-uid/-r or --folder/-f')
            return

        if not folder:
            self.record_rotate(context, record_uid)
            return

        folders = []  # root folders matching UID or title pattern
        records = []  # record UIDs of all v3/pamUser records

        if folder in vault.vault_data.folders():
            fldr = vault.vault_data.get_folder(folder)

            if fldr.folder_type in ('shared_folder', 'shared_folder_folder'):
                folders.append(folder)
            else:
                logger.debug(f'Folder skipped (not a shared folder/subfolder) - {folder} {fldr.name}')
        else:
            rx_name = self.str_to_regex(folder)
            for fuid in vault.vault_data.folders():
                fldr = vault.vault_data.get_folder(fuid.folder_uid)
                if fldr.folder_type in ('shared_folder', 'shared_folder_folder'):
                    if fldr.name and rx_name.search(fldr.name):
                        folders.append(fldr.folder_uid)

        folders = list(set(folders))

        if recursive and len(folders) > 1:
            roots: Dict[str, list] = {}
            for fuid in folders:
                roots.setdefault(vault.vault_data.get_folder(fuid).folder_scope_uid, []).append(fuid)
            uniq = []
            for fuid in roots:
                fldrs = list(set(roots[fuid]))
                if len(fldrs) == 1:
                    uniq.append(fldrs[0])
                elif fuid in fldrs:
                    uniq.append(fuid)
                else:
                    fldrset = set(fldrs)
                    for fldr in fldrs:
                        path = []
                        child = fldr
                        while vault.vault_data.get_folder(child).folder_uid != fuid:
                            path.append(child)
                            child = vault.vault_data.get_folder(child).parent_uid
                        path.append(child)
                        path = path[1:] if path else []
                        if not set(path) & fldrset:
                            uniq.append(fldr)
            folders = list(set(uniq))

        for fldr in folders:
            if recursive:
                logger.warning('--recursive/-a option not implemented (ignored)')
            
            folder_sub = vault.vault_data.get_folder(fldr)
            folder_records = folder_sub.records

            if folder_records:
                logger.debug(f"folder {fldr} empty - no records in folder(skipped)")
                continue
            for ruid in folder_records:
                record = vault.vault_data.get_record(ruid)
                if record and record.record_type == 'pamUser':
                    records.append(ruid)
        records = list(set(records))

        logger.info(f'Selected for rotation - folders: {len(folders)}, records: {len(records)}, recursive={recursive}')

        if logger.isEnabledFor(logger.DEBUG):
            for fldr in folders:
                fobj = vault.vault_data.get_folder(fldr)
                title = fobj.name if fobj else ''
                logger.debug(f'Rotation Folder UID: {fldr} {title}')
            for rec in records:
                record = vault.vault_data.get_record(rec)
                title = record.title if record else ''
                logger.debug(f'Rotation Record UID: {rec} {title}')

        if dry_run:
            return

        for record_uid in records:
            delay = 0
            while True:
                try:
                    self.record_rotate(context, record_uid, True)
                    break
                except Exception as e:
                    msg = str(e)
                    if re.search(r"throttle", msg, re.IGNORECASE):
                        delay = (delay+10) % 100
                        logger.debug(f'Record UID: {record_uid} was throttled (retry in {delay} sec)')
                        time.sleep(1+delay)
                    else:
                        logger.error(f'Record UID: {record_uid} skipped: non-throttling, non-recoverable error: {msg}')
                        break

    def record_rotate(self, context: KeeperParams, record_uid, slient:bool = False):
        vault = context.vault
        record = vault.vault_data.load_record(record_uid)
        if not isinstance(record, vault_record.TypedRecord):
            logger.error(f'Record [{record_uid}] is not available.')
            return

        ri = record_utils.record_rotation_get(vault, utils.base64_url_decode(record.record_uid))
        ri_pwd_complexity_encrypted = ri.pwdComplexity
        if not ri_pwd_complexity_encrypted:
            rule_list_dict = {
                'length': 20,
                'caps': 1,
                'lowercase': 1,
                'digits': 1,
                'special': 1,
            }
            record_key = vault.vault_data.get_record_key(record.record_uid)
            ri_pwd_complexity_encrypted = utils.base64_url_encode(router_utils.encrypt_pwd_complexity(rule_list_dict, record_key))

        resource_uid = None

        encrypted_session_token, encrypted_transmission_key, transmission_key = tunnel_utils.get_keeper_tokens(vault)
        config_uid = tunnel_utils.get_config_uid(vault, encrypted_session_token, encrypted_transmission_key, record_uid)
        if not config_uid:
            ri_rotation_setting_uid = utils.base64_url_encode(ri.configurationUid)
            resource_uid = utils.base64_url_encode(ri.resourceUid)
            pam_config = vault.vault_data.load_record(ri_rotation_setting_uid)
            if not isinstance(pam_config, vault_record.TypedRecord):
                logger.error(f'PAM Configuration [{ri_rotation_setting_uid}] is not available.')
                return
            facade = pam_config_facade.PamConfigurationRecordFacade()
            facade.record = pam_config

            config_uid = facade.controller_uid

        if not resource_uid:
            tmp_dag = tunnel_graph.TunnelDAG(vault, encrypted_session_token, encrypted_transmission_key, record.record_uid)
            resource_uid = tmp_dag.get_resource_uid(record_uid)
            if not resource_uid:
                is_noop = False
                pam_config = vault.vault_data.load_record(config_uid)

                record_link = record_link_utils.RecordLink(record=pam_config,
                                         context=context,
                                         fail_on_corrupt=False)
                acl = record_link.get_acl(record_uid, pam_config.record_uid)
                if acl is not None and acl.rotation_settings is not None:
                    is_noop = acl.rotation_settings.noop

                if is_noop is False:
                    noop_field = record.get_typed_field('text', 'NOOP')
                    is_noop = dag_utils.value_to_boolean(noop_field.value[0]) if noop_field and noop_field.value else False

                if not is_noop:
                    logger.error(f'Resource UID not found for record [{record_uid}]. please configure it '
                          f'"pam rotation user {record_uid} --resource RESOURCE_UID"')
                    return

        controller = config_utils.configuration_controller_get(vault, utils.base64_url_decode(config_uid))
        if not controller.controllerUid:
            raise base.CommandError(f'Gateway UID not found for configuration '
                                   f'{config_uid}.')

        enterprise_controllers_connected = router_utils.router_get_connected_gateways(vault)

        controller_from_config_bytes = controller.controllerUid
        gateway_uid = utils.base64_url_encode(controller.controllerUid)
        if enterprise_controllers_connected:
            router_controllers = {controller.controllerUid: controller for controller in
                                  list(enterprise_controllers_connected.controllers)}
            connected_controller = router_controllers.get(controller_from_config_bytes)

            if not connected_controller:
                logger.warning(f'The Gateway "{gateway_uid}" is down.')
                return
        else:
            logger.warning(f'There are no connected gateways.')
            return

        action_inputs = GatewayActionRotateInputs(
            record_uid=record_uid,
            configuration_uid=config_uid,
            pwd_complexity_encrypted=ri_pwd_complexity_encrypted,
            resource_uid=resource_uid
        )

        conversation_id = GatewayAction.generate_conversation_id()

        router_response = router_utils.router_send_action_to_gateway(
            context=context, gateway_action=GatewayActionRotate(inputs=action_inputs, conversation_id=conversation_id,
                                                              gateway_destination=gateway_uid),
            message_type=pam_pb2.CMT_ROTATE, is_streaming=False,
            transmission_key=transmission_key,
            encrypted_transmission_key=encrypted_transmission_key,
            encrypted_session_token=encrypted_session_token)

        if (self.self_destruct or self.send_email) and router_response:
            try:
                vault.sync_down(force=True)
                record = vault.vault_data.load_record(record_uid)
                if isinstance(record, vault_record.TypedRecord):
                    self._handle_post_rotation_email(vault, record)
            except Exception as e:
                logger.warning(f'Post-rotation email handling failed: {e}')

        if not slient:
            router_utils.print_router_response(router_response, 'job_info', conversation_id, gateway_uid=gateway_uid)

    def _handle_post_rotation_email(self, vault: vault_online.VaultOnline, record):
        """Handle email sending and share link creation after successful rotation."""
        try:
            if self.send_email and not self.email_config:
                logger.warning(f'--send-email requires --email-config. Skipping email.')
                return

            user_requested_self_destruct = bool(self.self_destruct)

            if self.send_email and not self.self_destruct:
                self.self_destruct = '24h'
                logger.info('--send-email used without --self-destruct, creating 24 hour time-based share link')

            share_url = None
            expiration_text = None
            if self.self_destruct:
                try:
                    expiration_period = timeout_utils.parse_timeout(self.self_destruct)
                    expire_seconds = int(expiration_period.total_seconds())

                    if expire_seconds <= 0:
                        logger.warning(f'Invalid --self-destruct value. Skipping share link.')
                        return

                    if expire_seconds >= 86400:
                        days = expire_seconds // 86400
                        expiration_text = f"{days} day{'s' if days > 1 else ''}"
                    elif expire_seconds >= 3600:
                        hours = expire_seconds // 3600
                        expiration_text = f"{hours} hour{'s' if hours > 1 else ''}"
                    else:
                        minutes = expire_seconds // 60
                        expiration_text = f"{minutes} minute{'s' if minutes > 1 else ''}"

                    logger.info(f'Creating one-time share link expiring in {self.self_destruct}...')
                    record_uid = record.record_uid
                    record_key = record.record_key
                    client_key = utils.generate_aes_key()
                    client_id = crypto.hmac_sha512(client_key, 'KEEPER_SECRETS_MANAGER_CLIENT_ID'.encode())
                    rq = APIRequest_pb2.AddExternalShareRequest()
                    rq.recordUid = utils.base64_url_decode(record_uid)
                    rq.encryptedRecordKey = crypto.encrypt_aes_v2(record_key, client_key)
                    rq.clientId = client_id
                    rq.accessExpireOn = utils.current_milli_time() + int(expiration_period.total_seconds() * 1000)
                    rq.isSelfDestruct = user_requested_self_destruct
                    vault.keeper_auth.execute_auth_rest(
                        rest_endpoint='vault/external_share_add',
                        request=rq,
                        response_type=APIRequest_pb2.Device
                    )
                    parsed = urlparse(vault.keeper_auth.keeper_endpoint.server)
                    server_netloc = parsed.netloc if parsed.netloc else parsed.path
                    share_url = urlunparse(('https', server_netloc, '/vault/share', None, None, utils.base64_url_encode(client_key)))
                    logger.info(f'Share link created successfully')
                except Exception as e:
                    logger.warning(f'Failed to create share link: {e}')
                    return

            if self.send_email and self.email_config and share_url:
                try:
                    logger.info(f'Loading email configuration: {self.email_config}')
                    config_uid = email_utils.find_email_config_record(vault, self.email_config)
                    if not config_uid:
                        logger.warning(f'Email configuration "{self.email_config}" not found. Skipping email.')
                        return

                    email_config = email_utils.load_email_config_from_record(vault, config_uid)

                    custom_message = self.email_message or 'Your password has been rotated. Click the link below to view your new credentials.'

                    html_content = email_utils.build_onboarding_email(
                        share_url=share_url,
                        custom_message=custom_message,
                        record_title=record.title,
                        expiration=expiration_text
                    )

                    logger.info(f'Sending email to {self.send_email}...')
                    email_sender = email_utils.EmailSender(email_config)
                    email_sender.send(
                        to=self.send_email,
                        subject=f"Password Rotated: {record.title}",
                        body=html_content,
                        html=True
                    )

                    if email_config.is_oauth_provider() and email_config._oauth_tokens_updated:
                        logger.info('Updating OAuth tokens in email configuration record...')
                        email_utils.update_oauth_tokens_in_record(
                            vault,
                            config_uid,
                            email_config.oauth_access_token,
                            email_config.oauth_refresh_token,
                            email_config.oauth_token_expiry
                        )

                    logger.info(f'Email sent successfully to {self.send_email}')

                except Exception as e:
                    logger.warning(f'Failed to send email: {e}')
                    return

        except Exception as e:
            logger.warning(f'Error in post-rotation email handler: {e}')

    def str_to_regex(self, text):
        text = str(text)
        try:
            pattern = re.compile(text, re.IGNORECASE)
        except:
            pattern = re.compile(re.escape(text), re.IGNORECASE)
            logger.debug(f"regex pattern {text} failed to compile (using it as plaintext pattern)")
        return pattern

class PAMGatewayActionJobCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action job')
        PAMGatewayActionJobCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=False, dest='gateway_uid', action='store',
                        help='Gateway UID. Needed only if there are more than one gateway running')
        parser.add_argument('job_id', help='Job ID')
    
    def execute(self, context: KeeperParams, **kwargs):
        job_id = kwargs.get('job_id')
        gateway_uid = kwargs.get('gateway_uid')

        logger.info(f"Job id to check [{job_id}]")

        action_inputs = GatewayActionJobInfoInputs(job_id)

        conversation_id = GatewayAction.generate_conversation_id()
        router_response = router_utils.router_send_action_to_gateway(
            context=context,
            gateway_action=GatewayActionJobInfo(inputs=action_inputs, conversation_id=conversation_id),
            message_type=pam_pb2.CMT_GENERAL,
            is_streaming=False,
            destination_gateway_uid_str=gateway_uid,
        )

        router_utils.print_router_response(router_response, 'job_info', original_conversation_id=conversation_id, gateway_uid=gateway_uid)


class PAMDiscoveryCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('PAM Discovery')
        self.register_command(PAMGatewayActionDiscoverJobStartCommand(), 'start', 's')
        self.register_command(PAMGatewayActionDiscoverJobStatusCommand(), 'status', 'st')
        self.register_command(PAMGatewayActionDiscoverJobRemoveCommand(), 'remove', 'r')
        self.register_command(PAMGatewayActionDiscoverResultProcessCommand(), 'process', 'p')
        self.register_command(PAMDiscoveryRuleCommand(), 'rule', 'r')

        self.default_verb = 'status'


class PAMActionServiceCommand(base.GroupCommand):

    def __init__(self):
        super().__init__('PAM Action Service')
        self.register_command(PAMActionServiceListCommand(), 'list', 'l')
        self.register_command(PAMActionServiceAddCommand(), 'add', 'a')
        self.register_command(PAMActionServiceRemoveCommand(), 'remove', 'r')
        self.default_verb = 'list'


class PAMActionSaasCommand(base.GroupCommand):

    def __init__(self):
        super().__init__('PAM Action Saas')
        self.register_command(PAMActionSaasConfigCommand(), 'config', 'c')
        self.register_command(PAMActionSaasSetCommand(), 'set', 's')
        self.register_command(PAMActionSaasRemoveCommand(), 'remove', 'r')
        self.register_command(PAMActionSaasUserCommand(), 'user', 'i')
        self.register_command(PAMActionSaasUpdateCommand(), 'update', 'u')


class PAMDebugCommand(base.GroupCommand):

    def __init__(self):
        super().__init__('PAM Debug')
        self.register_command(PAMDebugInfoCommand(), 'info', 'i')
        self.register_command(PAMDebugGatewayCommand(), 'gateway', 'g')
        self.register_command(PAMDebugGraphCommand(), 'graph', 'r')
        self.register_command(PAMDebugACLCommand(), 'acl', 'c')
        self.register_command(PAMDebugLinkCommand(), 'link', 'l')
        self.register_command(PAMDebugRotationSettingsCommand(), 'rs-reset', 'rs')
        self.register_command(PAMDebugVertexCommand(), 'vertex', 'v')


