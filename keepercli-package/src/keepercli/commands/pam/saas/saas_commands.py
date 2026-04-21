
import argparse
import json
import logging
import os
import traceback
from typing import List, Optional
from tempfile import TemporaryDirectory

from keepersdk.helpers.keeper_dag import dag_utils

from .... import api
from ..discovery.__init__ import GatewayContext, PAMGatewayActionDiscoverCommandBase
from ..pam_dto import GatewayAction
from ....params import KeeperParams
from .... import api
from ....__init__ import __version__
from . import (
    SaasCatalog,
    get_plugins_map,
    get_field_input,
    make_script_signature,
    get_record_field_value,
    set_record_field_value,
)

from keepersdk.vault import vault_record, vault_extensions, attachment, record_management
from keepersdk.helpers.keeper_dag.constants import PAM_USER, PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY
from keepersdk.helpers.keeper_dag.record_link import RecordLink
from keepersdk.helpers.keeper_dag.dag_types import UserAclRotationSettings
from keepersdk import crypto, utils
from keepersdk.proto import record_pb2
from keepersdk.errors import KeeperApiError

logger = api.get_logger()


class RecordNotConfigException(Exception):
    pass


class GatewayActionSaasConfigCommandInputs:

    def __init__(self,
                 configuration_uid: str,
                 plugin_code: str,
                 gateway_context: GatewayContext,
                 languages: Optional[List[str]] = None,
                 ):

        if languages is None:
            languages = ["en_US"]

        self.configurationUid = configuration_uid
        self.pluginCodeEnv = gateway_context.encrypt_str(plugin_code)
        self.languages = languages

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionSaasListCommand(GatewayAction):

    def __init__(self, inputs: GatewayActionSaasConfigCommandInputs, conversation_id=None):
        super().__init__('saas-list', inputs=inputs, conversation_id=conversation_id, is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class PAMActionSaasConfigCommand(PAMGatewayActionDiscoverCommandBase):
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam-action-saas-config')
        PAMActionSaasConfigCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                            help='Gateway name or UID')
        parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                            action='store', help='PAM configuration UID, if gateway has multiple.')
        parser.add_argument('--list', '-l', required=False, dest='do_list', action='store_true',
                            help='List available SaaS rotations.')
        parser.add_argument('--plugin', '-p', required=False, dest='plugin', action='store',
                            help='Plugin name')
        parser.add_argument('--info', required=False, dest='do_info', action='store_true',
                            help='Get information about a plugin or plugins being used.')
        parser.add_argument('--create', required=False, dest='do_create', action='store_true',
                            help='Create a SaaS Plugin config record.')
        parser.add_argument('--update-config-uid', '-u', required=False, dest='do_update', action='store',
                            help='Update an existing SaaS configuration.')
        parser.add_argument('--shared-folder-uid', '-s', required=False, dest='shared_folder_uid',
                            action='store', help='Shared folder to store SaaS configuration.')

    @staticmethod
    def _show_list(plugins: dict[str, SaasCatalog]):

        sorted_catalog = {}
        if plugins:
            sorted_catalog = dict(sorted(plugins.items(), key=lambda i: i[1].name))

        sort_results = {
            "custom": {"title": "Custom", "using": [], "not_using": []},
            "catalog": {"title": "Catalog", "using": [], "not_using": []},
            "builtin": {"title": "Builtin", "using": [], "not_using": []},
        }

        logger.info("")
        logger.info(f"Available SaaS Plugins")
        for _, plugin in sorted_catalog.items():
            plugin_type = plugin.type
            status = "using" if len(plugin.used_by) is True else "not_using"
            sort_results[plugin_type][status].append(plugin)

        for plugin_type in ["custom", "catalog", "builtin"]:
            for status in ["not_using", "using"]:
                title = sort_results[plugin_type]["title"]
                for plugin in sort_results[plugin_type][status]:
                    summary = plugin.summary or "No description available"
                    name = plugin.name
                    desc = f" ({title}"
                    if status == "using":
                        desc += f", Using"
                    desc += f")"
                    row = f" * {name}{desc} - {summary}"
                    logger.info(row)

    @staticmethod
    def _show_plugin_info(plugin: SaasCatalog):
        logger.info("")
        logger.info(f"{plugin.name}")
        logger.info(f"  Type: {plugin.type}")
        if plugin.author and plugin.email:
            logger.info(f"  Author: {plugin.author} ({plugin.email})")
        elif plugin.author:
            logger.info(f"  Author: {plugin.author}")
        logger.info(f"  Summary: {plugin.summary or 'No description available'}")
        if plugin.readme:
            logger.info(f"  Documents: {plugin.readme}")
        logger.info(f"  Fields")
        req_field = []
        opt_field = []
        for field in plugin.fields:
            if field.required:
                req_field.append(f"   * Required: {field.label} - "
                                 f"{field.desc}")
            else:
                opt_field.append(f"   * Optional: {field.label} - {field.desc}")
        for item in req_field:
            logger.info(item)
        for item in opt_field:
            logger.info(item)
        logger.info("")

    @staticmethod
    def _create_config(context: KeeperParams,
                       plugin: SaasCatalog,
                       shared_folder_uid: str,
                       plugin_code_bytes: Optional[bytes] = None):

        custom_fields = [
            vault_record.TypedField.new_field(
                field_type="text",
                field_label="SaaS Type",
                field_value=[plugin.name]
            ),
            vault_record.TypedField.new_field(
                field_type="text",
                field_label="Active",
                field_value=["TRUE"]
            )
        ]

        for is_required in [True, False]:
            for item in plugin.fields:
                if item.required is is_required:
                    logger.info("")
                    value = get_field_input(item)
                    if value is not None:
                        field_type = item.type
                        if field_type in ["url", "int", "number", "bool", "enum"]:
                            field_type = "text"

                        field_args = {
                            "field_type": field_type,
                            "field_label": item.label,
                            "field_value": value
                        }
                        record_field = vault_record.TypedField.new_field(**field_args)

                        record_field.required = True
                        custom_fields.append(record_field)

        logger.info("")
        while True:
            title = input("Title for the SaaS configuration record> ")
            if title != "":
                break
            logger.error(f"Require a record title.")

        record = vault_record.TypedRecord()
        record.type_name = "login"
        record.record_uid = utils.generate_uid()
        record.record_key = utils.generate_aes_key()
        record.title = title

        for item in custom_fields:
            record.custom.append(item)

        vault = context.vault
        folder = vault.vault_data.get_folder(shared_folder_uid)
        folder_key = None  # type: Optional[bytes]
        if folder.folder_type == 'shared_folder_folder':
            shared_folder_uid = folder.folder_scope_uid
        elif folder.folder_type == 'shared_folder':
            shared_folder_uid = folder.folder_uid
        else:
            shared_folder_uid = None
        if shared_folder_uid and shared_folder_uid in vault.vault_data._shared_folders:
            shared_folder = vault.vault_data.get_folder(shared_folder_uid)
            folder_key = shared_folder.folder_key

        add_record = record_pb2.RecordAdd()
        add_record.record_uid = utils.base64_url_decode(record.record_uid)
        add_record.record_key = crypto.encrypt_aes_v2(record.record_key, vault.keeper_auth.auth_context.data_key)
        add_record.client_modified_time = utils.current_milli_time()
        add_record.folder_type = record_pb2.user_folder
        if folder:
            add_record.folder_uid = utils.base64_url_decode(folder.uid)
            if folder.type == 'shared_folder':
                add_record.folder_type = record_pb2.shared_folder
            elif folder.type == 'shared_folder_folder':
                add_record.folder_type = record_pb2.shared_folder_folder
            if folder_key:
                add_record.folder_key = crypto.encrypt_aes_v2(record.record_key, folder_key)

        data = vault_extensions.extract_typed_record_data(record)
        json_data = vault_extensions.get_padded_json_bytes(data)
        add_record.data = crypto.encrypt_aes_v2(json_data, record.record_key)

        if vault.keeper_auth.auth_context.enterprise_ec_public_key:
            audit_data = vault_extensions.extract_audit_data(record)
            if audit_data:
                add_record.audit.version = 0
                add_record.audit.data = crypto.encrypt_ec(
                    json.dumps(audit_data).encode('utf-8'), vault.keeper_auth.auth_context.enterprise_ec_public_key)

        rq = record_pb2.RecordsAddRequest()
        rq.records.append(add_record)
        rs = vault.keeper_auth.execute_auth_rest('vault/records_add', rq, response_type=record_pb2.RecordsModifyResponse)
        record_rs = next((x for x in rs.records if utils.base64_url_encode(x.record_uid) == record.record_uid), None)
        if record_rs:
            if record_rs.status != record_pb2.RS_SUCCESS:
                raise KeeperApiError(record_rs.status, rs.message)
        record.revision = rs.revision

        vault.sync_down()

        # If this is not a built-in or custom script, we need to attach it to the config record.
        if plugin_code_bytes is not None and plugin.file_name:

            with TemporaryDirectory() as temp_dir:
                vault.sync_down()

                existing_record = vault.vault_data.load_record(record.record_uid)
                if existing_record is None:
                    logger.error(f"Could not load the config record {record.record_uid} to attach script.")
                    return

                temp_file = os.path.join(temp_dir, plugin.file_name)
                with open(temp_file, "wb") as fh:
                    fh.write(plugin_code_bytes)
                    fh.close()
                task = attachment.FileUploadTask(temp_file)
                task.title = f"{plugin.name} Script"
                task.mime_type = "text/x-python"

                if plugin.file_sig:
                    script_signature = make_script_signature(plugin_code_bytes)
                    if script_signature != plugin.file_sig:
                        raise ValueError("The plugin signature in catalog does not match what was downloaded.")

                attachment.upload_attachments(context, existing_record, [task])

                record.fields = [
                    vault_record.TypedField.new_field(
                        field_type="fileRef",
                        field_value=list(existing_record.linked_keys.keys()))
                ]

                record_management.update_record(context, existing_record)
                context.vault.sync_down()

        logger.info("")
        logger.info(f"Created SaaS configuration record with UID of {record.record_uid}")
        logger.info("")
        logger.info("Assign this configuration to a user using the following command.")
        logger.info(f"  pam action saas set -c {record.record_uid} -u <PAM User Record UID>")
        logger.info(f"  See pam action saas set --help for more information.")

    def execute(self, context: KeeperParams, **kwargs):

        do_list = kwargs.get("do_list", False) 
        do_info = kwargs.get("do_info", False) 
        do_create = kwargs.get("do_create", False)
        do_update = kwargs.get("do_update", False)
        shared_folder_uid = kwargs.get("shared_folder_uid")

        use_plugin = kwargs.get("plugin")
        gateway = kwargs.get("gateway")
        configuration_uid = kwargs.get('configuration_uid')

        vault = context.vault
        gateway_context = GatewayContext.from_gateway(vault=vault, gateway=gateway, configuration_uid=configuration_uid)
        if gateway_context is None:
            logger.error(f"Could not find the gateway configuration for {gateway}.")
            return None

        plugins = get_plugins_map(context=context, gateway_context=gateway_context)

        if do_list:
            self._show_list(plugins)
        elif use_plugin is not None:

            if use_plugin not in plugins:
                logger.error(f"Cannot find '{use_plugin}' in the catalog.")
                return None

            plugin = plugins[use_plugin]

            if do_info:
                self._show_plugin_info(plugin=plugin)

            elif do_create:

                shared_folders = gateway_context.get_shared_folders(vault)
                if shared_folder_uid is None:
                    if len(shared_folders) == 1:
                        shared_folder_uid = shared_folders[0].get("uid")
                    else:
                        logger.error(f"Multiple shared folders found. Please use '-s' to select a shared folder.")
                if next((x for x in shared_folders if x.get("uid") == shared_folder_uid), None) is None:
                    logger.error(f"The shared folder is not part of the gateway application.")
                    return None

                # For catalog plugins, we need to download the python file from GitHub.
                plugin_code_bytes = None
                if plugin.type == "catalog" and plugin.file:
                    res = utils.ssl_aware_get(plugin.file)
                    if res.ok is False:
                        logger.error(f"Could not download the script from GitHub.")
                        return None
                    plugin_code_bytes = res.content

                self._create_config(
                    context=context,
                    plugin=plugin,
                    shared_folder_uid=shared_folder_uid,
                    plugin_code_bytes=plugin_code_bytes)
            elif do_update:
                pass
            else:
                self.get_parser().print_help()
        else:
            if do_update:
                pass
            else:
                self.get_parser().print_help()


class PAMActionSaasSetCommand(PAMGatewayActionDiscoverCommandBase):
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action saas set')
        PAMActionSaasSetCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--user-uid', '-u', required=True, dest='user_uid', action='store',
                            help='The UID of the User record')
        parser.add_argument('--config-record-uid', '-c', required=True, dest='config_record_uid',
                            action='store', help='The UID of the record that has SaaS configuration')
        parser.add_argument('--resource-uid', '-r', required=False, dest='resource_uid', action='store',
                            help='The UID of the Resource record, if needed.')
    
    def execute(self, context: KeeperParams, **kwargs):

        user_uid = kwargs.get("user_uid")
        resource_uid = kwargs.get("resource_uid")
        config_record_uid = kwargs.get("config_record_uid")

        logger.info("")

        vault = context.vault

        # Check to see if the record exists.
        user_record = vault.vault_data.get_record(user_uid)
        if user_record is None:
            logger.error(f"The user record does not exists.")
            return

        # Make sure this user is a PAM User.
        if user_record.record_type != PAM_USER:
            logger.error(f"The user record is not a PAM User.")
            return

        record_rotation = context.get_record_rotation(user_record.record_uid)
        if record_rotation is not None:
            configuration_uid = record_rotation.configuration_uid
        else:
            logger.error(f"The user record does not have any rotation settings.")
            return

        if configuration_uid is None:
            logger.error(f"The user record does not have the configuration record set in the rotation settings.")
            return

        gateway_context = GatewayContext.from_configuration_uid(vault=vault, configuration_uid=configuration_uid)

        if gateway_context is None:
            logger.error(f"The user record does not have the set gateway")
            return

        plugins = get_plugins_map(context=context, gateway_context=gateway_context)
        if plugins is None:
            return

        # Check to see if the config record exists.
        config_record = vault.vault_data.get_record(config_record_uid)
        if config_record is None:
            logger.error(f"The SaaS configuration record does not exists.")
            return

        # Make sure this config is a Login record.

        if config_record.record_type not in ["login", "saasConfiguration"]:
            logger.error(f"The SaaS configuration record is not a SaaS configuration record: "
                         f"{config_record.record_type}")
            return
        
        config_record = vault.vault_data.load_record(config_record_uid)

        plugin_name_field = next((x for x in config_record.custom if x.label == "SaaS Type"), None)
        if plugin_name_field is None:
            logger.error(f"The SaaS configuration record is missing the custom field label 'SaaS Type'")
            return

        plugin_name = None
        if plugin_name_field.value is not None and len(plugin_name_field.value) > 0:
            plugin_name = plugin_name_field.value[0]

        if plugin_name is None:
            logger.error(f"The SaaS configuration record's custom field label 'SaaS Type' does not have a value.")
            return

        if plugin_name not in plugins:
            logger.error(f"The SaaS configuration record's custom field label 'SaaS Type' is not supported by the "
                         "gateway or the value is not correct.")
            return

        plugin = plugins[plugin_name]

        # Make sure the SaaS configuration record has correct custom fields.
        missing_fields = []
        for field in plugin.fields:
            if field.required is True and field.default_value is None:
                found = next((x for x in config_record.custom if x.label == field.label), None)
                if not found:
                    missing_fields.append(field.label.strip())

        if len(missing_fields) > 0:
            logger.error(f"The SaaS configuration record is missing the following required custom fields: "
                         f'{", ".join(missing_fields)}')
            return

        parent_uid = gateway_context.configuration_uid

        # Not sure if SaaS type rotation should be limited to NOOP rotation.
        # Allow a resource record to be used.
        if resource_uid is not None:
            # Check to see if the record exists.
            resource_record = vault.vault_data.load_record(resource_uid)
            if resource_record is None:
                logger.error(f"The resource record does not exists.")
                return

            # Make sure this user is a PAM User.
            if user_record.record_type in [PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY]:
                logger.error(f"The resource record does not have the correct record type.")
                return

            parent_uid = resource_uid

        record_link = RecordLink(record=gateway_context.configuration, context=context, fail_on_corrupt=False)
        acl = record_link.get_acl(user_uid, parent_uid)
        if acl is None:
            if resource_uid is not None:
                logger.error(f"There is no relationship between the user and the resource record.")
            else:
                logger.error(f"There is no relationship between the user and the configuration record.")
            return

        if acl.rotation_settings is None:
            acl.rotation_settings = UserAclRotationSettings()

        if resource_uid is not None and acl.rotation_settings.noop is True:
            logger.error(f"The rotation is flagged as No Operation, however you passed in a resource record. "
                         f"This combination is not allowed.")
            return

        # If there is a resource record, it not NOOP.
        # If there is NO resource record, it is NOOP.
        # However, if this is an IAM User, don't set the NOOP
        if acl.is_iam_user is False:
            acl.rotation_settings.noop = resource_uid is None

        # Make sure we are not re-adding the same SaaS config.
        if config_record_uid in acl.rotation_settings.saas_record_uid_list:
            logger.error(f"The SaaS configuration record is already being used for this user.")
            return

        acl.rotation_settings.saas_record_uid_list = [config_record_uid]

        record_link.belongs_to(user_uid, parent_uid, acl=acl)
        record_link.save()

        logger.info(f"Setting {plugin_name} rotation for the user record.")
        logger.info("")



class PAMActionSaasRemoveCommand(PAMGatewayActionDiscoverCommandBase):
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam-action-saas-remove')
        PAMActionSaasRemoveCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--user-uid', '-u', required=True, dest='user_uid', action='store',
                            help='The UID of the User record')
        parser.add_argument('--resource-uid', '-r', required=False, dest='resource_uid', action='store',
                            help='The UID of the Resource record, if needed.')

    def execute(self, context: KeeperParams, **kwargs):

        user_uid = kwargs.get("user_uid")  # type: str
        resource_uid = kwargs.get("resource_uid")  # type: str

        logger.info("")
        vault = context.vault

        # Check to see if the record exists.
        user_record = vault.vault_data.get_record(user_uid)
        if user_record is None:
            logger.error(f"The user record does not exists.")
            return

        # Make sure this user is a PAM User.
        if user_record.record_type != PAM_USER:
            logger.error(f"The user record is not a PAM User.")
            return

        record_rotation = context.get_record_rotation(user_record.record_uid)
        if record_rotation is not None:
            configuration_uid = record_rotation.configuration_uid
        else:
            logger.error(f"The user record does not have any rotation settings.")
            return

        if configuration_uid is None:
            logger.error(f"The user record does not have the configuration record set in the rotation settings.")
            return

        gateway_context = GatewayContext.from_configuration_uid(vault=vault, configuration_uid=configuration_uid)

        if gateway_context is None:
            logger.error(f"The user record does not have the set gateway")
            return

        # Don't check config record
        # Just accept the record UID; the record might not exist anymore.

        parent_uid = gateway_context.configuration_uid

        # Not sure if SaaS type rotation should be limited to NOOP rotation.
        # Allow a resource record to be used.
        if resource_uid is not None:
            # Check to see if the record exists.
            resource_record = vault.vault_data.get_record(resource_uid)
            if resource_record is None:
                logger.error(f"The resource record does not exists.")
                return

            # Make sure this user is a PAM User.
            if user_record.record_type in [PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY]:
                logger.error(f"The resource record does not have the correct record type.")
                return

            parent_uid = resource_uid

        record_link = RecordLink(record=gateway_context.configuration, context=context, fail_on_corrupt=False)
        acl = record_link.get_acl(user_uid, parent_uid)
        if acl is None:
            if resource_uid is not None:
                logger.error(f"There is no relationship between the user and the resource record.")
            else:
                logger.error(f"There is no relationship between the user and the configuration record.")
            return

        if acl.rotation_settings is None:
            acl.rotation_settings = UserAclRotationSettings()

        if resource_uid is not None and acl.rotation_settings.noop is True:
            logger.error(f"The rotation is flagged as No Operation, however you passed in a resource record. "
                         f"This combination is not allowed.")
            return

        # An empty array removes the SaaS config.
        acl.rotation_settings.saas_record_uid_list = []

        record_link.belongs_to(user_uid, parent_uid, acl)
        record_link.save()

        logger.info(f"Removing SaaS service rotation from the user record.")


class PAMActionSaasUserCommand(PAMGatewayActionDiscoverCommandBase):
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam-action-saas-user')
        PAMActionSaasUserCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--user-record-uid', '-u', required=True, dest='user_uid', action='store',
                            help='The UID of the User record')

    def execute(self, context: KeeperParams, **kwargs):

        user_uid = kwargs.get("user_uid")

        logger.info("")
        vault = context.vault

        # Check to see if the record exists.
        user_record = vault.vault_data.get_record(user_uid)
        if user_record is None:
            logger.error(f"The user record does not exists.")
            return

        # Make sure this user is a PAM User.
        if user_record.record_type != PAM_USER:
            logger.error(f"The user record is not a PAM User.")
            return

        record_rotation = context.get_record_rotation(user_record.record_uid)
        if record_rotation is not None:
            configuration_uid = record_rotation.configuration_uid
        else:
            logger.error(f"The user record does not have any rotation settings.")
            return

        if configuration_uid is None:
            logger.error(f"The user record does not have the configuration record set in the rotation settings.")
            return

        gateway_context = GatewayContext.from_configuration_uid(vault=vault, configuration_uid=configuration_uid)

        if gateway_context is None:
            logger.error(f"The user record does not have the set gateway")
            return

        plugins = get_plugins_map(context, gateway_context)

        record_link = RecordLink(record=gateway_context.configuration, context=context, fail_on_corrupt=False)
        user_vertex = record_link.get_record_link(user_uid)
        if user_vertex is None:
            logger.error(f"Cannot find the user in the record link graph.")
            return

        logger.info(f"User: {user_record.title}")

        missing_configs = []

        # User's can have multiple ACL edges to different parents.
        # One of those ACL edges, in the rotation settings, may a populated saas_record_uid_list
        for parent_vertex in user_vertex.belongs_to_vertices():

            # Check to see if the record exists.
            parent_record = vault.vault_data.get_record(parent_vertex.uid)
            if parent_record is None:
                logger.error(f"* Parent record UID {parent_vertex.uid} does not exists.")
                logger.error(f"   The record may have been deleted, however the relationship still exists.")
                logger.info("")
                continue

            logger.info(f" * {parent_record.title}, {parent_record.record_type}")
            logger.info("")

            acl = record_link.get_acl(user_uid, parent_vertex.uid)
            if acl is not None and acl.rotation_settings is not None:
                saas_record_uid_list = acl.rotation_settings.saas_record_uid_list
                if saas_record_uid_list is None or len(saas_record_uid_list) == 0:
                    logger.error(f"    The user does not have any SaaS service rotations.")
                    return

                for config_record_uid in saas_record_uid_list:
                    config_record = vault.vault_data.get_record(config_record_uid)
                    if config_record is None:
                        logger.error(f" * Record UID {config_record_uid} not longer exists.")
                        continue
                    logger.info(f"   {config_record.title}")

                    plugin_name = "<Not Set>"
                    saas_type_field = next((x for x in config_record.custom if x.label == "SaaS Type"), None)
                    if (saas_type_field is not None and saas_type_field.value is not None
                            and len(saas_type_field.value) > 0):
                        plugin_name = saas_type_field.value[0]

                    plugin = plugins.get(plugin_name)

                    # This might have been a valid plugin, or the name is mistyped, so it's not supported.
                    if plugin is None:
                        plugin_name += " (Not Supported)"

                    rotation_active = "Active"
                    rotation_active_field = next((x for x in config_record.custom if x.label == "Active"),
                                                 None)

                    if (rotation_active_field is not None and rotation_active_field.value is not None
                            and len(rotation_active_field.value) > 0):
                        is_active = dag_utils.value_to_boolean(rotation_active_field.value[0])
                        if is_active is False:
                            rotation_active = "Inactive"

                    logger.info(f"     SaaS Type: {plugin_name}")
                    logger.info(f"     Config Record UID: {config_record.record_uid}")
                    logger.info(f"     Active: {rotation_active}")

                    if plugin is not None:

                        for field in plugin.fields:
                            value = next((x.value for x in config_record.custom if x.label == field.label), None)
                            if value is not None:
                                if len(value) > 0:
                                    value = value[0]
                                else:
                                    value = None
                            if value is None:
                                if field.default_value is not None:
                                    value = f"{field.default_value} (Default)"
                                else:
                                    value = "Not Set"
                            logger.info(f"     {field.label}: {value}")
                    logger.info("")


class PAMActionSaasUpdateCommand(PAMGatewayActionDiscoverCommandBase):

    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam-action-saas-update')
        PAMActionSaasUpdateCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                            help='Gateway name of UID.')
        parser.add_argument('--configuration-uid', required=False, dest='configuration_uid',
                            action='store', help='PAM configuration UID, if gateway has multiple.')
        parser.add_argument('--all', '-a', required=False, dest='do_all', action='store_true',
                            help='Update all configurations.')
        parser.add_argument('--config-record-uid', '-c', required=False, dest='config_uid', action='store',
                            help='Update a specific configuration.')
        parser.add_argument('--dry-run', required=False, dest='do_dry_run', action='store_true',
                            help='Dry run. Do not save any changes.')

    @staticmethod
    def get_field_values(record: vault_record.TypedRecord, field_type: str) -> List[str]:
        return next(
            (f.value
             for f in record.fields
             if f.type == field_type),
            None
        )

    @classmethod
    def _get_file_refs(cls, record: vault_record.TypedRecord) -> List[str]:
        return list(next((x.value for x in record.fields if x.type == "fileRef"), []))

    @classmethod
    def _update_script(cls, context: KeeperParams, config_record: vault_record.TypedRecord, plugin: SaasCatalog):

        if plugin.type != "catalog":
            raise ValueError("Cannot download script for non-catalog plugin.")

        if not plugin.file:
            raise ValueError("Plugin does not have a file URL.")

        if not plugin.file_name:
            raise ValueError("Plugin does not have a file name.")

        logger.info("  * downloading updated plugin script")
        res = utils.ssl_aware_get(plugin.file)
        if res.ok is False:
            raise ValueError("Could download updated script from GitHub")
        plugin_code_bytes = res.content

        new_script_sig = make_script_signature(plugin_code_bytes=plugin_code_bytes)

        if plugin.file_sig:
            logger.debug(f"downloaded {new_script_sig} vs catalog {plugin.file_sig}")
            if new_script_sig != plugin.file_sig:
                raise ValueError("The plugin signature in catalog does not match what was downloaded.")

        with TemporaryDirectory() as temp_dir:
            temp_file = os.path.join(temp_dir, plugin.file_name)
            with open(temp_file, "wb") as fh:
                fh.write(plugin_code_bytes)
                fh.close()

            task = attachment.FileUploadTask(temp_file)
            task.title = f"{plugin.name} Script"
            task.mime_type = "text/x-python"

            # Get the existing attached; we are going to remove these
            existing_file_refs = cls._get_file_refs(config_record)
            logger.debug(f"existing file ref: {existing_file_refs}")

            attachment.upload_attachments(context.vault, config_record, [task])

            new_file_refs = cls._get_file_refs(config_record)
            logger.debug(f"new file ref: {new_file_refs}")

            if existing_file_refs is not None:
                logger.debug("existing file ref exists")
                for existing_file_ref in existing_file_refs:  # type: str
                    logger.debug(f"  * {existing_file_ref}")
                    if existing_file_ref in new_file_refs:
                        new_file_refs.remove(existing_file_ref)
            else:
                logger.debug("no existing file ref, use new file ref")

            logger.debug(f"save file ref: {new_file_refs}")

            config_record.fields = [
                vault_record.TypedField.new_field(
                    field_type="fileRef",
                    field_value=new_file_refs
                )
            ]

            record_management.update_record(context.vault, config_record)
            context.sync_data = True

            logger.info(f"  * the plugin script is now up-to-date.")

    @classmethod
    def _missing_fields(cls, config_record: vault_record.TypedRecord, plugin: SaasCatalog) -> List[str]:

        # Make the record into a map by the field label
        records_field_map = {}
        for field in config_record.custom:
            records_field_map[field.label] = field

        missing_fields = []
        for field in plugin.fields:

            # We only care about required fields.
            if not field.required or field.default_value is not None:
                continue
            record_field = records_field_map.get(field.label)
            if (record_field is None
                    or record_field.value is None
                    or len(record_field.value) == 0
                    or record_field.value[0] is None
                    or record_field.value[0] == ""):
                missing_fields.append(field.label)
        return missing_fields

    @classmethod
    def _update_config(cls,
                       context: KeeperParams,
                       plugins: dict[str, SaasCatalog],
                       config_record: vault_record.TypedRecord,
                       dry_run: bool = False) -> Optional[SaasCatalog]:

        plugin_field = next((x for x in config_record.custom if x.label == "SaaS Type"), None)
        if plugin_field is None or len(plugin_field.value) == 0:
            logger.debug("record is not a SaaS Configuration record")
            raise RecordNotConfigException()
        plugin_name = plugin_field.value[0]
        logger.debug(f"plugin name is {plugin_name}")

        plugin = plugins.get(plugin_name)
        if plugin is not None and plugin.type == "catalog":

            missing_fields = cls._missing_fields(config_record=config_record, plugin=plugin)

            logger.info(f"{config_record.title} ({config_record.record_uid}) - {plugin_name}")
            logger.debug(f"plugin is {plugin_name} for config {config_record.title}")
            attachments = list(attachment.prepare_attachment_download(context.vault, config_record.record_uid))

            # If there is no script, just attach script to record.
            # Someone might have deleted the script from the record.
            if len(attachments) == 0:
                logger.info("  * the record does not contain a plugin script.")
                logger.debug("  * configuration did not have script, add current script.")

                if not dry_run:
                    cls._update_script(
                        context=context,
                        config_record=config_record,
                        plugin=plugin,
                    )
                else:
                    logger.info(f"  * not updating script due to dry run.")

                if len(missing_fields) == 0:
                    logger.info(f"  * the configuration record fields are up-to-date.")
                else:
                    logger.error(f"  * the configuration record's required field(s) are missing or blank: "
                          f"{', '.join(missing_fields)}")
                logger.info("")
                return plugin

            logger.debug(f"found {len(attachments)} attached script(s).")

            if len(attachments) > 1:
                raise ValueError("Found multiple scripts. Only one script is allowed per SaaS Configuration record.")

            for atta in attachments:
                with TemporaryDirectory() as temp_dir:
                    if not plugin.file_name:
                        logger.debug("plugin does not have a file name, using default")
                        temp_file = str(os.path.join(temp_dir, f"{plugin.name}_script.py"))
                    else:
                        temp_file = str(os.path.join(temp_dir, plugin.file_name))
                    logger.debug(f"download to {temp_file}")

                    # download_to_file prints to the screen, we don't want that.
                    log_level = logger.getEffectiveLevel()
                    try:
                        logger.setLevel(logging.WARNING)
                        atta.download_to_file(context.vault, temp_file)
                    finally:
                        logger.setLevel(log_level)

                    with open(temp_file, "rb") as fh:
                        plugin_code_bytes = fh.read()
                        fh.close()

                    attach_file_sig = make_script_signature(plugin_code_bytes=plugin_code_bytes)
                
                if plugin.file_sig:
                    logger.debug(f"attached {attach_file_sig} vs catalog {plugin.file_sig}")
                    sig_matches = attach_file_sig == plugin.file_sig
                else:
                    logger.debug("plugin does not have a file signature, skipping verification")
                    sig_matches = True
                
                if not sig_matches:
                    logger.error(f"  * the plugin script have changed.")
                    logger.debug("the script has changed, update")

                    if not dry_run:
                        cls._update_script(
                            context=context,
                            config_record=config_record,
                            plugin=plugin,
                        )
                    else:
                        logger.info(f"  * not updating script due to dry run.")
                else:
                    logger.info(f"  * the plugin script is up-to-date.")

                if len(missing_fields) == 0:
                    logger.info(f"  * the configuration record fields are up-to-date.")
                else:
                    logger.error(f"  * the configuration record's required field(s) are missing or blank: "
                          f"{', '.join(missing_fields)}")

                # If the record type is login, migrate to saasConfiguration
                if config_record.record_type == "login":
                    logger.info(f"  * migrate record type to SaaS Configuration.")
                    config_record.type_name = "saasConfiguration"
                    record_management.update_record(context.vault, config_record)

                logger.info("")

        logger.debug("plugin doesn't used attached scripts, or bad SaaS type in config record.")
        return plugin

    def execute(self, context: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")  # type: str
        do_all = kwargs.get("do_all", False)  # type: bool
        config_record_uid = kwargs.get("config_uid")  # type: str
        do_dry_run = kwargs.get("do_dry_run", False)  # type: bool

        configuration_uid = kwargs.get('configuration_uid')  # type Optional[str]
        vault = context.vault

        gateway_context = GatewayContext.from_gateway(context=context,
                                                        gateway=gateway,
                                                        configuration_uid=configuration_uid)
        if gateway_context is None:
            logger.error(f"Could not find the gateway configuration for {gateway}.")
            return

        logger.info("")

        if do_dry_run:
            logger.info(f"Dry run enabled. No changes will be saved.")
            logger.info("")

        plugins = get_plugins_map(
            context=context,
            gateway_context=gateway_context
        )

        if do_all:
            logger.debug("search vault for login record types")
            for record in list(vault.vault_data.find_records(criteria=None, record_type=["login", "saasConfiguration"], record_version=None)):
                logger.debug("--------------------------------------------------------------------------------------")
                config_record = vault.vault_data.load_record(record.record_uid)

                logger.debug(f"checking record {record.record_uid}, {record.title}")
                try:
                    self._update_config(
                        context=context,
                        plugins=plugins,
                        config_record=config_record,
                        dry_run=do_dry_run
                    )
                except RecordNotConfigException:
                    pass
                except Exception as err:
                    logger.error(f"  *{err}")
                    logger.debug(traceback.format_exc())
                    logger.debug(f"ERROR (no fatal): {err}")

                context.sync_data = True

        elif config_record_uid is not None:
            config_record = vault.vault_data.load_record(config_record_uid)
            if config_record is None:
                logger.error(f"Cannot find a record for UID {config_record_uid}.")
                return

            try:
                plugin = self._update_config(
                    context=context,
                    plugins=plugins,
                    config_record=config_record,
                    dry_run=do_dry_run
                )
                if plugin is not None:
                    missing_fields = self._missing_fields(config_record=config_record, plugin=plugin)

                    if len(missing_fields) > 0:

                        # If we added a script, we need to sync down to get the record version number correct.
                        vault.sync_down()
                        config_record = vault.vault_data.load_record(config_record_uid)

                        # If the record type is login, migrate to saasConfiguration
                        if config_record.record_type == "login":
                            logger.debug("migrating from login to saasConfiguration record type")
                            config_record.type_name = "saasConfiguration"

                        for required in [True, False]:
                            for field in plugin.fields:
                                if field.required is required:
                                    current_value = get_record_field_value(
                                        record=config_record,
                                        label=field.label
                                    )
                                    logger.info("")
                                    value = get_field_input(field, current_value=current_value)
                                    if value is not None:
                                        set_record_field_value(
                                            record=config_record,
                                            label=field.label,
                                            value=value
                                        )

                        if not do_dry_run:
                            record_management.update_record(vault, config_record)
                            logger.info("")
                            logger.info(f"The SaaS configuration record has been updated.")
                            logger.info("")
                        else:
                            logger.info("")
                            logger.info(f"The SaaS configuration record was not saved due to dry run.")
                            logger.info("")

                        vault.sync_down()

            except Exception as err:
                logger.error("")
                logger.debug(traceback.format_exc())
                logger.error(f"{err}.")
                return
        else:
            logger.error("")
            logger.error(f"Requires either the --all or --config-record-uid parameters.")
            logger.info("")
            PAMActionSaasUpdateCommand.parser.print_help()
