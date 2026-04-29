
import abc
import json

from keepersdk import crypto, utils


class GatewayAction(metaclass=abc.ABCMeta):

    def __init__(self, action, is_scheduled, gateway_destination=None, inputs=None, conversation_id=None, message_id=None):
        self.action = action
        self.is_scheduled = is_scheduled
        self.gateway_destination = gateway_destination
        self.inputs = inputs
        self.conversationId = conversation_id
        self.messageId = message_id

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)

    @staticmethod
    def generate_conversation_id(is_bytes=False):
        message_id_bytes = crypto.get_random_bytes(16)
        if is_bytes:
            return message_id_bytes
        else:
            message_id = utils.base64_url_encode(message_id_bytes)
            return message_id

    @staticmethod
    def conversation_id_to_message_id(conversation_id):
        """Convert conversationId to messageId format (replace + with -, / with _)"""
        if conversation_id:
            return conversation_id.rstrip('=').replace('+', '-').replace('/', '_')
        return None


class GatewayActionRotateInputs:

    def __init__(self, record_uid, configuration_uid, pwd_complexity_encrypted, resource_uid=None):
        self.recordUid = record_uid
        self.configurationUid = configuration_uid
        self.pwdComplexity = pwd_complexity_encrypted
        self.resourceRef = resource_uid

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionRotate(GatewayAction):

    def __init__(self, inputs: GatewayActionRotateInputs, conversation_id=None, gateway_destination=None):
        super().__init__('rotate', inputs=inputs, conversation_id=conversation_id,
                         gateway_destination=gateway_destination, is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionJobInfoInputs:

    def __init__(self, job_id):
        self.jobId = job_id

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionJobInfo(GatewayAction):

    def __init__(self, inputs: GatewayActionJobInfoInputs, conversation_id=None):
        super().__init__('job-info', inputs=inputs, conversation_id=conversation_id, is_scheduled=False)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionDiscoverJobStartInputs:

    def __init__(self, configuration_uid, user_map, shared_folder_uid, resource_uid=None, languages=None,
                 # Settings
                 include_machine_dir_users=False,
                 include_azure_aadds=False,
                 skip_rules=False,
                 skip_machines=False,
                 skip_databases=False,
                 skip_directories=False,
                 skip_cloud_users=False,
                 credentials=None):
        if languages is None:
            languages = ["en_US"]
        self.configurationUid = configuration_uid
        self.resourceUid = resource_uid
        self.userMap = user_map
        self.sharedFolderUid = shared_folder_uid
        self.languages = languages
        self.includeMachineDirUsers = include_machine_dir_users
        self.includeAzureAadds = include_azure_aadds
        self.skipRules = skip_rules
        self.skipMachines = skip_machines
        self.skipDatabases = skip_databases
        self.skipDirectories = skip_directories
        self.skipCloudUsers = skip_cloud_users

        if credentials is None:
            credentials = []
        self.credentials = credentials

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionDiscoverJobStart(GatewayAction):

    def __init__(self, inputs: GatewayActionDiscoverJobStartInputs, conversation_id=None):
        super().__init__('discover-job-start', inputs=inputs, conversation_id=conversation_id, is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionDiscoverJobRemoveInputs:

    def __init__(self, configuration_uid, job_id):
        self.configurationUid = configuration_uid
        self.jobId = job_id

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)

class GatewayActionDiscoverJobRemove(GatewayAction):

    def __init__(self, inputs: GatewayActionDiscoverJobRemoveInputs, conversation_id=None):
        super().__init__('discover-job-remove', inputs=inputs, conversation_id=conversation_id, is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionDiscoverRuleValidateInputs:

    def __init__(self, configuration_uid, statement):
        self.configurationUid = configuration_uid
        self.statement = statement

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionDiscoverRuleValidate(GatewayAction):

    def __init__(self, inputs: GatewayActionDiscoverRuleValidateInputs, conversation_id=None):
        super().__init__('discover-rule-validate', inputs=inputs, conversation_id=conversation_id,
                         is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)

