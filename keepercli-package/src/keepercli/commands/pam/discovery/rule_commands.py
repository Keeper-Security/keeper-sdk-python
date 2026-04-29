import argparse
from typing import List

from ....params import KeeperParams
from ....helpers import router_utils
from .... import api
from .__init__ import GatewayContext, PAMGatewayActionDiscoverCommandBase
from ..pam_dto import GatewayAction, GatewayActionDiscoverRuleValidate, GatewayActionDiscoverRuleValidateInputs

from keepersdk.helpers.keeper_dag.dag_types import Statement
from keepersdk.helpers.keeper_dag.rule import Rules, ActionRuleItem, RuleItem, RuleTypeEnum, RuleActionEnum
from keepersdk.proto import pam_pb2


logger = api.get_logger()


class PAMGatewayActionDiscoverRuleListCommand(PAMGatewayActionDiscoverCommandBase):
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action discover rule list')
        PAMGatewayActionDiscoverRuleListCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                            help='Gateway name of UID.')
        parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                            action='store', help='PAM configuration UID, if gateway has multiple.')
        parser.add_argument('--search', '-s', required=False, dest='search', action='store',
                            help='Search for rules.')

    @staticmethod
    def print_rule_table(rule_list: List[RuleItem]):

        logger.info("")
        logger.info(f"{'Rule ID'.ljust(15, ' ')} "
              f"{'Name'.ljust(20, ' ')} "
              f"{'Action'.ljust(6, ' ')} "
              f"{'Priority'.ljust(8, ' ')} "
              f"{'Case'.ljust(12, ' ')} "
              f"{'Added'.ljust(19, ' ')} "
              f"{'Shared Folder UID'.ljust(22, ' ')} "
              f"{'Admin UID'.ljust(22, ' ')} "
              "Rule"
              )

        logger.info(f"{''.ljust(15, '=')} "
              f"{''.ljust(20, '=')} "
              f"{''.ljust(6, '=')} "
              f"{''.ljust(8, '=')} "
              f"{''.ljust(12, '=')} "
              f"{''.ljust(19, '=')} "
              f"{''.ljust(22, '=')} "
              f"{''.ljust(22, '=')} "
              f"{''.ljust(10, '=')} ")

        for rule in rule_list:
            if rule.case_sensitive:
                ignore_case_str = "Sensitive"
            else:
                ignore_case_str = "Insensitive"

            shared_folder_uid = ""
            if rule.shared_folder_uid is not None:
                shared_folder_uid = rule.shared_folder_uid

            admin_uid = ""
            if rule.admin_uid is not None:
                admin_uid = rule.admin_uid

            name = ""
            if rule.name is not None:
                name = rule.name

            action_value = f"NONE"
            if rule.action is not None:
                action_value = rule.action.value

            logger.info(f"{rule.rule_id.ljust(14, ' ')} "
                  f"{name[:20].ljust(20, ' ')} "
                  f"{action_value.ljust(6, ' ')} "
                  f"{str(rule.priority).rjust(8, ' ')} "
                  f"{ignore_case_str.ljust(12, ' ')} "
                  f"{rule.added_ts_str.ljust(19, ' ')} "
                  f"{shared_folder_uid.ljust(22, ' ')} "
                  f"{admin_uid.ljust(22, ' ')} "
                  f"{Rules.make_action_rule_statement_str(rule.statement)}")

    def execute(self, context: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        configuration_uid = kwargs.get('configuration_uid')
        vault = context.vault
        gateway_context = GatewayContext.from_gateway(vault=vault,
                                                      gateway=gateway,
                                                      configuration_uid=configuration_uid)
        if gateway_context is None:
            logger.error(f"Could not find the gateway configuration for {gateway}.")
            return

        rules = Rules(record=gateway_context.configuration, context=context)
        rule_list = rules.rule_list(rule_type=RuleTypeEnum.ACTION,
                                    search=kwargs.get("search"))  # type: List[RuleItem]
        if len(rule_list) == 0:
            logger.info("")
            text = f"There are no rules. " \
                   f"Use 'pam action discover rule add -g {gateway_context.gateway_uid} "
            if configuration_uid:
                text += f"-c {gateway_context.configuration_uid}' "
            text += f"to create rules."
            logger.info(text)
            return

        self.print_rule_table(rule_list=rule_list)


class PAMGatewayActionDiscoverRuleAddCommand(PAMGatewayActionDiscoverCommandBase):
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action discover rule add')
        PAMGatewayActionDiscoverRuleAddCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                            help='Gateway name of UID.')
        parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                            action='store', help='PAM configuration UID, if gateway has multiple.')

        parser.add_argument('--action', '-a', required=True, choices=['add', 'ignore', 'prompt'],
                            dest='rule_action', action='store', help='Action to take if rule matches')
        parser.add_argument('--priority', '-p', required=True, dest='priority', action='store', type=int,
                            help='Rule execute priority')
        parser.add_argument('--name', '-n', required=False, dest='name', action='store', type=str,
                            help='Rule name')
        parser.add_argument('--ignore-case', required=False, dest='ignore_case', action='store_true',
                            help='Ignore value case. Rule value must be in lowercase.')
        parser.add_argument('--shared-folder-uid', required=False, dest='shared_folder_uid',
                            action='store', help='Folder to place record.')
        parser.add_argument('--admin-uid', required=False, dest='admin_uid',
                            action='store', help='Admin record UID to use for resource.')
        parser.add_argument('--statement', '-s', required=True, dest='statement', action='store',
                            help='Rule statement')

    @staticmethod
    def validate_rule_statement(context: KeeperParams, gateway_context: GatewayContext, statement: str) \
            -> List[Statement]:

        # Send rule the gateway to be validated. The rule is encrypted. It might contain sensitive information.
        action_inputs = GatewayActionDiscoverRuleValidateInputs(
            configuration_uid=gateway_context.configuration_uid,
            statement=gateway_context.encrypt_str(statement)
        )
        conversation_id = GatewayAction.generate_conversation_id()
        router_response = router_utils.router_send_action_to_gateway(
            context=context,
            gateway_action=GatewayActionDiscoverRuleValidate(
                inputs=action_inputs,
                conversation_id=conversation_id),
            message_type=pam_pb2.CMT_DISCOVERY,
            is_streaming=False,
            destination_gateway_uid_str=gateway_context.gateway_uid
        )

        data = PAMGatewayActionDiscoverCommandBase.get_response_data(router_response)

        if data is None:
            raise Exception("The router returned a failure.")
        elif data.get("success") is False:
            error = data.get("error")
            raise Exception(f"The rule does not appear valid: {error}")

        statement_struct = data.get("statementStruct")
        logger.debug(f"Rule Structure = {statement_struct}")
        if not isinstance(statement_struct, list):
            raise Exception(f"The structured rule statement is not a list.")
        ret = []
        for item in statement_struct:
            ret.append(
                Statement(
                    field=item.get("field"),
                    operator=item.get("operator"),
                    value=item.get("value")
                )
            )

        return ret

    def execute(self, context: KeeperParams, **kwargs):
        try:
            gateway_uid = kwargs.get("gateway")
            gateway_context = GatewayContext.from_gateway(vault=context.vault,
                                                          gateway=gateway_uid,
                                                          configuration_uid=kwargs.get('configuration_uid'))
            if gateway_context is None:
                logger.error(f"Could not find the gateway configuration for {gateway_uid}.")
                return

            shared_folder_uid = kwargs.get("shared_folder_uid")
            if shared_folder_uid is not None:
                shared_folder_uids = gateway_context._shared_folders if gateway_context._shared_folders is not None else []
                exists = next((x for x in shared_folder_uids if x["uid"] == shared_folder_uid), None)
                if exists is None:
                    logger.error(f"The shared folder UID {shared_folder_uid} is not part of this "
                          f"application/gateway. Valid shared folder UID are:")
                    for item in shared_folder_uids:
                        logger.error(f"* {item['uid']} - {item['name']}")
                    return

            statement = kwargs.get("statement")
            statement_struct = self.validate_rule_statement(
                context=context,
                gateway_context=gateway_context,
                statement=statement
            )

            shared_folder_uid = kwargs.get("shared_folder_uid")
            if shared_folder_uid is not None and len(shared_folder_uid) != 22:
                logger.error(f"The shared folder UID {shared_folder_uid} is not the correct length.")
                return

            admin_uid = kwargs.get("admin_uid")
            if admin_uid is not None and len(admin_uid) != 22:
                logger.error(f"The admin UID {admin_uid} is not the correct length.")
                return

            # If the rule passes its validation, then add control DAG
            rules = Rules(record=gateway_context.configuration, context=context)
            new_rule = ActionRuleItem(
                name=kwargs.get("name"),
                action=kwargs.get("rule_action"),
                priority=kwargs.get("priority"),
                case_sensitive=not kwargs.get("ignore_case", False),
                shared_folder_uid=shared_folder_uid,
                admin_uid=admin_uid,
                statement=statement_struct,
                enabled=True
            )
            rules.add_rule(new_rule)

            logger.info(f"Rule has been added")
        except Exception as err:
            logger.error(f"Rule was not added: {err}")


class PAMGatewayActionDiscoverRuleUpdateCommand(PAMGatewayActionDiscoverCommandBase):
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action discover rule update')
        PAMGatewayActionDiscoverRuleUpdateCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                            help='Gateway name of UID.')
        parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                            action='store', help='PAM configuration UID, if gateway has multiple.')
        parser.add_argument('--rule-id', '-i', required=True, dest='rule_id', action='store',
                            help='Identifier for the rule')
        parser.add_argument('--action', '-a', required=False, choices=['add', 'ignore', 'prompt'],
                            dest='rule_action', action='store', help='Update the action to take if rule matches')
        parser.add_argument('--priority', '-p', required=False, dest='priority', action='store', type=int,
                            help='Update the rule execute priority')
        parser.add_argument('--name', '-n', required=False, dest='name', action='store', type=str,
                            help='Rule name')
        parser.add_argument('--ignore-case', required=False, dest='ignore_case', action='store_true',
                            help='Update the rule to ignore case')
        parser.add_argument('--no-ignore-case', required=False, dest='ignore_case', action='store_false',
                            help='Update the rule to not ignore case')
        parser.add_argument('--shared-folder-uid', required=False, dest='shared_folder_uid',
                            action='store', help='Update the folder to place record.')
        parser.add_argument('--admin-uid', required=False, dest='admin_uid',
                            action='store', help='Admin record UID to use for resource.')
        parser.add_argument('--clear-shared-folder-uid', required=False, dest='clear_shared_folder_uid',
                            action='store_true', help='Clear shared folder UID, use default.')
        parser.add_argument('--clear-admin-uid', required=False, dest='clear_admin_uid',
                            action='store_true', help='Clear admin UID')
        parser.add_argument('--statement', '-s', required=False, dest='statement', action='store',
                            help='Update the rule statement')
        parser.add_argument('--active', required=False, dest='active', action='store_true',
                            help='Enable rule.')
        parser.add_argument('--disable', required=False, dest='active', action='store_false',
                            help='Disable rule.')
        parser.set_defaults(active=None, ignore_case=None)

    def execute(self, context: KeeperParams, **kwargs):
        gateway = kwargs.get("gateway")
        gateway_context = GatewayContext.from_gateway(vault=context.vault,
                                                      gateway=gateway,
                                                      configuration_uid=kwargs.get('configuration_uid'))
        if gateway_context is None:
            logger.error(f"Could not find the gateway configuration for {gateway}.")
            return

        try:
            rule_id = kwargs.get("rule_id")
            rules = Rules(record=gateway_context.configuration, context=context)
            rule_item = rules.get_rule_item(rule_type=RuleTypeEnum.ACTION, rule_id=rule_id)
            if rule_item is None:
                raise ValueError("Rule Id does not exist.")

            rule_action = kwargs.get("rule_action")
            if rule_action is not None:
                action = RuleActionEnum.find_enum(rule_action)
                if action is None:
                    raise ValueError(f"The action does not look correct: {rule_action}")
                rule_item.action = action

            priority = kwargs.get("priority")
            if priority is not None:
                logger.info("  * Changing the priority of the rule.")
                rule_item.priority = priority

            ignore_case = kwargs.get("ignore_case")
            if ignore_case is not None:
                if ignore_case:
                    logger.info("  * Ignore the case of text.")
                else:
                    logger.info("  * Make rule text case sensitive.")

                rule_item.case_sensitive = not ignore_case

            if kwargs.get("clear_shared_folder_uid"):
                logger.info("  * Clearing shared folder.")
                rule_item.shared_folder_uid = None
            else:
                shared_folder_uid = kwargs.get("shared_folder_uid")
                if shared_folder_uid is not None:
                    if len(shared_folder_uid) != 22:
                        logger.error(f"The shared folder UID {shared_folder_uid} is not the correct length.")
                    logger.info("  * Changing shared folder UID.")
                    rule_item.shared_folder_uid = shared_folder_uid

            if kwargs.get("clear_admin_uid"):
                logger.info("  * Clearing resource admin UID.")
                rule_item.admin_uid = None
            else:
                admin_uid = kwargs.get("admin_uid")
                if admin_uid is not None:
                    if len(admin_uid) != 22:
                        logger.error(f"The admin UID {admin_uid} is not the correct length.")
                        return
                    logger.info("  * Changing the resource admin UID.")
                    rule_item.admin_uid = admin_uid

            statement = kwargs.get("statement")
            if statement is not None:
                statement_struct = PAMGatewayActionDiscoverRuleAddCommand.validate_rule_statement(
                    context=context,
                    gateway_context=gateway_context,
                    statement=statement
                )

                logger.info("  * Changing the rule statement.")
                rule_item.statement = statement_struct

            name = kwargs.get("name")
            if name is not None:
                logger.info("  * Changing the rule name.")
                rule_item.name = name

            enabled = kwargs.get("active")
            if enabled is not None:
                if enabled:
                    logger.info("  * Enabling the rule.")
                else:
                    logger.info("  * Disabling the rule.")
                rule_item.enabled = enabled

            rules.update_rule(rule_item)
            logger.info(f"Rule has been updated")
        except Exception as err:
            logger.error(f"Rule was not updated: {err}")


class PAMGatewayActionDiscoverRuleRemoveCommand(PAMGatewayActionDiscoverCommandBase):
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam action discover rule remove')
        PAMGatewayActionDiscoverRuleRemoveCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                            help='Gateway name of UID.')
        parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                            action='store', help='PAM configuration UID, if gateway has multiple.')
        parser.add_argument('--rule-id', '-i', required=False, dest='rule_id', action='store',
                            help='Identifier for the rule')
        parser.add_argument('--remove-all', required=False, dest='remove_all', action='store_true',
                            help='Remove all the rules.')

    def execute(self, context: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        gateway_context = GatewayContext.from_gateway(vault=context.vault,
                                                        gateway=gateway,
                                                        configuration_uid=kwargs.get('configuration_uid'))
        if gateway_context is None:
            logger.error(f"Could not find the gateway configuration for {gateway}.")
            return

        rule_id = kwargs.get("rule_id")
        remove_all = kwargs.get("remove_all")

        if rule_id is None and remove_all is None:
            logger.error(f'Either --rule-id or --remove-all are required.')
            return

        try:
            rules = Rules(record=gateway_context.configuration, context=context)
            if remove_all:
                rules.remove_all(RuleTypeEnum.ACTION)
                logger.info(f"All rules removed.")
            else:

                rule_item = rules.get_rule_item(rule_type=RuleTypeEnum.ACTION, rule_id=rule_id)
                if rule_item is None:
                    raise ValueError("Rule Id does not exist.")
                rules.remove_rule(rule_item)

                logger.info(f"Rule has been removed.")
        except Exception as err:
            if remove_all:
                logger.error(f"Rules have NOT been removed: {err}")
            else:
                logger.error(f"Rule was not removed: {err}")
