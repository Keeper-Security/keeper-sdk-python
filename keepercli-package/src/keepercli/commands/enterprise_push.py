import argparse
import json
import logging
import os

from keepersdk.enterprise import enterprise_push

from . import base
from .. import api
from ..params import KeeperParams

logger = api.get_logger()


ENTERPRISE_PUSH_DESCRIPTION = """
"enterprise-push" command uses Keeper JSON record import format.
https://docs.keeper.io/secrets-manager/commander-cli/import-and-export-commands/json-import

To create template records use the Web Vault or any other Keeper client.
1. Create an empty folder for storing templates. e.g. "Templates"
2. Create records in that folder
3. export the folder as JSON
My Vault> export --format=json --folder=Templates templates.json
4. Optional: edit JSON file to delete the following properties:
   "uid", "schema", "folders" not used by "enterprise-push" command


The template JSON file should be either array of records or
an object that contains property "records" of array of records

Template record file examples:
1.   Array of records
[
    {
        "title": "Record For ${user_name}",
        "login": "${user_email}",
        "password": "${generate_password}",
        "login_url": "",
        "notes": "",
        "custom_fields": {
            "key1": "value1",
            "key2": "value2"
        }
    }
]

2. Object that holds "records" property
{
    "records": [
        {
            "title": "Record For ${user_name}",
        }
    ]
}


Supported template parameters:

    ${user_email}            User email address
    ${generate_password}     Generate random password
    ${user_name}             User name
"""


def load_template_records_from_file(file_path: str) -> list:
    """Load and validate template records from a JSON file.

    Accepts either a JSON array of records or an object with a "records" array.
    Raises CommandError if the file is missing, invalid, or contains no templates.
    """
    path = os.path.abspath(os.path.expanduser(file_path))
    if not os.path.isfile(path):
        raise base.CommandError(f"File {file_path} does not exist")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and "records" in data:
        records = data["records"]
    elif isinstance(data, list):
        records = data
    else:
        records = None

    if not isinstance(records, list) or len(records) == 0:
        raise base.CommandError(f"File {file_path} does not contain record templates")

    return records


class EnterprisePushCommand(base.ArgparseCommand):
    """CLI command: populate user vaults with template records (by user or team)."""

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog="enterprise-push",
            description="Populate user's vault with default records",
        )
        EnterprisePushCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--syntax-help",
            dest="syntax_help",
            action="store_true",
            help="Display help on file format and template parameters.",
        )
        parser.add_argument(
            "--team",
            dest="team",
            action="append",
            help="Team name or team UID. Records will be assigned to all users in the team.",
        )
        parser.add_argument(
            "--email",
            dest="user",
            action="append",
            help="User email or User ID. Records will be assigned to the user.",
        )
        parser.add_argument(
            "file",
            nargs="?",
            type=str,
            action="store",
            help="File name in JSON format that contains template records.",
        )

    def execute(self, context: KeeperParams, **kwargs) -> None:
        if kwargs.get("syntax_help"):
            logging.info(ENTERPRISE_PUSH_DESCRIPTION)
            return

        base.require_login(context)
        base.require_enterprise_admin(context)

        file_arg = kwargs.get("file") or ""
        if not file_arg:
            raise base.CommandError("The template file name argument is required")

        template_records = load_template_records_from_file(file_arg)
        user_ids = kwargs.get("user") or []
        team_ids = kwargs.get("team") or []

        enterprise_push.EnterprisePush.push_enterprise_records(
            context.enterprise_data,
            context.auth,
            context.vault,
            user_ids,
            team_ids,
            template_records,
        )
