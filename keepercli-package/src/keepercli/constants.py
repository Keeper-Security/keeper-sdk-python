import sys
from datetime import timedelta
from typing import Optional
from urllib.parse import urlparse

from keepersdk.constants import KEEPER_PUBLIC_HOSTS

EMAIL_PATTERN = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"

week_days = ('SUNDAY', 'MONDAY', 'TUESDAY', 'WEDNESDAY','THURSDAY', 'FRIDAY', 'SATURDAY')
occurrences = ('FIRST', 'SECOND', 'THIRD', 'FOURTH', 'LAST')
months = ('JANUARY', 'FEBRUARY', 'MARCH', 'APRIL', 'MAY', 'JUNE', 'JULY', 'AUGUST', 'SEPTEMBER', 'OCTOBER',
          'NOVEMBER', 'DECEMBER')


def get_cron_week_day(text: Optional[str]) -> Optional[int]:
    if isinstance(text, str):
        try:
            return week_days.index(text.upper())
        except Exception:
            pass


def get_cron_occurrence(text: Optional[str]) -> Optional[int]:
    if isinstance(text, str):
        try:
            idx = occurrences.index(text.upper())
            idx += 1
            if idx > 4:
                idx = 4
            return idx
        except Exception:
            pass


def get_cron_month(text: Optional[str]) -> Optional[int]:
    if isinstance(text, str):
        try:
            m = months.index(text.upper())
            return m + 1
        except Exception:
            pass


def get_cron_month_day(text: Optional[str]) -> Optional[int]:
    if isinstance(text, str) and text.isnumeric():
        day = int(text)
        if day < 1:
            day = 1
        elif day > 28:
            day = 28
        return day


# OS dependent constants
if sys.platform.startswith('win'):
    OS_WHICH_CMD = 'where'
else:
    OS_WHICH_CMD = 'which'


def get_abbrev_by_host(host: str) -> Optional[str]:
    # Return abbreviation of the Keeper's public host

    if host.startswith('https:'):
        host = urlparse(host).netloc    # https://keepersecurity.com/api/v2/ --> keepersecurity.com

    keys = [k for k, v in KEEPER_PUBLIC_HOSTS.items() if v == host]
    if keys:
        return keys[0]
    return None


# Messages
# Account Transfer
ACCOUNT_TRANSFER_MSG = """
Your Keeper administrator has enabled the ability to transfer your vault records
in accordance with company operating procedures and policies.
Please acknowledge this change in account settings by typing 'Accept'.
If you do not accept this change by {0}, you will be locked out of your account.
"""

PBKDF2_ITERATIONS = 1_000_000

# Timeout constants
# Set to default value by using timedelta of 0
TIMEOUT_DEFAULT = timedelta(0)
TIMEOUT_MIN = timedelta(minutes=1)
TIMEOUT_DEFAULT_UNIT = 'minutes'
TIMEOUT_ALLOWED_UNITS = ('days', 'hours', 'minutes')

LAST_RECORD_UID = 'last_record_uid'
LAST_SHARED_FOLDER_UID = 'last_shared_folder_uid'
LAST_FOLDER_UID = 'last_folder_uid'
LAST_TEAM_UID = 'last_team_uid'
