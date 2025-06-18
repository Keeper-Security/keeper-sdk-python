from keepersdk.vault import ksm

from .. import api
from ..helpers import report_utils

logger = api.get_logger()

def print_client_device_info(client_devices: list[ksm.ClientDevice]) -> None:
    for index, client_device in enumerate(client_devices, start=1):
        client_devices_str = f"\nClient Device {index}\n" \
                                    f"=============================\n" \
                                    f'  Device Name: {client_device.name}\n' \
                                    f'  Short ID: {client_device.short_id}\n' \
                                    f'  Created On: {client_device.created_on}\n' \
                                    f'  Expires On: {client_device.expires_on}\n' \
                                    f'  First Access: {client_device.first_access}\n' \
                                    f'  Last Access: {client_device.last_access}\n' \
                                    f'  IP Lock: {client_device.ip_lock}\n' \
                                    f'  IP Address: {client_device.ip_address or "--"}'
        logger.info(client_devices_str)

def print_shared_secrets_info(shared_secrets: list[ksm.SharedSecretsInfo]) -> None:
    shares_table_fields = ['Share Type', 'UID', 'Title', 'Permissions']
    rows = [
        [secrets.type, secrets.uid, secrets.name, secrets.permissions]
        for secrets in shared_secrets
    ]
    report_utils.dump_report_data(rows, shares_table_fields, fmt='table')