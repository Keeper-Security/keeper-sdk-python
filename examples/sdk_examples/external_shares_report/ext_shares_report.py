"""External Shares Report SDK Example. Usage: python ext_shares_report.py"""

import getpass
import logging
import os
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.constants import KEEPER_PUBLIC_HOSTS
from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage, compliance
from keepersdk.errors import KeeperApiError
from keepersdk.plugins.sox import compliance_storage as cs

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

TABLE_WIDTH = 120
COL_WIDTHS = (22, 22, 15, 32, 18)
DEFAULT_SERVER = 'keepersecurity.com'
DEFAULT_CONFIG_PATH = '~/.keeper/config.json'
CACHE_MAX_AGE_DAYS = 1
REPORT_TITLE = 'External Shares Report'


def login():
    config = configuration.JsonConfigurationStorage()

    if not config.get().last_server:
        logger.info("Available server options:")
        for region, host in KEEPER_PUBLIC_HOSTS.items():
            logger.info(f"  {region}: {host}")
        server = input(f'Enter server (default: {DEFAULT_SERVER}): ').strip() or DEFAULT_SERVER
        config.get().last_server = server
    else:
        server = config.get().last_server

    keeper_endpoint = endpoint.KeeperEndpoint(config, server)
    login_auth_context = login_auth.LoginAuth(keeper_endpoint)
    username = config.get().last_login or input('Enter username: ')

    login_auth_context.resume_session = True
    login_auth_context.login(username)

    logged_in_with_persistent = True
    while not login_auth_context.login_step.is_final():
        if isinstance(login_auth_context.login_step, login_auth.LoginStepDeviceApproval):
            login_auth_context.login_step.send_push(login_auth.DeviceApprovalChannel.KeeperPush)
            logger.info("Device approval request sent. Approve this device and press Enter to continue.")
            input()
        elif isinstance(login_auth_context.login_step, login_auth.LoginStepPassword):
            login_auth_context.login_step.verify_password(getpass.getpass('Enter password: '))
        elif isinstance(login_auth_context.login_step, login_auth.LoginStepTwoFactor):
            channel = login_auth_context.login_step.get_channels()[0]
            login_auth_context.login_step.send_code(
                channel.channel_uid,
                getpass.getpass(f'Enter 2FA code for {channel.channel_name}: ')
            )
        else:
            raise NotImplementedError(
                f"Unsupported login step: {type(login_auth_context.login_step).__name__}"
            )
        logged_in_with_persistent = False

    if logged_in_with_persistent:
        logger.info("Successfully logged in with persistent login")

    if isinstance(login_auth_context.login_step, login_auth.LoginStepConnected):
        return login_auth_context.login_step.take_keeper_auth()
    return None


def get_compliance_storage(config_path: str, enterprise_id: int):
    db_name = cs.get_compliance_database_name(config_path, enterprise_id)
    storage = cs.SqliteComplianceStorage(lambda: cs.get_cached_connection(db_name), enterprise_id)
    storage.database_name = db_name
    storage.close_connection = lambda: cs.close_cached_connection(db_name)
    return storage


def format_row(values, widths=COL_WIDTHS):
    formatted = []
    for i, val in enumerate(values):
        if i >= len(widths):
            break
        text = str(val if val is not None else '')[: max(1, widths[i] - 1)]
        formatted.append(f"{text:<{widths[i]}}")
    return ' '.join(formatted)


def log_report(rows, headers):
    logger.info("\n" + "=" * TABLE_WIDTH)
    logger.info(REPORT_TITLE)
    logger.info("=" * TABLE_WIDTH)

    display_headers = [h.replace('_', ' ').title() for h in headers]
    logger.info(format_row(display_headers))
    logger.info("-" * TABLE_WIDTH)

    for row in rows:
        logger.info(format_row(row))

    logger.info("=" * TABLE_WIDTH)
    logger.info("Total: %d", len(rows))


def run_external_shares_report(
    keeper_auth_context: keeper_auth.KeeperAuth,
    share_type: str = 'all',
    refresh_data: bool = False,
):
    if not keeper_auth_context.auth_context.is_enterprise_admin:
        logger.error("This operation requires enterprise admin privileges.")
        keeper_auth_context.close()
        return

    enterprise = None
    compliance_storage = None

    try:
        conn = sqlite3.Connection('file::memory:', uri=True)
        enterprise_id = keeper_auth_context.auth_context.enterprise_id or 0
        enterprise_storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(lambda: conn, enterprise_id)
        enterprise = enterprise_loader.EnterpriseLoader(keeper_auth_context, enterprise_storage)

        config_path = os.path.expanduser(DEFAULT_CONFIG_PATH)
        compliance_storage = get_compliance_storage(config_path, enterprise_id)

        logger.info("Loading compliance data%s...", " (refresh)" if refresh_data else " (from cache when available)")

        def progress_callback(msg):
            if msg:
                logger.info(msg)

        config = compliance.ComplianceReportConfig(
            shared=True,
            rebuild=refresh_data,
            no_rebuild=not refresh_data,
            external_share_type=share_type,
            cache_max_age_days=CACHE_MAX_AGE_DAYS,
        )
        generator = compliance.ComplianceReportGenerator(
            enterprise.enterprise_data,
            keeper_auth_context,
            config,
            compliance_storage=compliance_storage,
            progress_callback=progress_callback,
        )

        rows = list(generator.generate_report_rows(compliance.REPORT_TYPE_EXTERNAL_SHARES))
        headers = compliance.ComplianceReportGenerator.get_headers(compliance.REPORT_TYPE_EXTERNAL_SHARES)
        log_report(rows, headers)

    except KeeperApiError as e:
        logger.error("API Error: %s", e)
    except Exception as e:
        logger.exception("Error: %s", e)
    finally:
        if compliance_storage and hasattr(compliance_storage, 'close_connection') and compliance_storage.close_connection:
            compliance_storage.close_connection()
        if enterprise:
            enterprise.close()
        keeper_auth_context.close()


def main():
    logger.info("=" * 60)
    logger.info("Keeper External Shares Report (SDK Example)")
    logger.info("=" * 60 + "\n")

    keeper_auth_context = login()
    if not keeper_auth_context:
        logger.error("Login failed.")
        return

    run_external_shares_report(
        keeper_auth_context,
        share_type='all',
        refresh_data=False,
    )


if __name__ == "__main__":
    main()
