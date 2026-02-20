"""
BreachWatch Report SDK Example

Usage: python breachwatch_report.py
Requirements: Enterprise admin account, BreachWatch enabled, Keeper SDK installed.
"""

import getpass
import logging
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage, breachwatch_report
from keepersdk.errors import KeeperApiError
from keepersdk.constants import KEEPER_PUBLIC_HOSTS

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

TABLE_WIDTH = 110
COL_WIDTHS = (38, 22, 14, 10, 10, 10)
BANNER_WIDTH = 60
DEFAULT_SERVER = 'keepersecurity.com'


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
            password = getpass.getpass('Enter password: ')
            login_auth_context.login_step.verify_password(password)
        elif isinstance(login_auth_context.login_step, login_auth.LoginStepTwoFactor):
            channel = login_auth_context.login_step.get_channels()[0]
            code = getpass.getpass(f'Enter 2FA code for {channel.channel_name}: ')
            login_auth_context.login_step.send_code(channel.channel_uid, code)
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


def format_row(values, widths=COL_WIDTHS):
    formatted = []
    for i, val in enumerate(values):
        if i >= len(widths):
            break
        width = widths[i]
        text = str(val if val is not None else '')[: max(1, width - 1)]
        formatted.append(f"{text:<{width}}")
    return ' '.join(formatted)


def log_breachwatch_report(result: breachwatch_report.BreachWatchReportResult):
    title = result.report_title if not result.has_errors else result.error_title.split('\n')[0]
    logger.info("\n" + "=" * TABLE_WIDTH)
    logger.info(title)
    logger.info("=" * TABLE_WIDTH)

    if result.has_errors:
        headers = [h.replace('_', ' ').title() for h in result.error_headers]
        logger.info(format_row(headers))
        logger.info("-" * TABLE_WIDTH)
        for row in result.error_rows:
            logger.info(format_row(row))
        logger.info("=" * TABLE_WIDTH)
        logger.info("Note: %s", result.fix_instructions)
        return

    headers = [h.replace('_', ' ').title() for h in result.headers]
    logger.info(format_row(headers))
    logger.info("-" * TABLE_WIDTH)
    for row in result.rows:
        logger.info(format_row(row))
    logger.info("=" * TABLE_WIDTH)
    logger.info("Total Users: %d", len(result.rows))

    if result.rows:
        total_at_risk = sum(r[3] for r in result.rows if len(r) > 3)
        total_passed = sum(r[4] for r in result.rows if len(r) > 4)
        total_ignored = sum(r[5] for r in result.rows if len(r) > 5)
        logger.info("Summary: At Risk=%d, Passed=%d, Ignored=%d", total_at_risk, total_passed, total_ignored)
    if result.saved_count:
        logger.info("Saved %d updated security report(s) to the server.", result.saved_count)


def generate_breachwatch_report(keeper_auth_context: keeper_auth.KeeperAuth):
    if not keeper_auth_context.auth_context.is_enterprise_admin:
        logger.error("This operation requires enterprise admin privileges.")
        keeper_auth_context.close()
        return
    if not keeper_auth_context.auth_context.license.get('breachWatchEnabled'):
        logger.error("BreachWatch is not enabled for this account.")
        keeper_auth_context.close()
        return

    enterprise = None
    try:
        conn = sqlite3.Connection('file::memory:', uri=True)
        enterprise_id = keeper_auth_context.auth_context.enterprise_id or 0
        enterprise_storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(
            lambda: conn, enterprise_id
        )
        enterprise = enterprise_loader.EnterpriseLoader(
            keeper_auth_context, enterprise_storage
        )
        logger.info("Loading enterprise data...")
        enterprise.load()
        logger.info("Generating BreachWatch report...")
        result = breachwatch_report.run_breachwatch_report(
            enterprise.enterprise_data,
            keeper_auth_context,
            node_ids=None,
            save_report=True,
        )
        log_breachwatch_report(result)
    except KeeperApiError as e:
        logger.error("API Error: %s", e)
    except Exception:
        logger.exception("Error generating BreachWatch report")
    finally:
        if enterprise:
            enterprise.close()
        keeper_auth_context.close()


def main():
    logger.info("=" * BANNER_WIDTH)
    logger.info("Keeper BreachWatch Report (SDK Example)")
    logger.info("=" * BANNER_WIDTH)
    logger.info("Generates a BreachWatch security audit report for all enterprise users.\n")

    keeper_auth_context = login()
    if keeper_auth_context:
        generate_breachwatch_report(keeper_auth_context)
    else:
        logger.error("Login failed. Unable to generate BreachWatch report.")


if __name__ == "__main__":
    main()
