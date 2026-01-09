"""
Security Audit Report SDK Example

This example demonstrates how to use the Keeper SDK to generate a security audit
report for enterprise users. The report includes password strength analysis,
reused passwords, and security scores for all users in the enterprise.

Usage:
    python security_audit_report.py

Requirements:
    - Enterprise admin account
    - Keeper SDK installed
"""

import getpass
import sqlite3
import traceback

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage, security_audit_report
from keepersdk.errors import KeeperApiError
from keepersdk.constants import KEEPER_PUBLIC_HOSTS


# Table formatting constants
TABLE_WIDTH = 140
COL_WIDTHS = (35, 20, 8, 8, 8, 8, 8, 8, 8, 10, 6, 20)


def login():
    """
    Handle the login process including server selection, authentication,
    and multi-factor authentication steps.
    
    Returns:
        keeper_auth.KeeperAuth: The authenticated Keeper context, or None if login fails.
    """
    config = configuration.JsonConfigurationStorage()
    
    # Server selection
    if not config.get().last_server:
        print("Available server options:")
        for region, host in KEEPER_PUBLIC_HOSTS.items():
            print(f"  {region}: {host}")
        server = input('Enter server (default: keepersecurity.com): ').strip() or 'keepersecurity.com'
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
            print("Device approval request sent. Approve this device and press Enter to continue.")
            input()
        elif isinstance(login_auth_context.login_step, login_auth.LoginStepPassword):
            password = getpass.getpass('Enter password: ')
            login_auth_context.login_step.verify_password(password)
        elif isinstance(login_auth_context.login_step, login_auth.LoginStepTwoFactor):
            channel = login_auth_context.login_step.get_channels()[0]
            code = getpass.getpass(f'Enter 2FA code for {channel.channel_name}: ')
            login_auth_context.login_step.send_code(channel.channel_uid, code)
        else:
            raise NotImplementedError(f"Unsupported login step: {type(login_auth_context.login_step).__name__}")
        logged_in_with_persistent = False
    
    if logged_in_with_persistent:
        print("Successfully logged in with persistent login")
    
    if isinstance(login_auth_context.login_step, login_auth.LoginStepConnected):
        return login_auth_context.login_step.take_keeper_auth()
    
    return None


def format_row(values, widths=COL_WIDTHS):
    """
    Format a row of values according to column widths.
    
    Args:
        values: List of values to format
        widths: Tuple of column widths
        
    Returns:
        str: Formatted row string
    """
    formatted = []
    for i, val in enumerate(values):
        if i >= len(widths):
            break
        width = widths[i]
        text = str(val if val is not None else '')[:width - 1]
        formatted.append(f"{text:<{width}}")
    return ' '.join(formatted)


def print_report(entries):
    """
    Print the security audit report in table format.
    
    Args:
        entries: List of SecurityAuditEntry objects
    """
    print("\n" + "=" * TABLE_WIDTH)
    print("ENTERPRISE SECURITY AUDIT REPORT")
    print("=" * TABLE_WIDTH)
    
    headers = ['Email', 'Name', 'Weak', 'Fair', 'Medium', 'Strong', 'Reused', 'Unique', 'Score', 'Pending', '2FA', 'Node']
    print(format_row(headers))
    print("-" * TABLE_WIDTH)
    
    for entry in entries:
        row = [
            entry.email,
            entry.username,
            entry.weak,
            entry.fair,
            entry.medium,
            entry.strong,
            entry.reused,
            entry.unique,
            f"{entry.security_score}%",
            'Yes' if entry.sync_pending else '',
            'On' if entry.two_factor_enabled else 'Off',
            entry.node_path
        ]
        print(format_row(row))
    
    print("=" * TABLE_WIDTH)
    print(f"\nTotal Users: {len(entries)}")

    if entries:
        avg_score = sum(e.security_score for e in entries) / len(entries)
        total_weak = sum(e.weak for e in entries)
        total_strong = sum(e.strong for e in entries)
        total_reused = sum(e.reused for e in entries)
        twofa_enabled = sum(1 for e in entries if e.two_factor_enabled)
        
        print(f"\nSummary Statistics:")
        print(f"  Average Security Score: {avg_score:.1f}%")
        print(f"  Total Weak Passwords: {total_weak}")
        print(f"  Total Strong Passwords: {total_strong}")
        print(f"  Total Reused Passwords: {total_reused}")
        print(f"  Users with 2FA Enabled: {twofa_enabled} ({100*twofa_enabled/len(entries):.1f}%)")


def print_errors(errors):
    """
    Print any errors encountered during report generation.
    
    Args:
        errors: List of SecurityAuditError objects
    """
    if not errors:
        return
    
    print("\n" + "!" * 60)
    print("ERRORS ENCOUNTERED")
    print("!" * 60)
    
    for error in errors:
        print(f"  {error.email}: {error.error_message}")
    
    print("!" * 60)


def generate_security_audit_report(keeper_auth_context: keeper_auth.KeeperAuth):
    """
    Generate enterprise security audit report.
    
    This function loads enterprise data, fetches security report data for all users,
    and displays the results in a formatted table.
    
    Args:
        keeper_auth_context: The authenticated Keeper context with enterprise admin privileges.
    """
    if not keeper_auth_context.auth_context.is_enterprise_admin:
        print("ERROR: This operation requires enterprise admin privileges.")
        print("The current user is not an enterprise administrator.")
        print("\nTo use security audit report features, you need:")
        print("  1. An enterprise account")
        print("  2. Enterprise administrator role")
        keeper_auth_context.close()
        return
    
    enterprise = None
    try:
        conn = sqlite3.Connection('file::memory:', uri=True)
        enterprise_id = keeper_auth_context.auth_context.enterprise_id or 0
        enterprise_storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(lambda: conn, enterprise_id)
        enterprise = enterprise_loader.EnterpriseLoader(keeper_auth_context, enterprise_storage)
        
        print("\nLoading enterprise data...")

        config = security_audit_report.SecurityAuditConfig(
            node_ids=None,
            show_breachwatch=False,
            show_updated=False,
            save_report=False,
            score_type='default'
        )
        
        print("Generating security audit report...")
        
        generator = security_audit_report.SecurityAuditReportGenerator(
            enterprise.enterprise_data,
            keeper_auth_context,
            config
        )

        entries = generator.generate_report()

        if generator.has_errors:
            print_errors(generator.errors)

        print_report(entries)
        
    except KeeperApiError as e:
        print(f"\nAPI Error: {e}")
    except Exception as e:
        print(f"\nError generating security audit report: {e}")
        traceback.print_exc()
    finally:
        if enterprise:
            enterprise.close()
        keeper_auth_context.close()


def main():
    """
    Main entry point for the security audit report script.
    Performs login and generates the security audit report.
    """
    print("=" * 60)
    print("Keeper Enterprise Security Audit Report Generator")
    print("=" * 60)
    print("\nThis tool generates a security audit report for all enterprise users,")
    print("including password strength analysis and security scores.\n")
    
    keeper_auth_context = login()
    
    if keeper_auth_context:
        generate_security_audit_report(keeper_auth_context)
    else:
        print("Login failed. Unable to generate security audit report.")


if __name__ == "__main__":
    main()

