#!/usr/bin/env python3
"""SDK Example: Compliance using Keeper SDK.

This example demonstrates how to generate compliance reports using the Keeper SDK directly.
It covers:
- Default compliance report with record permissions
- Team access to shared folders report
- Summary statistics report
- Shared folder access report

Usage:
    python compliance.py

Requirements:
    - keepersdk package installed
    - Valid Keeper enterprise admin account
"""

import getpass
import sqlite3
import sys
import traceback

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage, compliance
from keepersdk.errors import KeeperApiError
from keepersdk.constants import KEEPER_PUBLIC_HOSTS


TABLE_WIDTH = 140


def login():
    """Handle login with server selection, authentication, and MFA."""
    config = configuration.JsonConfigurationStorage()
    
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


def print_default_report(entries):
    """Print default compliance report."""
    print("\n" + "=" * TABLE_WIDTH)
    print("DEFAULT COMPLIANCE REPORT")
    print("=" * TABLE_WIDTH)
    print(f"{'Record UID':<22} {'Title':<25} {'Type':<15} {'Username':<30} {'Permissions':<15}")
    print("-" * TABLE_WIDTH)
    
    for entry in entries:
        print(f"{entry.record_uid:<22} {entry.title[:24]:<25} {entry.record_type[:14]:<15} "
              f"{entry.username[:29]:<30} {entry.permissions:<15}")
    
    print("=" * TABLE_WIDTH)
    print(f"\nTotal entries: {len(entries)}")


def print_team_report(entries):
    """Print team access report."""
    print("\n" + "=" * TABLE_WIDTH)
    print("TEAM ACCESS REPORT")
    print("=" * TABLE_WIDTH)
    print(f"{'Team Name':<30} {'Shared Folder':<35} {'Permissions':<20} {'Records':<10}")
    print("-" * TABLE_WIDTH)
    
    for entry in entries:
        print(f"{entry.team_name[:29]:<30} {entry.shared_folder_name[:34]:<35} "
              f"{entry.permissions[:19]:<20} {entry.records:<10}")
    
    print("=" * TABLE_WIDTH)
    print(f"\nTotal entries: {len(entries)}")


def print_summary_report(entries):
    """Print summary report."""
    print("\n" + "=" * TABLE_WIDTH)
    print("SUMMARY REPORT")
    print("=" * TABLE_WIDTH)
    print(f"{'Email':<40} {'Total Items':<15} {'Total Owned':<15} {'Active':<10} {'Deleted':<10}")
    print("-" * TABLE_WIDTH)
    
    for entry in entries:
        print(f"{entry.email[:39]:<40} {entry.total_items:<15} {entry.total_owned:<15} "
              f"{entry.active_owned:<10} {entry.deleted_owned:<10}")
    
    print("=" * TABLE_WIDTH)


def print_shared_folder_report(entries):
    """Print shared folder report."""
    print("\n" + "=" * TABLE_WIDTH)
    print("SHARED FOLDER ACCESS REPORT")
    print("=" * TABLE_WIDTH)
    print(f"{'Shared Folder UID':<30} {'Teams':<20} {'Records':<10} {'Users':<10}")
    print("-" * TABLE_WIDTH)
    
    for entry in entries:
        team_count = len(entry.team_uid) if entry.team_uid else 0
        record_count = len(entry.record_uid) if entry.record_uid else 0
        user_count = len(entry.email) if entry.email else 0
        print(f"{entry.shared_folder_uid[:29]:<30} {team_count:<20} {record_count:<10} {user_count:<10}")
    
    print("=" * TABLE_WIDTH)
    print(f"\nTotal shared folders: {len(entries)}")


def run_default_compliance_report(enterprise, auth):
    """Run default compliance report."""
    print("\n\nGenerating default compliance report...")
    
    config = compliance.ComplianceReportConfig()
    generator = compliance.ComplianceReportGenerator(enterprise.enterprise_data, auth, config)
    
    entries = generator.generate_default_report()
    print_default_report(entries[:20])  # Show first 20 entries
    
    if len(entries) > 20:
        print(f"\n(Showing 20 of {len(entries)} total entries)")


def run_team_report(enterprise, auth):
    """Run team access report."""
    print("\n\nGenerating team access report...")
    
    config = compliance.ComplianceReportConfig(shared=True)
    generator = compliance.ComplianceReportGenerator(enterprise.enterprise_data, auth, config)
    
    entries = generator.generate_team_report()
    print_team_report(entries)


def run_summary_report(enterprise, auth):
    """Run summary report."""
    print("\n\nGenerating summary report...")
    
    config = compliance.ComplianceReportConfig()
    generator = compliance.ComplianceReportGenerator(enterprise.enterprise_data, auth, config)
    
    entries = generator.generate_summary_report()
    print_summary_report(entries)


def run_shared_folder_report(enterprise, auth):
    """Run shared folder report."""
    print("\n\nGenerating shared folder report...")
    
    config = compliance.ComplianceReportConfig(shared=True)
    generator = compliance.ComplianceReportGenerator(enterprise.enterprise_data, auth, config)
    
    entries = generator.generate_shared_folder_report()
    print_shared_folder_report(entries[:20])  # Show first 20 entries
    
    if len(entries) > 20:
        print(f"\n(Showing 20 of {len(entries)} total shared folders)")


def generate_compliance_reports(keeper_auth_context: keeper_auth.KeeperAuth):
    """Generate various compliance reports."""
    if not keeper_auth_context.auth_context.is_enterprise_admin:
        print("ERROR: This operation requires enterprise admin privileges.")
        keeper_auth_context.close()
        return
    
    enterprise = None
    try:
        conn = sqlite3.Connection('file::memory:', uri=True)
        enterprise_id = keeper_auth_context.auth_context.enterprise_id or 0
        enterprise_storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(lambda: conn, enterprise_id)
        enterprise = enterprise_loader.EnterpriseLoader(keeper_auth_context, enterprise_storage)
        
        print("\nLoading enterprise data...")
        
        # Run all reports
        run_default_compliance_report(enterprise, keeper_auth_context)
        run_team_report(enterprise, keeper_auth_context)
        run_summary_report(enterprise, keeper_auth_context)
        run_shared_folder_report(enterprise, keeper_auth_context)
        
    except KeeperApiError as e:
        print(f"\nAPI Error: {e}")
    except Exception as e:
        print(f"\nError generating compliance reports: {e}")
        traceback.print_exc()
    finally:
        if enterprise:
            enterprise.close()
        keeper_auth_context.close()


def main():
    """Main entry point for the compliance report script."""
    print("=" * 80)
    print("Keeper Enterprise Compliance Report Generator")
    print("=" * 80)
    
    keeper_auth_context = login()
    
    if keeper_auth_context:
        generate_compliance_reports(keeper_auth_context)
    else:
        print("Login failed. Unable to generate compliance reports.")


if __name__ == "__main__":
    main()
