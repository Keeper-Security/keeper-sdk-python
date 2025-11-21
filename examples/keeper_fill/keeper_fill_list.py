import sys
import os
import json

from keepersdk.vault import vault_online

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../keepercli-package/src'))

from keepercli.commands.keeper_fill import _KeeperFillMixin
from keepercli.params import KeeperParams
from keepercli.login import LoginFlow


SUPPORTED_RECORD_VERSIONS = (2, 3)


def create_keeper_params() -> KeeperParams:
    config_file = os.path.join(os.path.expanduser('~'), '.keeper', 'config.json')
    
    if not os.path.exists(config_file):
        raise FileNotFoundError(f'Config file {config_file} not found. Please run "keeper login" first.')
    
    with open(config_file, 'r') as f:
        config_data = json.load(f)
    
    username = config_data.get('user', config_data.get('username'))
    password = config_data.get('password', '')
    
    if not username:
        raise ValueError('Username not found in config file')
    
    params = KeeperParams(config_filename=config_file, config=config_data)
    params.username = username
    if password:
        params.password = password
    
    logged_in = LoginFlow.login(params, username=username, password=password or None, resume_session=bool(username))
    
    if not logged_in:
        raise Exception('Failed to authenticate with Keeper')
    
    return params


def list_keeper_fill_settings(params: KeeperParams):
    print("\n" + "="*80)
    print("KeeperFill Settings Report")
    print("="*80)
    print(f"{'Title':<30} {'URL':<35} {'Auto Fill':<12} {'Auto Submit':<12}")
    print("-"*80)
    
    vault_data = params.vault.vault_data
    record_count = 0
    
    for record_info in vault_data.records():
        if record_info.version not in SUPPORTED_RECORD_VERSIONS:
            continue
        
        try:
            record = vault_data.load_record(record_info.record_uid)
            if not record:
                continue
            
            url = _KeeperFillMixin.get_record_url(record)
            if not url:
                continue
            
            kf_data = _KeeperFillMixin.get_keeper_fill_data(params, record_info.record_uid)
            
            auto_fill_mode = None
            if kf_data:
                auto_fill_mode = _KeeperFillMixin._normalize_auto_fill_for_display(
                    kf_data.get('auto_fill_mode')
                )
            
            auto_submit = kf_data.get('ext_auto_submit') if kf_data else None
            
            auto_fill_display = 'True' if auto_fill_mode is True else ('False' if auto_fill_mode is False else '-')
            auto_submit_display = 'True' if auto_submit is True else ('False' if auto_submit is False else '-')
            
            title = _KeeperFillMixin._truncate_text(record.title, 30)
            url_display = _KeeperFillMixin._format_url_for_display(url, verbose=False)
            
            print(f"{title:<30} {url_display:<35} {auto_fill_display:<12} {auto_submit_display:<12}")
            record_count += 1
            
        except Exception as e:
            print(f"Error processing record {record_info.record_uid}: {e}")
            continue
    
    print("-"*80)
    print(f"Total records with URLs: {record_count}")
    print("="*80 + "\n")


def main():
    try:
        params = create_keeper_params()
        list_keeper_fill_settings(params)
        return 0
        
    except Exception as e:
        print(f"\n✗ Error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
