import argparse
import datetime

import itertools
import json
from typing import Optional
from functools import reduce

from keepersdk.vault import vault_online, vault_utils, vault_record, storage_types
from keepersdk.proto import record_pb2
from keepersdk import utils, crypto

from . import base, enterprise_utils
from .. import api, prompt_utils
from ..params import KeeperParams
from ..helpers import timeout_utils, folder_utils, report_utils

RECORD_DETAILS_URL = 'vault/get_records_details'
SHARE_ADMIN_URL = 'vault/am_i_share_admin'
SHARE_OBJECTS_API = 'vault/get_share_objects'
SHARE_UPDATE_URL = 'vault/records_share_update'

logger = api.get_logger()


class ShareRecordCommand(base.ArgparseCommand):
    
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='share-record',
            description='Change the sharing permissions of an individual record',
        )
        ShareRecordCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)

    def add_arguments_to_parser(parser: argparse.ArgumentParser):

        parser.add_argument(
            '-e', '--email', dest='email', action='append', required=True, help='account email'
            )
        parser.add_argument(
            '--contacts-only', action='store_true', help="Share only to known targets; Allows routing to alternate domains with matching usernames if needed")
        parser.add_argument(
            '-f', '--force', action='store_true', help='Skip confirmation prompts'
            )
        parser.add_argument(
            '-a', '--action', dest='action', choices=['grant', 'revoke', 'owner', 'cancel'],
            default='grant', action='store', help='user share action. \'grant\' if omitted'
            )
        parser.add_argument(
            '-s', '--share', dest='can_share', action='store_true', help='can re-share record'
            )
        parser.add_argument(
            '-w', '--write', dest='can_edit', action='store_true', help='can modify record'
            )
        parser.add_argument(
            '-R', '--recursive', dest='recursive', action='store_true', 
            help='apply command to shared folder hierarchy'
            )
        parser.add_argument(
            '--dry-run', dest='dry_run', action='store_true', 
            help='display the permissions changes without committing them'
            )
        expiration = parser.add_mutually_exclusive_group()
        expiration.add_argument(
            '--expire-at', dest='expire_at', action='store', help='share expiration: never or UTC datetime'
            )
        expiration.add_argument(
            '--expire-in', dest='expire_in', action='store', metavar='<NUMBER>[(mi)nutes|(h)ours|(d)ays|(mo)nths|(y)ears]',
            help='share expiration: never or period'
            )
        parser.add_argument(
            'record', nargs='?', type=str, action='store', help='record/shared folder path/UID'
            )
    
    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError("Vault is not initialized.")
        vault = context.vault
        
        uid_or_name = kwargs.get('record')
        emails = kwargs.get('email') or []
        if not emails:
            raise ValueError('share-record', '\'email\' parameter is missing')
        
        force = kwargs.get('force') is True
        action = kwargs.get('action') or 'grant'
        contacts_only = kwargs.get('contacts_only')
        dry_run = kwargs.get('dry_run') is True
        can_edit = kwargs.get('can_edit') or False
        can_share = kwargs.get('can_share') or False
        recursive = kwargs.get('recursive')
    
        if contacts_only:
            shared_objects = get_share_objects(vault=vault)
            known_users = shared_objects.get('users', {})
            known_emails = [u.casefold() for u in known_users.keys()]
            is_unknown = lambda e: e.casefold() not in known_emails and utils.is_email(e)
            unknowns = [e for e in emails if is_unknown(e)]
            if unknowns:
                username_map = {e: get_contact(e, known_users) for e in unknowns}
                table = [[k, v] for k, v in username_map.items()]
                logger.info(f'{len(unknowns)} unrecognized share recipient(s) and closest matching contact(s)')
                report_utils.dump_report_data(table, ['Username', 'From Contacts'])
                confirmed = force or prompt_utils.user_choice('\tReplace with known matching contact(s)?', 'yn', default='n') == 'y'
                if confirmed:
                    good_emails = [e for e in emails if e not in unknowns]
                    replacements = [e for e in username_map.values() if e]
                    emails = [*good_emails, *replacements]

        if action == 'cancel':
            for email in emails:
                request = {
                    'command': 'cancel_share',
                    'to_email': email
                }
                try:
                    vault.keeper_auth.execute_auth_command(request=request)
                except Exception:
                    continue
            vault.sync_down()
            return
        else:
            share_expiration = get_share_expiration(kwargs.get('expire_at'), kwargs.get('expire_in'))
            request = prep_request(context=context, uid_or_name=uid_or_name, emails=emails, share_expiration=share_expiration, action=action, dry_run=dry_run, can_edit=can_edit, can_share=can_share, recursive=recursive)
            request and send_requests(vault, [request])


def get_share_objects(vault: vault_online.VaultOnline):
    request = record_pb2.GetShareObjectsRequest
    response = vault.keeper_auth.execute_auth_rest(rest_endpoint=SHARE_OBJECTS_API, request=request, response_type=record_pb2.GetShareObjectsResponse)
    users_by_type = dict(
            relationship=response.shareRelationships,
            family= response.shareFamilyUsers,
            enterprise=response.shareEnterpriseUsers,
            mc=response.shareMCEnterpriseUsers,
        )
    get_users = lambda rs_data, cat: {su.username: dict(name=su.fullname, is_sa=su.isShareAdmin, enterprise_id=su.enterpriseId, status=su.status, category=cat) for su in rs_data}
    users = reduce(
        lambda a, b: {**a, **b},
        [get_users(users, cat) for cat, users in users_by_type.items()],
        {}
    )
    enterprises = {se.enterpriseId: se.enterprisename for se in response.shareEnterpriseNames}
    get_teams = lambda rs_data: {utils.base64_url_encode(st.teamUid): dict(name=st.teamname, enterprise_id=st.enterpriseId) for st in rs_data}
    teams = get_teams(response.shareTeams)
    teams_mc = get_teams(response.shareMCTeams)

    share_objects = dict(
        users=users,
        enterprises=enterprises,
        teams={**teams, **teams_mc}
    )
    
    return share_objects


def get_contact(user, contacts):
    get_username = lambda addr: next(iter(addr.split('@')), '').casefold()
    matches = [c for c in contacts if get_username(user) == get_username(c)]
    if len(matches) > 1:
        raise ValueError('More than 1 matching usernames found')
    return next(iter(matches), None)


def prep_request(context: KeeperParams,
                 emails: list[str],
                 action: str,
                 uid_or_name: str,
                 share_expiration: int,
                 dry_run: bool,
                 recursive: Optional[bool] = False,
                 can_edit: Optional[bool] = False,
                 can_share: Optional[bool] = False):
    
    vault = context.vault
    record_uid = None
    folder_uid = None
    shared_folder_uid = None
    
    record_cache = {x.record_uid: x for x in vault.vault_data.records()}
    if uid_or_name in record_cache:
        record_uid = uid_or_name
    elif uid_or_name in vault.vault_data._shared_folders:
        shared_folder_uid = uid_or_name
    elif uid_or_name in vault.vault_data._folders:
        folder_uid = uid_or_name
    else:
        for shared_folder_info in vault.vault_data.shared_folders():
            if uid_or_name == shared_folder_info.name:
                shared_folder_uid = shared_folder_info.shared_folder_uid
                break
            sf = vault.vault_data.load_shared_folder(shared_folder_uid=shared_folder_info.shared_folder_uid)
            if sf:
                if any((True for x in sf.record_permissions if x.record_uid == uid_or_name)):
                    record_uid = uid_or_name
                    shared_folder_uid = shared_folder_info.shared_folder_uid
                    break

        if shared_folder_uid is None and record_uid is None:
            rs = folder_utils.try_resolve_path(context, uid_or_name)
            if rs is not None:
                folder, name = rs
                if name:
                    for record in vault.vault_data.records():
                        if record.title.lower() == name.lower():
                            record_uid = record.record_uid
                            break
                else:
                    if folder.folder_type == 'shared_folder':
                        folder_uid = folder.folder_uid
                        shared_folder_uid = folder_uid
                    elif folder.folder_type == 'shared_folder_folder':
                        folder_uid = folder.folder_uid
                        shared_folder_uid = folder.subfolders
    
    is_share_admin = False
    if record_uid is None and folder_uid is None and shared_folder_uid is None:
        if context._enterprise_loader:
            try:
                uid = utils.base64_url_decode(uid_or_name)
                if isinstance(uid, bytes) and len(uid) == 16:
                    request = record_pb2.AmIShareAdmin()
                    obj_share_admin = record_pb2.IsObjectShareAdmin()
                    obj_share_admin.uid = uid
                    obj_share_admin.objectType = record_pb2.CHECK_SA_ON_RECORD
                    request.isObjectShareAdmin.append(obj_share_admin)
                    response = vault.keeper_auth.execute_auth_rest(request=request, response_type=record_pb2.AmIShareAdmin, rest_endpoint=SHARE_ADMIN_URL)
                    if response.isObjectShareAdmin:
                        if response.isObjectShareAdmin[0].isAdmin:
                            is_share_admin = True
                            record_uid = uid_or_name
            except:
                pass

    if record_uid is None and folder_uid is None and shared_folder_uid is None:
        raise ValueError('share-record', 'Enter name or uid of existing record or shared folder')
    
    record_uids = set()
    if record_uid:
        record_uids.add(record_uid)
    elif folder_uid:
        folders = set()
        folders.add(folder_uid)
        folder = vault.vault_data.get_folder(folder_uid)
        if recursive:
            vault_utils.traverse_folder_tree(vault=vault.vault_data, folder=folder, callback=lambda x: folders.add(x.folder_uid))
        for uid in folders:
            if record_uid in record_cache:
                record_uids.update(uid)
    elif shared_folder_uid:
        if not recursive:
            raise ValueError('share-record', '--recursive parameter is required')
        sf = vault.vault_data.load_shared_folder(shared_folder_uid=shared_folder_uid)
        record_uids.update((x.record_uid for x in sf.record_permissions))

    if len(record_uids) == 0:
        raise ValueError('share-record', 'There are no records to share selected')

    if action == 'owner' and len(emails) > 1:
        raise ValueError('share-record', 'You can transfer ownership to a single account only')

    all_users = set((x.casefold() for x in emails))
    if not dry_run and action in ('grant', 'owner'):
        invited = vault.keeper_auth.load_user_public_keys(list(all_users), send_invites=True)
        if invited:
            for email in invited:
                logger.warning('Share invitation has been sent to \'%s\'', email)
            logger.warning('Please repeat this command when invitation is accepted.')
            all_users.difference_update(invited)
        all_users.intersection_update(vault.keeper_auth._key_cache.keys())

    if len(all_users) == 0:
        raise ValueError('share-record', 'Nothing to do.')

    if shared_folder_uid and isinstance(shared_folder_uid, str):
        load_records_in_shared_folder(vault=vault, shared_folder_uid=shared_folder_uid, record_uids=record_uids)
    elif shared_folder_uid and isinstance(shared_folder_uid, list):
        for sf_uid in shared_folder_uid:
            load_records_in_shared_folder(vault=vault, shared_folder_uid=sf_uid, record_uids=record_uids)

    not_owned_records = {} if is_share_admin else None
    for x in get_record_shares(vault=vault, record_uids=record_uids, is_share_admin=False) or []:
        if not_owned_records:
            record_uid = x.get('record_uid')
            if record_uid:
                not_owned_records[record_uid] = x

    rq = record_pb2.RecordShareUpdateRequest()
    existing_shares = {}
    record_titles = {}
    transfer_ruids = set()
    for record_uid in record_uids:
        if record_uid in record_cache:
            rec = record_cache[record_uid]
        elif not_owned_records and record_uid in not_owned_records:
            rec = not_owned_records[record_uid]
        elif is_share_admin:
            rec = {
                'record_uid': record_uid,
                'shares': {
                    'user_permissions': [{
                        'username': x,
                        'owner': False,
                        'share_admin': False,
                        'shareable': True if action == 'revoke' else False,
                        'editable': True if action == 'revoke' else False,
                    } for x in all_users]
                }
            }
        else:
            continue

        existing_shares.clear()
        if isinstance(rec, dict):
            if 'shares' in rec:
                shares = rec['shares']
                if 'user_permissions' in shares:
                    for po in shares['user_permissions']:
                        existing_shares[po['username'].lower()] = po
                del rec['shares']
            if 'data_unencrypted' in rec:
                try:
                    data = json.loads(rec['data_unencrypted'].decode())
                    if isinstance(data, dict):
                        if 'title' in data:
                            record_titles[record_uid] = data['title']
                except:
                    pass

        record_path = resolve_record_share_path(context=context, record_uid=record_uid)
        for email in all_users:
            ro = record_pb2.SharedRecord()
            ro.toUsername = email
            ro.recordUid = utils.base64_url_decode(record_uid)
            if record_path:
                if 'shared_folder_uid' in record_path:
                    ro.sharedFolderUid = utils.base64_url_decode(record_path['shared_folder_uid'])
                if 'team_uid' in record_path:
                    ro.teamUid = utils.base64_url_decode(record_path['team_uid'])

            if action in {'grant', 'owner'}:
                record_key = vault.vault_data.get_record_key(record_uid=rec.record_uid)
                if record_key and email not in existing_shares and vault.keeper_auth._key_cache and email in vault.keeper_auth._key_cache:
                    keys = vault.keeper_auth._key_cache[email]
                    if vault.keeper_auth.auth_context.forbid_rsa and keys.ec:
                        ec_key = crypto.load_ec_public_key(keys.ec)
                        ro.recordKey = crypto.encrypt_ec(record_key, ec_key)
                        ro.useEccKey = True
                    elif not vault.keeper_auth.auth_context.forbid_rsa and keys.rsa:
                        rsa_key = crypto.load_rsa_public_key(keys.rsa)
                        ro.recordKey = crypto.encrypt_rsa(record_key, rsa_key)
                        ro.useEccKey = False
                    if action == 'owner':
                        ro.transfer = True
                        transfer_ruids.add(record_uid)
                    else:
                        ro.editable = can_edit
                        ro.shareable = can_share
                        if isinstance(share_expiration, int):
                            if share_expiration > 0:
                                ro.expiration = share_expiration * 1000
                                ro.timerNotificationType = record_pb2.NOTIFY_OWNER
                            elif share_expiration < 0:
                                ro.expiration = -1
                elif email in existing_shares:
                    current = existing_shares[email]
                    if action == 'owner':
                        ro.transfer = True
                        transfer_ruids.add(record_uid)
                    else:
                        ro.editable = True if can_edit else current.get('editable')
                        ro.shareable = True if can_share else current.get('shareable')
                rq.updateSharedRecord.append(ro) if email in existing_shares else rq.addSharedRecord.append(ro)
            else:
                if can_share or can_edit:
                    if email in existing_shares:
                        current = existing_shares[email]
                        ro.editable = False if can_edit else current.get('editable')
                        ro.shareable = False if can_share else current.get('shareable')
                    rq.updateSharedRecord.append(ro)
                else:
                    rq.removeSharedRecord.append(ro)
    


def get_share_expiration(expire_at, expire_in):
    if not expire_at and not expire_in:
        return

    dt = None
    if isinstance(expire_at, str):
        if expire_at == 'never':
            return -1
        dt = datetime.datetime.fromisoformat(expire_at)
    elif isinstance(expire_in, str):
        if expire_in == 'never':
            return -1
        td = timeout_utils.parse_timeout(expire_in)
        dt = datetime.datetime.now() + td
    if dt is None:
        raise ValueError(f'Incorrect expiration: {expire_at or expire_in}')

    return int(dt.timestamp())


def cancel_share(vault: vault_online.VaultOnline, emails: list[str]):
    for email in emails:
        request = {
            'command': 'cancel_share',
            'to_email': email
        }
        try:
            vault.keeper_auth.execute_auth_command(request=request)
        except Exception:
            continue
    vault.sync_down()
    return


def load_records_in_shared_folder(vault: vault_online.VaultOnline, shared_folder_uid: str, record_uids: Optional[set[str]] = None):

    shared_folder = None
    for shared_folder_info in vault.vault_data.shared_folders():
        if shared_folder_uid == shared_folder_info.shared_folder_uid:
            shared_folder = vault.vault_data.load_shared_folder(shared_folder_uid=shared_folder_uid)
            break
    if not shared_folder:
        raise Exception(f'Shared folder \"{shared_folder_uid}\" is not loaded.')
    
    shared_folder_key = vault.vault_data._shared_folders[shared_folder_uid].shared_folder_key
    record_keys = {}
    sf_record_keys = vault.vault_data.storage.record_keys.get_links_by_object(shared_folder.shared_folder_uid) or []
    for rk in sf_record_keys:
        record_uid = rk.record_uid
        try:
            key = utils.base64_url_decode(rk['record_key'])
            if len(key) == 60:
                record_key = crypto.decrypt_aes_v2(key, shared_folder_key)
            else:
                record_key = crypto.decrypt_aes_v1(key, shared_folder_key)
            record_keys[record_uid] = record_key
        except Exception as e:
            logger.debug('Cannot decrypt record \"%s\" key: %s', record_uid, e)

    record_cache = [x.record_uid for x in vault.vault_data.records()]

    if record_uids:
        record_set = set(record_uids)
        record_set.intersection_update(record_keys.keys())
    else:
        record_set = set(record_keys.keys())
    record_set.difference_update(record_cache)

    while len(record_set) > 0:
        rq = record_pb2.GetRecordDataWithAccessInfoRequest()
        rq.clientTime = utils.current_milli_time()
        rq.recordDetailsInclude = record_pb2.DATA_PLUS_SHARE
        for uid in record_set:
            try:
                rq.recordUid.append(utils.base64_url_decode(uid))
            except Exception as e:
                logger.debug('Incorrect record UID \"%s\": %s', uid, e)
        record_set.clear()

        rs = vault.keeper_auth.execute_auth_rest(rest_endpoint=RECORD_DETAILS_URL, request=rq, response_type=record_pb2.GetRecordDataWithAccessInfoResponse)
        for record_info in rs.recordDataWithAccessInfo:
            record_uid = utils.base64_url_encode(record_info.recordUid)
            record_data = record_info.recordData
            try:
                if record_data.recordUid and record_data.recordKey:
                    owner_id = utils.base64_url_encode(record_data.recordUid)
                    if owner_id in record_keys:
                        record_keys[record_uid] = crypto.decrypt_aes_v2(record_data.recordKey, record_keys[owner_id])

                if record_uid not in record_keys:
                    continue

                record_key = record_keys[record_uid]
                version = record_data.version
                record = {
                    'record_uid': record_uid,
                    'revision': record_data.revision,
                    'version': version,
                    'shared': record_data.shared,
                    'data': record_data.encryptedRecordData,
                    'record_key_unencrypted': record_keys[record_uid],
                    'client_modified_time': record_data.clientModifiedTime,
                }
                data_decoded = utils.base64_url_decode(record_data.encryptedRecordData)
                if version <= 2:
                    record['data_unencrypted'] = crypto.decrypt_aes_v1(data_decoded, record_key)
                else:
                    record['data_unencrypted'] = crypto.decrypt_aes_v2(data_decoded, record_key)

                if record_data.encryptedExtraData and version <= 2:
                    record['extra'] = record_data.encryptedExtraData
                    extra_decoded = utils.base64_url_decode(record_data.encryptedExtraData)
                    record['extra_unencrypted'] = crypto.decrypt_aes_v1(extra_decoded, record_key)
                if version == 3:
                    v3_record = vault.vault_data.load_record(record_uid=record_uid)
                    if isinstance(v3_record, vault_record.TypedRecord):
                        for ref in itertools.chain(v3_record.fields, v3_record.custom):
                            if ref.type.endswith('Ref') and isinstance(ref.value, list):
                                record_set.update(ref.value)
                elif version == 4:
                    if record_data.fileSize > 0:
                        record['file_size'] = record_data.fileSize
                    if record_data.thumbnailSize > 0:
                        record['thumbnail_size'] = record_data.thumbnailSize
                if record_data.recordUid and record_data.recordKey:
                    record['owner_uid'] = utils.base64_url_encode(record_data.recordUid)
                    record['link_key'] = utils.base64_url_encode(record_data.recordKey)

                record['shares'] = {
                    'user_permissions': [{
                        'username': up.username,
                        'owner': up.owner,
                        'share_admin': up.shareAdmin,
                        'shareable': up.sharable,
                        'editable': up.editable,
                        'awaiting_approval': up.awaitingApproval,
                        'expiration': up.expiration,
                    } for up in record_info.userPermission],
                    'shared_folder_permissions': [{
                        'shared_folder_uid': utils.base64_url_encode(sp.sharedFolderUid),
                        'reshareable': sp.resharable,
                        'editable': sp.editable,
                        'revision': sp.revision,
                        'expiration': sp.expiration,
                    } for sp in record_info.sharedFolderPermission],
                }
                record_set.add(record_uid)
            except Exception as e:
                logger.debug('Error decrypting record \"%s\": %s', record_uid, e)
        
        
def get_record_shares(vault: vault_online.VaultOnline, record_uids: set[str], is_share_admin=False):
    record_cache = {x.record_uid: x for x in vault.vault_data.records()}
    
    def need_share_info(uid):
        if uid in record_cache:
            r = record_cache[uid]
            return not hasattr(r, 'shares')
        return is_share_admin

    result = []
    unique = set(record_uids)
    uids = [x for x in unique if need_share_info(x)]
    try:
        while len(uids) > 0:
            chunk = uids[:999]
            uids = uids[999:]
            rq = record_pb2.GetRecordDataWithAccessInfoRequest()
            rq.clientTime = utils.current_milli_time()
            rq.recordUid.extend([utils.base64_url_decode(x) for x in chunk])
            rq.recordDetailsInclude = record_pb2.SHARE_ONLY
            rs= vault.keeper_auth.execute_auth_rest(rest_endpoint=RECORD_DETAILS_URL, request=rq, response_type=record_pb2.GetRecordDataWithAccessInfoResponse)
            for info in rs.recordDataWithAccessInfo:
                record_uid = utils.base64_url_encode(info.recordUid)
                if record_uid in record_cache:
                    keeper_record = record_cache[record_uid]
                    rec = {'record_uid': record_uid}
                    if hasattr(keeper_record, 'title'):
                        rec['title'] = keeper_record.title
                    if hasattr(keeper_record, 'data_unencrypted'):
                        rec['data_unencrypted'] = keeper_record.data_unencrypted
                else:
                    rec = {'record_uid': record_uid}
                
                if 'shares' not in rec:
                    rec['shares'] = {}
                rec['shares']['user_permissions'] = []
                rec['shares']['shared_folder_permissions'] = []
                for up in info.userPermission:
                    oup = {
                        'username': up.username,
                        'owner': up.owner,
                        'share_admin': up.shareAdmin,
                        'shareable': up.sharable,
                        'editable': up.editable,
                    }
                    if up.awaitingApproval:
                        oup['awaiting_approval'] = up.awaitingApproval
                    if up.expiration > 0:
                        oup['expiration'] = up.expiration.__str__()
                    rec['shares']['user_permissions'].append(oup)
                for sp in info.sharedFolderPermission:
                    osp = {
                        'shared_folder_uid': utils.base64_url_encode(sp.sharedFolderUid),
                        'reshareable': sp.resharable,
                        'editable': sp.editable,
                        'revision': sp.revision,
                    }
                    if sp.expiration > 0:
                        osp['expiration'] = sp.expiration
                    rec['shares']['shared_folder_permissions'].append(osp)

                if record_uid not in record_cache:
                    result.append(rec)
    except Exception as e:
        logger.error(e)

    if len(result) > 0:
        return result
    return None


def resolve_record_share_path(context: KeeperParams, record_uid: str):
    return resolve_record_permission_path(context=context, record_uid=record_uid, permission='can_share')


def resolve_record_permission_path(context: KeeperParams, record_uid: str, permission: str):
    for ap in enumerate_record_access_paths(context=context, record_uid=record_uid):
        if ap.get(permission):
            path = {
                'record_uid': record_uid
            }
            if 'shared_folder_uid' in ap:
                path['shared_folder_uid'] = ap['shared_folder_uid']
            if 'team_uid' in ap:
                path['team_uid'] = ap['team_uid']
            return path

    return None


def enumerate_record_access_paths(context: KeeperParams, record_uid: str):

    for sf_info in context.vault.vault_data.shared_folders():
        sf_uid = sf_info.shared_folder_uid
        sf = context.vault.vault_data.load_shared_folder(shared_folder_uid=sf_uid)
        if sf and sf.record_permissions:
            shared_folder_records = [x for x in sf.record_permissions if x.record_uid == record_uid]
            if len(shared_folder_records) > 0:
                sfr = shared_folder_records[0]
                is_owner = sfr.can_edit and sfr.can_share
                if is_owner:
                    can_edit = True
                    can_share = True
                else:
                    can_edit = sfr.can_edit
                    can_share = sfr.can_share
                if hasattr(sf, 'key_type'):
                    yield {
                        'record_uid': record_uid,
                        'shared_folder_uid': sf_uid,
                        'can_edit': can_edit,
                        'can_share': can_share,
                        'can_view': True
                    }
                else:
                    for up in sf.user_permissions:
                        if up.user_type == storage_types.SharedFolderUserType.Team:
                            team_uid = up.user_uid
                            enterprise_data = context.enterprise_data
                            team = enterprise_utils.TeamUtils.resolve_single_team(enterprise_data, team_uid)
                            if team:
                                yield {
                                    'record_uid': record_uid,
                                    'shared_folder_uid': sf_uid,
                                    'team_uid': team_uid,
                                    'can_edit': can_edit and not team.restrict_edit,
                                    'can_share': can_share and not team.restrict_share,
                                    'can_view': not team.restrict_view
                                }



def send_requests(vault: vault_online.VaultOnline, requests):
    requests = iter(requests)
    rq = next(requests, None)
    while rq and (len(rq.addSharedRecord) > 0 or len(rq.updateSharedRecord) > 0 or len(rq.removeSharedRecord) > 0):
        rq1 = record_pb2.RecordShareUpdateRequest()
        left = 990
        if left > 0 and len(rq.addSharedRecord) > 0:
            rq1.addSharedRecord.extend(rq.addSharedRecord[0:left])
            added = len(rq1.addSharedRecord)
            del rq.addSharedRecord[0:added]
            left -= added
        if left > 0 and len(rq.updateSharedRecord) > 0:
            rq1.updateSharedRecord.extend(rq.updateSharedRecord[0:left])
            added = len(rq1.updateSharedRecord)
            del rq.updateSharedRecord[0:added]
            left -= added
        if left > 0 and len(rq.removeSharedRecord) > 0:
            rq1.removeSharedRecord.extend(rq.removeSharedRecord[0:left])
            added = len(rq1.removeSharedRecord)
            del rq.removeSharedRecord[0:added]
            left -= added

        rs = vault.keeper_auth.execute_auth_rest(rest_endpoint=SHARE_UPDATE_URL, request=rq1, response_type=record_pb2.RecordShareUpdateResponse)
        for attr in ['addSharedRecordStatus', 'updateSharedRecordStatus', 'removeSharedRecordStatus']:
            if hasattr(rs, attr):
                statuses = getattr(rs, attr)
                for status_rs in statuses:
                    record_uid = utils.base64_url_encode(status_rs.recordUid)
                    status = status_rs.status
                    email = status_rs.username
                    if status == 'success':
                        verb = 'granted to' if attr == 'addSharedRecordStatus' else 'changed for' if attr == 'updateSharedRecordStatus' else 'revoked from'
                        logger.info('Record \"%s\" access permissions has been %s user \'%s\'', record_uid, verb, email)
                    else:
                        verb = 'grant' if attr == 'addSharedRecordStatus' else 'change' if attr == 'updateSharedRecordStatus' else 'revoke'

                        logger.info('Failed to %s record \"%s\" access permissions for user \'%s\': %s', verb, record_uid, email, status_rs.message)
        rq = next(requests, None)
