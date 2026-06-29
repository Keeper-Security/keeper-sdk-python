import argparse
import json
from typing import Any, Dict, List, Optional

from keepersdk.vault import nsf_folder_records, nsf_management, nsf_sharing, vault_record, nsf_common
from keepersdk.vault.share_management_utils import parse_nsf_share_expiration
from keepersdk.vault.nsf_management import (
    NsfError,
    NsfListRow,
    NsfRemovePreviewItem,
    NsfRemoveResult,
)
from keepersdk.vault import share_management_utils

from . import base
from .record_edit import RecordEditMixin, record_fields_description, ParsedFieldValue
from .. import api, prompt_utils
from ..helpers import report_utils
from ..params import KeeperParams

logger = api.get_logger()

_MASKED_TYPES = frozenset({'password', 'secret', 'pinCode', 'pin_code'})


def _mask_sensitive_fields(fields: List[Any], *, unmask: bool) -> List[Any]:
    """Return a copy of record fields with sensitive values replaced unless ``unmask``."""
    if unmask or not fields:
        return list(fields)
    masked_fields: List[Any] = []
    for f in fields:
        if not isinstance(f, dict):
            masked_fields.append(f)
            continue
        ftype = str(f.get('type', ''))
        if ftype not in _MASKED_TYPES:
            masked_fields.append(f)
            continue
        entry = dict(f)
        values = entry.get('value', [])
        if not isinstance(values, list):
            values = [values]
        entry['value'] = [
            '********' if (val or val == 0) else val
            for val in values
        ]
        masked_fields.append(entry)
    return masked_fields


def _require_vault(context: KeeperParams):
    base.require_login(context)
    if context.vault is None:
        raise base.CommandError('Vault is not initialized. Login to initialize the vault.')
    return context.vault


def _wrap_nsf(command: str, fn):
    try:
        return fn()
    except NsfError as e:
        raise base.CommandError(str(e)) from e


def _typed_record_to_data(
        record: vault_record.TypedRecord,
        title: str,
        notes: Optional[str]) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        'type': record.record_type,
        'title': title,
        'fields': [
            {'type': f.type, 'label': f.label or '', 'value': list(f.value)}
            for f in record.fields
        ],
    }
    if record.custom:
        data['custom'] = [
            {'type': f.type, 'label': f.label or '', 'value': list(f.value)}
            for f in record.custom
        ]
    if notes:
        data['notes'] = notes
    return data


def _legacy_record_to_data(
        record: vault_record.PasswordRecord,
        title: str,
        notes: Optional[str]) -> Dict[str, Any]:
    data: Dict[str, Any] = {'type': record.get_record_type(), 'title': title, 'fields': []}
    for ftype, val in (
            ('login', record.login),
            ('password', record.password),
            ('url', record.link),
            ('oneTimeCode', record.totp),
    ):
        if val:
            data['fields'].append({'type': ftype, 'value': [val]})
    for cf in record.custom or []:
        data['fields'].append({
            'type': 'text',
            'label': cf.name if hasattr(cf, 'name') else '',
            'value': [cf.value if hasattr(cf, 'value') else str(cf)],
        })
    if notes:
        data['notes'] = notes
    return data


def _access_role_label(access: Dict[str, Any]) -> str:
    if access.get('owner'):
        return 'owner'
    if access.get('can_edit'):
        return 'editor'
    if access.get('can_view') or access.get('can_view_title'):
        return 'viewer'
    return str(access.get('access_type') or '')


class _NsfRecordDataMixin(RecordEditMixin):
    """Build encrypted record JSON payloads for nsf-record-add / nsf-record-update."""

    def build_nsf_record_data(
            self,
            context: KeeperParams,
            record_type: str,
            title: str,
            notes: Optional[str],
            record_fields: List[ParsedFieldValue]) -> Dict[str, Any]:
        notes = self.validate_notes(notes or '')
        if record_type in ('legacy', 'general'):
            record = vault_record.PasswordRecord()
            self.assign_legacy_fields(record, record_fields)
            record.title = title
            record.notes = notes
            return _legacy_record_to_data(record, title, notes)

        rt = context.vault.vault_data.get_record_type_by_name(record_type)
        if not rt:
            raise base.CommandError(f'Record type "{record_type}" cannot be found.')

        record = vault_record.TypedRecord()
        record.record_type = record_type
        for rf in rt.fields:
            ref = rf.type
            if not ref:
                continue
            field = vault_record.TypedField.create_field(ref, rf.label)
            if rf.required is True:
                field.required = True
            record.fields.append(field)
        self.assign_typed_fields(record, record_fields)
        record.title = title
        record.notes = notes
        return _typed_record_to_data(record, title, notes)


class NsfListCommand(base.ArgparseCommand):
    
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='nsf-list',
            description='List NSF folders and records',
        )
        NsfListCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('--folders', action='store_true', help='Show only folders')
        parser.add_argument('--records', action='store_true', help='Show only records')
        parser.add_argument(
            '--format', dest='format', choices=['table', 'csv', 'json'], default='table',
        )
        parser.add_argument(
            '--output', dest='output', type=str,
            help='Path to output file (ignored for table format)',
        )

    def execute(self, context: KeeperParams, **kwargs):
        vault = _require_vault(context)
        show_folders = kwargs.get('folders', False)
        show_records = kwargs.get('records', False)
        fmt = kwargs.get('format', 'table')
        if not show_folders and not show_records:
            show_folders = show_records = True

        def _run():
            return nsf_management.list_nsf_items(
                vault,
                include_folders=show_folders,
                include_records=show_records,
            )

        rows_data: List[NsfListRow] = _wrap_nsf('nsf-list', _run)
        if not rows_data:
            if show_folders and show_records:
                logger.info('No NSF folders or records found. Run sync-down first.')
            elif show_folders:
                logger.info('No NSF folders found.')
            else:
                logger.info('No NSF records found.')
            return

        table = []
        if fmt in ('json', 'csv'):
            headers = ['Item Type', 'UID', 'Title', 'Type', 'Description', 'Parent/Folder']
            for r in rows_data:
                table.append([r.item_type, r.uid, r.title, r.record_type, r.description, r.parent_or_folder])
        else:
            headers = ['Item Type', 'UID', 'Title', 'Type', 'Description']
            for r in rows_data:
                table.append([r.item_type, r.uid, r.title, r.record_type, r.description])
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(
            table, headers, fmt=fmt, filename=kwargs.get('output'),
            row_number=True, column_width=40,
        )


class NsfGetCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='nsf-get',
            description='Get details of an NSF record or folder by UID or title',
        )
        NsfGetCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('uid', type=str, help='Record UID, folder UID, or title')
        parser.add_argument(
            '--format', dest='format', choices=['detail', 'json'], default='detail',
            help='Output format: detail (default) or json',
        )
        parser.add_argument(
            '--verbose', '-v', dest='verbose', action='store_true',
            help='Show full permission breakdown for each accessor',
        )
        parser.add_argument(
            '--unmask', dest='unmask', action='store_true',
            help='Reveal masked field values (passwords, secrets)',
        )

    def execute(self, context: KeeperParams, **kwargs):
        vault = _require_vault(context)
        uid = (kwargs.get('uid') or '').strip()
        if not uid:
            raise base.CommandError('UID parameter is required')

        fmt = kwargs.get('format') or 'detail'
        verbose = kwargs.get('verbose', False)
        unmask = kwargs.get('unmask', False)

        def _run():
            return nsf_management.get_nsf_item(vault, uid)

        detail = _wrap_nsf('nsf-get', _run)
        if detail.get('item_type') == 'folder':
            if fmt == 'json':
                self._print_folder_json(detail, verbose)
            else:
                self._print_folder_detail(detail, verbose)
            return

        if unmask:
            logger.warning(
                'nsf-get: --unmask was requested for record %s; '
                'sensitive values are printed to stdout only.',
                detail.get('record_uid', uid),
            )
        if fmt == 'json':
            self._print_record_json(vault, detail, verbose, unmask)
        else:
            self._print_record_detail(detail, verbose, unmask)

    @staticmethod
    def _print_folder_detail(detail: Dict[str, Any], verbose: bool) -> None:
        logger.info('')
        logger.info('{0:>25s}: {1}'.format('NSF Folder UID', detail.get('nsf_folder_uid', '')))
        logger.info('{0:>25s}: {1}'.format('Name', detail.get('name', '')))
        logger.info('{0:>25s}: {1}'.format('Parent', detail.get('parent_uid', '')))
        NsfGetCommand._print_folder_access(
            detail.get('access') or {},
            verbose,
            owner_username=detail.get('owner_username'),
            owner_account_uid=detail.get('owner_account_uid'),
        )

    @staticmethod
    def _print_folder_json(detail: Dict[str, Any], verbose: bool) -> None:
        fo = {
            'nsf_folder_uid': detail.get('nsf_folder_uid'),
            'name': detail.get('name'),
            'parent_uid': detail.get('parent_uid'),
        }
        if detail.get('owner_username'):
            fo['owner'] = detail['owner_username']
        access = detail.get('access') or {}
        for fr in access.get('results') or []:
            if not fr.get('success'):
                continue
            accessors = fr.get('accessors') or []
            if accessors:
                owner_username = detail.get('owner_username')
                owner_account_uid = detail.get('owner_account_uid')
                fo['accessors'] = accessors if verbose else [
                    {
                        'username': a.get('username'),
                        'role': nsf_common.folder_access_role_label(
                            a, owner_username, owner_account_uid),
                    }
                    for a in accessors
                ]
        logger.info(json.dumps(fo, indent=2))

    @staticmethod
    def _print_folder_access(
            access: Dict[str, Any],
            verbose: bool,
            owner_username: Optional[str] = None,
            owner_account_uid: Optional[str] = None) -> None:
        for fr in access.get('results') or []:
            if not fr.get('success'):
                err = fr.get('error') or {}
                logger.warning('  Access error: %s — %s', err.get('status'), err.get('message'))
                continue
            accessors = fr.get('accessors') or []
            if not accessors:
                continue
            logger.info('')
            logger.info('{0:>25s}:'.format('Folder Access'))
            for a in accessors:
                label = a.get('username', '') or a.get('accessor_uid', '')
                role = nsf_common.folder_access_role_label(
                    a, owner_username, owner_account_uid)
                logger.info('{0:>25s}: {1}'.format(label, role))
                if verbose and a.get('permissions'):
                    logger.info('{0:>25s}: {1}'.format('', json.dumps(a.get('permissions', {}))))

    def _print_record_detail(self, detail: Dict[str, Any], verbose: bool, unmask: bool) -> None:
        record_uid = detail.get('record_uid', '')
        logger.info('')
        logger.info('{0:>20s}: {1}'.format('UID', record_uid))
        logger.info('{0:>20s}: {1}'.format('Type', detail.get('type') or ''))
        if detail.get('title'):
            logger.info('{0:>20s}: {1}'.format('Title', detail['title']))
        if detail.get('folder'):
            logger.info('{0:>20s}: {1}'.format('Folder', detail['folder']))

        fields = _mask_sensitive_fields(detail.get('fields') or [], unmask=unmask)
        for label, key in (('Login', 'login'), ('Password', 'password'), ('URL', 'url')):
            val = self._extract_field_value(fields, key)
            if val:
                logger.info('{0:>20s}: {1}'.format(label, val))

        shown = {'login', 'password', 'url'}
        for f in fields:
            if not isinstance(f, dict):
                continue
            ftype = f.get('type', '')
            if ftype in shown:
                continue
            label = f.get('label') or ftype.replace('_', ' ').title()
            values = f.get('value', [])
            if not isinstance(values, list):
                values = [values]
            for val in values:
                if not val and val != 0:
                    continue
                if isinstance(val, dict):
                    dval = ', '.join(f'{k}: {v}' for k, v in val.items() if v)
                else:
                    dval = str(val)
                logger.info('{0:>20s}: {1}'.format(label, dval))

        notes = detail.get('notes') or ''
        if notes:
            for i, line in enumerate(notes.split('\n')):
                logger.info('{0:>21s} {1}'.format('Notes:' if i == 0 else '', line.strip()))

        self._print_record_permissions(detail.get('record_accesses') or [], verbose)

    def _print_record_json(
            self,
            vault,
            detail: Dict[str, Any],
            verbose: bool,
            unmask: bool) -> None:
        ro: Dict[str, Any] = {
            'record_uid': detail.get('record_uid'),
            'title': detail.get('title'),
            'type': detail.get('type'),
            'version': detail.get('version'),
            'revision': detail.get('revision'),
        }
        if detail.get('folder'):
            ro['folder'] = detail['folder']
        if detail.get('fields'):
            ro['fields'] = _mask_sensitive_fields(detail['fields'], unmask=unmask)
        if detail.get('notes'):
            ro['notes'] = detail['notes']

        accesses = detail.get('record_accesses') or []
        if accesses:
            ro['user_permissions'] = [
                {
                    'username': a.get('accessor_name') or a.get('access_type_uid', ''),
                    'owner': a.get('owner', False),
                    'editable': a.get('can_edit', False),
                    'role': nsf_common.access_role_label(a),
                    **({flag: a.get(flag) for flag in (
                        'can_view_title', 'can_edit', 'can_view', 'can_list_access',
                        'can_update_access', 'can_delete',
                    )} if verbose else {}),
                }
                for a in accesses
            ]
        logger.info(json.dumps(ro, indent=2))

    @staticmethod
    def _extract_field_value(fields: List[Any], field_type: str) -> str:
        for f in fields:
            if not isinstance(f, dict) or f.get('type', '') != field_type:
                continue
            values = f.get('value', [])
            if not isinstance(values, list):
                values = [values]
            for val in values:
                if val:
                    if isinstance(val, dict):
                        return ', '.join(f'{k}: {v}' for k, v in val.items() if v)
                    return str(val)
        return ''

    @staticmethod
    def _print_record_permissions(accesses: List[Dict[str, Any]], verbose: bool) -> None:
        if not accesses:
            return
        logger.info('')
        logger.info('User Permissions:')
        for a in accesses:
            accessor = a.get('accessor_name') or a.get('access_type_uid', '')
            logger.info('')
            logger.info('  User: ' + accessor)
            if a.get('owner'):
                logger.info('  Owner: Yes')
            else:
                logger.info('  Role: ' + nsf_common.access_role_label(a))
            can_edit = a.get('can_edit', False)
            can_share = a.get('can_approve_access', False) or a.get('can_update_access', False)
            logger.info('  Shareable: ' + ('Yes' if can_share else 'No'))
            logger.info('  Read-Only: ' + ('Yes' if not can_edit else 'No'))
            if verbose:
                logger.info(f'  {"Permission":<20}  Value')
                logger.info(f'  {"-"*20}  -----')
                for flag in (
                        'can_view_title', 'can_edit', 'can_view', 'can_list_access',
                        'can_update_access', 'can_delete', 'can_change_ownership',
                ):
                    logger.info(f'  {flag:<20}  {"Y" if a.get(flag) else "N"}')


class NsfRecordAddCommand(base.ArgparseCommand, _NsfRecordDataMixin):

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='nsf-record-add',
            description='Add a record to NSF',
        )
        NsfRecordAddCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('--syntax-help', dest='syntax_help', action='store_true',
                        help='Display help on field parameters.')
        parser.add_argument('-f', '--force', dest='force', action='store_true', help='ignore warnings')
        parser.add_argument('-t', '--title', dest='title', type=str, help='record title')
        parser.add_argument('-rt', '--record-type', dest='record_type', type=str, help='record type')
        parser.add_argument('-n', '--notes', dest='notes', type=str, help='record notes')
        parser.add_argument('--folder', dest='folder_uid', metavar='FOLDER', type=str,
                        help='folder name or UID to store record')
        parser.add_argument('fields', nargs='*', type=str,
                        help='load record type data from strings with dot notation')

    def execute(self, context: KeeperParams, **kwargs):
        vault = _require_vault(context)
        if kwargs.get('syntax_help'):
            prompt_utils.output_text(record_fields_description)
            return

        title = kwargs.get('title')
        if not title:
            raise base.CommandError('Title parameter is required.')
        record_type = kwargs.get('record_type')
        if not record_type:
            raise base.CommandError('Record type parameter is required.')

        record_fields: List[ParsedFieldValue] = []
        add_attachments: List[ParsedFieldValue] = []
        for field in kwargs.get('fields', []):
            parsed = RecordEditMixin.parse_field(field)
            if parsed.type == 'file':
                add_attachments.append(parsed)
            else:
                record_fields.append(parsed)

        self.warnings.clear()
        data = self.build_nsf_record_data(
            context, record_type, title, kwargs.get('notes'), record_fields)

        if self.warnings:
            for w in self.warnings:
                logger.warning(w)
            if not kwargs.get('force'):
                return

        if add_attachments:
            logger.warning(
                'File attachments are not yet supported in nsf-record-add. '
                'Use record-add for attachment support.')
            if not kwargs.get('force'):
                return

        folder_uid = kwargs.get('folder_uid')
        if folder_uid:
            resolved = nsf_management.resolve_nsf_folder_uid(vault, folder_uid)
            if resolved is None or resolved == '':
                raise base.CommandError(f'No such NSF folder: {folder_uid}')
            folder_uid = resolved

        def _run():
            return nsf_management.create_nsf_record(
                vault,
                title=title,
                record_type=record_type,
                folder_uid=folder_uid,
                record_data=data,
            )

        result = _wrap_nsf('nsf-record-add', _run)
        logger.info('NSF record created: %s', result.record_uid)
        return result.record_uid


class NsfRecordUpdateCommand(base.ArgparseCommand, _NsfRecordDataMixin):

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='nsf-record-update',
            description='Update an NSF record',
        )
        NsfRecordUpdateCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('--syntax-help', dest='syntax_help', action='store_true',
                        help='Display help on field parameters.')
        parser.add_argument('-f', '--force', dest='force', action='store_true', help='ignore warnings')
        parser.add_argument('-t', '--title', dest='title', type=str, help='modify record title')
        parser.add_argument('-rt', '--record-type', dest='record_type', type=str, help='record type')
        parser.add_argument('-n', '--notes', dest='notes', type=str, help='modify record notes')
        parser.add_argument('-r', '--record', dest='record_uids', metavar='RECORD', type=str,
                        action='append', help='record UID or title')
        parser.add_argument('fields', nargs='*', type=str,
                        help='load record type data from strings with dot notation')

    def execute(self, context: KeeperParams, **kwargs):
        vault = _require_vault(context)
        if kwargs.get('syntax_help'):
            prompt_utils.output_text(record_fields_description)
            return

        record_uids = kwargs.get('record_uids') or []
        if not record_uids:
            raise base.CommandError('Record UID is required (use -r or --record)')

        record_type = kwargs.get('record_type')
        if record_type and record_type not in ('legacy', 'general'):
            rt = vault.vault_data.get_record_type_by_name(record_type)
            if not rt:
                raise base.CommandError(f'Record type "{record_type}" cannot be found.')

        fields: Dict[str, Any] = {}
        for spec in [f.strip() for f in kwargs.get('fields', []) if f.strip()]:
            try:
                parsed = RecordEditMixin.parse_field(spec)
                if parsed.type in fields:
                    existing = fields[parsed.type]
                    fields[parsed.type] = (
                        ([existing] if not isinstance(existing, list) else existing) + [parsed.value]
                    )
                else:
                    fields[parsed.type] = parsed.value
            except ValueError as e:
                raise base.CommandError(f'Invalid field specification: {e}') from e

        title = kwargs.get('title')
        notes = kwargs.get('notes')

        for identifier in record_uids:
            def _run(uid=identifier):
                return nsf_management.update_nsf_record(
                    vault,
                    uid,
                    title=title,
                    record_type=record_type,
                    fields=fields or None,
                    notes=notes,
                )

            result = _wrap_nsf('nsf-record-update', _run)
            logger.info('NSF record updated: %s (%s)', result.record_uid, result.status)


def _record_title_from_vault(vault, record_uid: str) -> str:
    entry = vault.nsf_data.get_record(record_uid) if vault.nsf_data else None
    if entry and entry.decrypted_data:
        try:
            payload = json.loads(entry.decrypted_data)
            if isinstance(payload, dict) and payload.get('title'):
                return str(payload['title'])
        except json.JSONDecodeError:
            pass
    return record_uid


def _folder_name_from_vault(vault, folder_uid: str) -> str:
    if vault.nsf_data:
        folder = vault.nsf_data.get_folder(folder_uid)
        if folder and folder.name:
            return folder.name
    return folder_uid


def _print_remove_preview_items(
        vault,
        items: List[NsfRemovePreviewItem],
        *,
        item_label: str,
        operation: str,
        name_fn,
        quiet: bool = False) -> bool:
    """Print preview lines. Returns True if any error."""
    any_error = False
    for pr in items:
        name = name_fn(vault, pr.item_uid)
        if pr.error:
            any_error = True
            logger.error(
                f"  {name} [{pr.item_uid}]: "
                f"{pr.error.get('code', '')} — {pr.error.get('message', '')}"
            )
        else:
            action = 'permanently deleted' if operation == 'delete-permanent' else operation
            logger.info(f"\nThe following {item_label} will be {action}:")
            logger.info(f"  {name} [{pr.item_uid}]")
            if pr.impact and not quiet:
                parts = []
                for key, label in (
                        ('folders_count', 'sub-folder(s)'),
                        ('records_count', 'record(s)'),
                        ('affected_users_count', 'user(s)'),
                        ('affected_teams_count', 'team(s)'),
                ):
                    count = pr.impact.get(key, 0)
                    if count:
                        parts.append(f"{count} {label}")
                if parts:
                    logger.info(f"  This will affect: {', '.join(parts)}")
                for w in pr.impact.get('warnings') or []:
                    logger.info(f"  Warning: {w}")
    return any_error


def _confirm_removal(prompt: str, force: bool) -> bool:
    if force:
        return True
    return prompt_utils.user_choice(prompt, 'yn', default='n') in ('y', 'yes')


class NsfRecordDetailsCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='nsf-record-details',
            description='Get NSF record metadata (title, type, revision) using v3 API',
        )
        NsfRecordDetailsCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('record_uids', nargs='+', type=str,
                        help='Record UIDs or titles')
        parser.add_argument(
            '--format', dest='format', choices=['table', 'json'], default='table',
            help='Output format (default: table)',
        )

    def execute(self, context: KeeperParams, **kwargs):
        vault = _require_vault(context)
        identifiers = kwargs.get('record_uids') or []
        fmt = kwargs.get('format', 'table')

        def _run():
            return nsf_management.get_nsf_record_details(vault, identifiers)

        result = _wrap_nsf('nsf-record-details', _run)
        if fmt == 'json':
            logger.info(json.dumps(result, indent=2))
            return

        for record in result.get('data', []):
            logger.info('Record UID: %s', record['record_uid'])
            logger.info('  Title: %s', record['title'])
            logger.info('  Type: %s', record.get('type', 'Unknown'))
            logger.info('  Version: %s', record.get('version', 0))
            logger.info('  Revision: %s', record.get('revision', 0))
            logger.info('')
        forbidden = result.get('forbidden_records') or []
        if forbidden:
            logger.warning('Forbidden records: %d', len(forbidden))
            for uid in forbidden:
                logger.warning('  %s', uid)
        logger.info('Total records retrieved: %d', len(result.get('data', [])))


class NsfMkdirCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='nsf-mkdir',
            description='Create a new NSF folder using v3 API',
        )
        NsfMkdirCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('folder', type=str,
                        help='Folder name (use "//" to embed a literal "/" in the name)')
        parser.add_argument('--color', type=str,
                        choices=['none', 'red', 'orange', 'yellow', 'green', 'blue', 'gray'],
                        help='Folder color')
        parser.add_argument('--no-inherit', dest='no_inherit_permissions', action='store_true',
                        help='Do not inherit parent folder permissions')

    @staticmethod
    def _parse_path(folder_path: str) -> List[str]:
        """Split *folder_path* into segment names (``//`` → literal ``/`` in a name)."""
        sentinel = '\x00'
        collapsed = folder_path.replace('//', sentinel)
        raw_segments = collapsed.split('/')
        segments = []
        for raw in raw_segments:
            name = raw.replace(sentinel, '/').strip()
            if name:
                segments.append(name)
        if not segments:
            raise base.CommandError('Invalid folder name')
        return segments

    def execute(self, context: KeeperParams, **kwargs):
        vault = _require_vault(context)
        folder_path = (kwargs.get('folder') or '').strip()
        if not folder_path:
            raise base.CommandError('Folder name is required')

        color = kwargs.get('color')
        inherit_permissions = not kwargs.get('no_inherit_permissions', False)

        parent_uid = None
        current_folder = context.current_folder
        if current_folder and nsf_management.is_nsf_folder(vault, current_folder):
            parent_uid = current_folder

        segments = self._parse_path(folder_path)
        last_idx = len(segments) - 1
        created_uid: Optional[str] = None

        for idx, segment in enumerate(segments):
            is_leaf = idx == last_idx
            existing = nsf_management.find_nsf_child_folder(vault, segment, parent_uid)
            if existing:
                if is_leaf:
                    logger.warning('nsf-mkdir: Folder "%s" already exists', segment)
                    return existing
                parent_uid = existing
                continue

            seg_color = color if is_leaf else None
            seg_inherit = inherit_permissions if is_leaf else True

            def _run(name=segment, parent=parent_uid, seg_color=seg_color, seg_inherit=seg_inherit):
                return nsf_management.create_nsf_folder(
                    vault,
                    name,
                    parent_uid=parent,
                    color=seg_color,
                    inherit_permissions=seg_inherit,
                )

            result = _wrap_nsf('nsf-mkdir', _run)
            created_uid = result.folder_uid
            parent_uid = created_uid

        if created_uid:
            logger.info('NSF folder created: %s', created_uid)
        return created_uid


class NsfRndirCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='nsf-rndir',
            description='Rename or recolor an NSF folder',
        )
        NsfRndirCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('-n', '--name', dest='folder_name', action='store', metavar='NAME',
                        help='folder new name')
        parser.add_argument('--color', type=str,
                        choices=['none', 'red', 'orange', 'yellow', 'green', 'blue', 'gray'],
                        help='folder color')
        parser.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                        help='suppress success message')
        parser.add_argument('folder', nargs='?', type=str, help='folder path or UID')

    def execute(self, context: KeeperParams, **kwargs):
        vault = _require_vault(context)
        folder_arg = kwargs.get('folder')
        if not folder_arg:
            raise base.CommandError('Enter the path or UID of existing folder.')

        new_name = kwargs.get('folder_name')
        color = kwargs.get('color')
        if new_name is not None:
            new_name = new_name.strip()
            if not new_name:
                raise base.CommandError('Folder name cannot be empty')
        if new_name is None and color is None:
            raise base.CommandError('New folder name and/or color parameters are required.')

        def _run():
            return nsf_management.update_nsf_folder(
                vault, folder_arg, folder_name=new_name, color=color)

        result = _wrap_nsf('nsf-rndir', _run)
        if not kwargs.get('quiet'):
            display = _folder_name_from_vault(vault, result.folder_uid)
            if new_name:
                logger.info('Folder "%s" has been renamed to "%s"', display, new_name)
            elif color:
                logger.info('Folder "%s" color has been updated', display)
            else:
                logger.info('Folder "%s" has been updated', display)


class NsfRmCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='nsf-rm',
            description='Remove NSF record(s). Supports owner-trash, folder-trash, or unlink.',
        )
        NsfRmCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('records', nargs='+', metavar='RECORD',
                        help='Record UID(s) or title(s) to remove (max 500)')
        parser.add_argument('--folder', dest='folder_uid', metavar='FOLDER',
                        help='Folder UID or name for operation context')
        parser.add_argument('--operation', '-o', dest='operation',
                        choices=['owner-trash', 'folder-trash', 'unlink'], default='owner-trash',
                        help='Removal operation (default: owner-trash)')
        _confirm = parser.add_mutually_exclusive_group()
        _confirm.add_argument('--force', '-f', action='store_true',
                        help='Skip confirmation after preview')
        _confirm.add_argument('--dry-run', dest='dry_run', action='store_true',
                        help='Preview only; do not delete')

    def execute(self, context: KeeperParams, **kwargs):
        vault = _require_vault(context)
        record_args = kwargs.get('records') or []
        operation = kwargs.get('operation', 'owner-trash')
        folder_arg = kwargs.get('folder_uid')
        force = kwargs.get('force', False)
        dry_run = kwargs.get('dry_run', False)

        if not record_args:
            raise base.CommandError('At least one record UID or title is required')
        if operation == 'unlink' and not folder_arg:
            raise base.CommandError('--folder is required when --operation is "unlink"')
        record_limit = 500
        if len(record_args) > record_limit:
            raise base.CommandError('Maximum 500 records per invocation')

        def _build():
            return nsf_management.build_nsf_record_removals(
                vault, record_args,
                operation_type=operation,
                folder_uid=folder_arg,
            )

        removals = _wrap_nsf('nsf-rm', _build)
        self._preview_and_confirm(vault, removals, operation, force, dry_run)

    def _preview_and_confirm(
            self,
            vault,
            removals: List[Dict[str, str]],
            operation: str,
            force: bool,
            dry_run: bool) -> None:
        def _preview():
            return nsf_management.remove_nsf_records(vault, removals, dry_run=True)

        preview: NsfRemoveResult = _wrap_nsf('nsf-rm', _preview)
        any_error = _print_remove_preview_items(
            vault, preview.preview_results,
            item_label='record', operation=operation,
            name_fn=_record_title_from_vault,
        )
        if any_error:
            logger.info('\nOne or more records could not be previewed. Aborting.')
            return
        if dry_run:
            logger.info('\n[Dry-run] No records were deleted.')
            return
        if not _confirm_removal('Do you want to proceed with deletion?', force):
            return

        def _confirm():
            return nsf_management.remove_nsf_records(vault, removals, dry_run=False)

        result = _wrap_nsf('nsf-rm', _confirm)
        if result.confirmed:
            logger.info('Record removal completed.')
        else:
            logger.warning('Record removal was not confirmed by the server.')


class NsfRmdirCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='nsf-rmdir',
            description='Remove NSF folder(s) and their contents',
        )
        NsfRmdirCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('folders', nargs='+', metavar='FOLDER',
                        help='Folder UID(s) or name(s) to remove (max 100)')
        parser.add_argument('--operation', '-o', dest='operation',
                        choices=['folder-trash', 'delete-permanent'], default='folder-trash',
                        help='Removal operation (default: folder-trash)')
        parser.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                        help='Suppress per-folder impact detail')
        _confirm = parser.add_mutually_exclusive_group()
        _confirm.add_argument('--force', '-f', action='store_true',
                        help='Skip confirmation after preview')
        _confirm.add_argument('--dry-run', dest='dry_run', action='store_true',
                        help='Preview only; do not delete')

    def execute(self, context: KeeperParams, **kwargs):
        vault = _require_vault(context)
        folder_args = kwargs.get('folders') or []
        operation = kwargs.get('operation', 'folder-trash')
        force = kwargs.get('force', False)
        dry_run = kwargs.get('dry_run', False)
        quiet = kwargs.get('quiet', False)

        if not folder_args:
            raise base.CommandError('Enter the name or UID of at least one folder.')
        folder_limit = 100
        if len(folder_args) > folder_limit:
            raise base.CommandError('Maximum 100 folders per invocation')

        removals: List[Dict[str, str]] = []
        for identifier in folder_args:
            folder_uid = nsf_management.resolve_nsf_folder_uid(vault, identifier)
            if not folder_uid:
                raise base.CommandError(f'Folder "{identifier}" not found')
            removals.append({'folder_uid': folder_uid, 'operation_type': operation})

        if operation == 'delete-permanent' and not force and not dry_run:
            logger.info(
                '\n  *** WARNING ***\n'
                '  --operation delete-permanent is IRREVERSIBLE.\n'
                '  All sub-folders and records inside will be permanently destroyed.\n')

        self._preview_and_confirm(vault, removals, operation, force, dry_run, quiet)

    def _preview_and_confirm(
            self,
            vault,
            removals: List[Dict[str, str]],
            operation: str,
            force: bool,
            dry_run: bool,
            quiet: bool) -> None:
        def _preview():
            return nsf_management.remove_nsf_folders(vault, removals, dry_run=True)

        preview: NsfRemoveResult = _wrap_nsf('nsf-rmdir', _preview)
        any_error = _print_remove_preview_items(
            vault, preview.preview_results,
            item_label='folder', operation=operation,
            name_fn=_folder_name_from_vault,
            quiet=quiet,
        )
        if any_error:
            prefix = '[Dry-run] ' if dry_run else ''
            logger.info(f"\n{prefix}The following folder(s) cannot be removed:")
            logger.info('\nAborting — fix the errors above before retrying.')
            return
        if dry_run:
            logger.info('\n[Dry-run] No folders were deleted.')
            return
        prompt = (
            'Do you want to permanently delete the folder(s) and all their contents?'
            if operation == 'delete-permanent'
            else 'Do you want to proceed with the folder deletion?'
        )
        if not _confirm_removal(prompt, force):
            return

        def _confirm():
            return nsf_management.remove_nsf_folders(vault, removals, dry_run=False)

        result = _wrap_nsf('nsf-rmdir', _confirm)
        if result.confirmed:
            logger.info('Folder removal completed.')
        else:
            logger.warning('Folder removal was not confirmed by the server.')


class NsfLnCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='nsf-ln',
            description='Link an NSF record into a folder (RECORD FOLDER)',
        )
        NsfLnCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('src', type=str, help='record UID or title')
        parser.add_argument('dst', type=str, help='destination folder UID or name')

    def execute(self, context: KeeperParams, **kwargs):
        vault = _require_vault(context)
        src, dst = kwargs.get('src'), kwargs.get('dst')
        if not src or not dst:
            raise base.CommandError('Both record and folder arguments are required')

        def _run():
            return nsf_folder_records.link_nsf_record_to_folder(vault, src, dst)

        result = _wrap_nsf('nsf-ln', _run)
        logger.info('Record %s linked to folder %s', result.record_uid, result.folder_uid)


class NsfShareFolderCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='nsf-share-folder',
            description='Change sharing permissions of an NSF folder',
        )
        NsfShareFolderCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('-a', '--action', dest='action', choices=['grant', 'remove'],
                        default='grant', help='grant (default) or remove access')
        parser.add_argument('-e', '--email', dest='user', action='append', metavar='USER',
                        help='email, team name/UID, or @existing for all folder accessors')
        parser.add_argument('-r', '--role', dest='role',
                        choices=['viewer', 'share-manager', 'content-manager', 'content-share-manager', 'full-manager'],
                        default='viewer',
                    )
        parser.add_argument('folder', nargs='+', type=str, help='folder UID or name')
        _expire = parser.add_mutually_exclusive_group()
        _expire.add_argument('--expire-at', dest='expire_at', metavar='TIMESTAMP')
        _expire.add_argument('--expire-in', dest='expire_in', metavar='PERIOD')

    def execute(self, context: KeeperParams, **kwargs):
        vault = _require_vault(context)
        folders = kwargs.get('folder') or []
        recipients = kwargs.get('user') or []
        action = kwargs.get('action') or 'grant'
        if not folders:
            raise base.CommandError('Folder path or UID is required')
        if not recipients:
            raise base.CommandError('Recipient is required (use -e/--email)')

        expiration = None
        if action == 'grant':
            try:
                expiration = parse_nsf_share_expiration(kwargs.get('expire_at'), kwargs.get('expire_in'))
            except Exception as e:
                raise base.CommandError(str(e)) from e

        for folder_arg in folders:
            targets = self._collect_targets(vault, recipients, folder_arg, context)
            for recipient, is_team in targets:
                def _run(rec=recipient, team=is_team, f=folder_arg):
                    if action == 'remove':
                        return nsf_sharing.revoke_nsf_folder_access(
                            vault, f, rec, as_team=team)
                    return nsf_sharing.grant_nsf_folder_access(
                        vault, f, rec, role=kwargs.get('role') or 'viewer',
                        expiration_timestamp=expiration, as_team=team)

                result = _wrap_nsf('nsf-share-folder', _run)
                logger.info('%s: %s', recipient, result.get('message', result.get('status')))

    @classmethod
    def _collect_targets(cls, vault, recipients, folder_arg, context):
        targets: List[tuple] = []
        seen: set = set()
        for raw in recipients:
            if raw in ('@existing', '@current'):
                access = nsf_management.get_nsf_folder_access(vault, [
                    nsf_management.resolve_nsf_folder_uid(vault, folder_arg) or folder_arg])
                for fr in access.get('results') or []:
                    if not fr.get('success'):
                        continue
                    for a in fr.get('accessors') or []:
                        username = a.get('username')
                        if username and username != context.auth.login:
                            key = ('user', username.casefold())
                            if key not in seen:
                                seen.add(key)
                                targets.append((username, False))
                continue
            if '@' in raw:
                is_team = False
            else:
                teams = share_management_utils.get_share_objects(vault).get('teams', {})
                is_team = (
                    raw in teams
                    or any((info.get('name') or '').casefold() == raw.casefold()
                           for info in teams.values())
                )
            key = ('team' if is_team else 'user', raw.casefold())
            if key not in seen:
                seen.add(key)
                targets.append((raw, is_team))
        return targets


class NsfShareRecordCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='nsf-share-record',
            description='Change sharing permissions of an NSF record',
        )
        NsfShareRecordCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('record', nargs='?', type=str, help='record UID, title, or folder')
        parser.add_argument(
            '-e', '--email', dest='email', action='append', required=True,
            help='recipient email (repeatable)',
        )
        parser.add_argument(
            '-a', '--action', dest='action', choices=['grant', 'revoke', 'owner'], default='grant',
        )
        parser.add_argument(
            '-r', '--role', dest='role',
            choices=['viewer', 'share-manager', 'content-manager', 'content-share-manager', 'full-manager'],
        )
        parser.add_argument('-R', '--recursive', dest='recursive', action='store_true')
        parser.add_argument('--dry-run', dest='dry_run', action='store_true')
        _expire = parser.add_mutually_exclusive_group()
        _expire.add_argument('--expire-at', dest='expire_at', metavar='EXPIRE_AT')
        _expire.add_argument('--expire-in', dest='expire_in', metavar='PERIOD')

    def execute(self, context: KeeperParams, **kwargs):
        vault = _require_vault(context)
        record_arg = kwargs.get('record')
        emails = kwargs.get('email') or []
        action = kwargs.get('action') or 'grant'
        if not record_arg:
            raise base.CommandError('Record path or UID is required')
        if action == 'owner' and len(emails) > 1:
            raise base.CommandError('Ownership can only be transferred to a single account')
        if action == 'grant' and not kwargs.get('role'):
            raise base.CommandError('Role is required for grant action')

        expiration = None
        if action == 'grant':
            try:
                expiration = parse_nsf_share_expiration(kwargs.get('expire_at'), kwargs.get('expire_in'))
            except Exception as e:
                raise base.CommandError(str(e)) from e

        record_uids = _wrap_nsf(
            'nsf-share-record',
            lambda: nsf_sharing.resolve_nsf_share_record_uids(
                vault, record_arg, recursive=kwargs.get('recursive', False)))

        if kwargs.get('dry_run'):
            logger.info(f'[dry-run] Action: {action.upper()}')
            logger.info(f'[dry-run] Records: {", ".join(record_uids)}')
            logger.info(f'[dry-run] Recipients: {", ".join(emails)}')
            return

        for email in emails:
            for record_uid in record_uids:
                def _run(uid=record_uid, em=email):
                    return nsf_sharing.share_nsf_record_with_action(
                        vault, uid, em, action=action, role=kwargs.get('role'),
                        expiration_timestamp=expiration)

                result, effective = _wrap_nsf('nsf-share-record', _run)
                if effective == 'owner' and result.success:
                    logger.info("Record '%s' ownership transferred to '%s'", record_uid, email)
                    logger.warning('You will no longer have access to this record!')
                elif result.success:
                    logger.info('Record %s permissions %s for %s', record_uid, effective, email)
                else:
                    msg = result.results[0]['message'] if result.results else 'failed'
                    logger.error('Share failed for %s: %s', record_uid, msg)


class NsfRecordPermissionCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='nsf-record-permission',
            description='Bulk-update NSF record permissions within a folder',
        )
        NsfRecordPermissionCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('--dry-run', dest='dry_run', action='store_true')
        parser.add_argument('-f', '--force', dest='force', action='store_true')
        parser.add_argument('-R', '--recursive', dest='recursive', action='store_true')
        parser.add_argument('-a', '--action', dest='action', choices=['grant', 'revoke'], required=True)
        parser.add_argument(
            '-r', '--role', dest='role',
            choices=['viewer', 'share-manager', 'content-manager', 'content-share-manager', 'full-manager'],
        )
        parser.add_argument('folder', nargs='?', type=str, help='folder UID or name')

    def execute(self, context: KeeperParams, **kwargs):
        vault = _require_vault(context)
        action = kwargs.get('action')
        role = kwargs.get('role')
        if action == 'grant' and not role:
            raise base.CommandError('Role is required for grant action')

        login = context.auth.auth_context.username if context.auth and context.auth.auth_context else ''
        plan = _wrap_nsf(
            'nsf-record-permission',
            lambda: nsf_sharing.plan_nsf_record_permissions(
                vault, kwargs.get('folder'), action=action, role=role,
                recursive=kwargs.get('recursive', False), current_user=login))

        if not plan.updates and not plan.creates and not plan.revokes and not plan.denies:
            if plan.skipped:
                logger.warning('No permission changes can be made (see skipped entries).')
            else:
                logger.info('No permission changes are needed.')
            return

        if kwargs.get('dry_run') or not kwargs.get('force'):
            self._print_plan(plan)
        if kwargs.get('dry_run'):
            return
        if not kwargs.get('force'):
            if not _confirm_removal('Do you want to proceed with these permission changes?', False):
                return

        outcomes = _wrap_nsf(
            'nsf-record-permission',
            lambda: nsf_sharing.apply_nsf_record_permissions(vault, plan))
        for bucket, rows in outcomes.items():
            for item, result in rows:
                if result.get('success'):
                    logger.info('%s %s %s: ok', bucket, item.get('record_uid'), item.get('email'))
                elif not result.get('skipped'):
                    logger.warning('%s %s %s: %s', bucket, item.get('record_uid'),
                                     item.get('email'), result.get('message'))

    @staticmethod
    def _print_plan(plan) -> None:
        for label, items in (
                ('SKIP', plan.skipped), ('GRANT/UPDATE', plan.updates + plan.creates),
                ('REVOKE', plan.revokes), ('DENY INHERITED', plan.denies)):
            if not items:
                continue
            logger.info(f'\n{label}:')
            for item in items:
                line = f"  {item.get('record_uid')} {item.get('email', '')} {item.get('cur_role', '')}"
                if item.get('new_role'):
                    line += f" -> {item['new_role']}"
                if item.get('reason'):
                    line += f" ({item['reason']})"
                logger.info(line)


class NsfTransferRecordCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='nsf-transfer-record',
            description='Transfer NSF record ownership to another user',
        )
        NsfTransferRecordCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('record_uids', nargs='+', type=str, help='record UID(s) or title(s)')
        parser.add_argument('new_owner_email', type=str, help='new owner email')

    def execute(self, context: KeeperParams, **kwargs):
        vault = _require_vault(context)
        identifiers = kwargs.get('record_uids') or []
        new_owner = kwargs.get('new_owner_email')
        if not identifiers or not new_owner:
            raise base.CommandError('Record UID(s) and new owner email are required')

        for identifier in identifiers:
            def _run(uid=identifier):
                return nsf_sharing.transfer_nsf_record_ownership(vault, uid, new_owner)

            result = _wrap_nsf('nsf-transfer-record', _run)
            for row in result.results:
                if row.get('success'):
                    logger.info("Record '%s' transferred to %s", row['record_uid'], new_owner)
                    logger.warning('You will no longer have access to this record!')
                else:
                    logger.error('Transfer failed: %s', row.get('message'))


class NsfShortcutListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='nsf-shortcut list',
            description='List NSF records linked to multiple folders',
        )
        NsfShortcutListCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('target', nargs='?', type=str, help='optional record or folder filter')
        parser.add_argument('--format', dest='format', choices=['table', 'csv', 'json'], default='table')
        parser.add_argument('--output', dest='output', type=str)

    def execute(self, context: KeeperParams, **kwargs):
        vault = _require_vault(context)
        fmt = kwargs.get('format', 'table')

        def _run():
            return nsf_folder_records.list_nsf_shortcuts(vault, target=kwargs.get('target'))

        rows = _wrap_nsf('nsf-shortcut list', _run)
        if not rows:
            logger.info('No NSF shortcut records found')
            return

        view = vault.nsf_data
        table = []
        for row in rows:
            if fmt == 'json':
                folders = [
                    {'folder_uid': fuid,
                     'name': (view.get_folder(fuid).name if view and view.get_folder(fuid) else fuid)}
                    for fuid in row.folder_uids
                ]
                table.append([row.record_uid, row.title, folders])
            else:
                names = []
                for fuid in row.folder_uids:
                    fname = view.get_folder(fuid).name if view and view.get_folder(fuid) else fuid
                    names.append(f'{fname} ({fuid})')
                table.append([row.record_uid, row.title, names])

        headers = ['Record UID', 'Record Title', 'Folders']
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(
            table, headers, fmt=fmt, filename=kwargs.get('output'), row_number=True, column_width=40)


class NsfShortcutKeepCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='nsf-shortcut keep',
            description='Keep an NSF record in one folder only',
        )
        NsfShortcutKeepCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('target', type=str, help='record UID or title')
        parser.add_argument('folder', nargs='?', type=str, help='folder to keep (default: current)')
        parser.add_argument('-f', '--force', dest='force', action='store_true')

    def execute(self, context: KeeperParams, **kwargs):
        vault = _require_vault(context)
        target = kwargs.get('target')
        folder_arg = kwargs.get('folder')
        if not target:
            raise base.CommandError('Record UID or title is required')
        if not folder_arg:
            if context.current_folder and nsf_management.is_nsf_folder(vault, context.current_folder):
                folder_arg = context.current_folder
            else:
                raise base.CommandError('No folder specified and current folder is not an NSF folder')

        shortcuts = nsf_folder_records.get_nsf_shortcut_map(vault)
        record_uid = nsf_management.resolve_nsf_record_uid(vault, target)
        if not record_uid:
            raise base.CommandError(f'Record "{target}" not found')
        keep_folder = nsf_management.resolve_nsf_folder_uid(vault, folder_arg) or folder_arg
        to_remove = [f for f in shortcuts.get(record_uid, set()) if f != keep_folder]
        if not to_remove:
            logger.info('Nothing to do — record is already in only one folder.')
            return
        if not kwargs.get('force'):
            logger.info(f'Will keep record in {folder_arg} and remove from {len(to_remove)} other folder(s).')
            if not _confirm_removal('Do you want to proceed?', False):
                return

        def _run():
            return nsf_folder_records.keep_nsf_shortcut_in_folder(vault, target, folder_arg)

        results = _wrap_nsf('nsf-shortcut keep', _run)
        logger.info('Removed record from %d folder link(s).', len(results))


class NsfShortcutCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('Manage NSF record shortcuts (multi-folder links)')
        self.register_command(NsfShortcutListCommand(), 'list')
        self.register_command(NsfShortcutKeepCommand(), 'keep')
        self.default_verb = 'list'

