"""SQLite Storage for Compliance Data."""

import datetime
import logging
import os
import sqlite3
from typing import Callable, Optional

from keepersdk import sqlite_dao
from keepersdk.storage import sqlite

from . import storage_types


logger = logging.getLogger(__name__)


class SqliteComplianceStorage:
    """SQLite storage for compliance reporting with full caching support."""
    
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], enterprise_id: int, owner: str = '') -> None:
        self.get_connection = get_connection
        self.enterprise_id = enterprise_id
        self.database_name = None
        self.close_connection = None
        
        # Schema definitions for all 12 tables
        metadata_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.Metadata, [], owner_column='account_uid')
        
        user_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageUser, 'user_uid')
        
        record_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageRecord, 'record_uid')
        
        record_aging_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageRecordAging, 'record_uid')
        
        user_record_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageUserRecordLink,
            ['record_uid', 'user_uid'],
            indexes={'UserUID': 'user_uid'})
        
        team_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageTeam, 'team_uid')
        
        team_user_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageTeamUserLink,
            ['team_uid', 'user_uid'],
            indexes={'UserUID': 'user_uid'})
        
        role_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageRole, 'role_id')
        
        record_permissions_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageRecordPermissions,
            ['record_uid', 'user_uid'],
            indexes={'UserUID': 'user_uid'})
        
        shared_folder_record_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageSharedFolderRecordLink,
            ['folder_uid', 'record_uid'],
            indexes={'RecordUID': 'record_uid'})
        
        shared_folder_user_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageSharedFolderUserLink,
            ['folder_uid', 'user_uid'],
            indexes={'UserUID': 'user_uid'})
        
        shared_folder_team_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageSharedFolderTeamLink,
            ['folder_uid', 'team_uid'],
            indexes={'TeamUID': 'team_uid'})
        
        shared_folder_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageSharedFolder, 'folder_uid')
        
        # Verify and create tables
        sqlite_dao.verify_database(
            self.get_connection(),
            (metadata_schema, user_schema, record_schema, record_aging_schema,
             user_record_schema, team_schema, team_user_schema, role_schema,
             record_permissions_schema, shared_folder_record_schema,
             shared_folder_user_schema, shared_folder_team_schema,
             shared_folder_schema))
        
        # Initialize storage objects
        self._metadata = sqlite.SqliteRecordStorage(self.get_connection, metadata_schema, owner)
        self._users = sqlite.SqliteEntityStorage(self.get_connection, user_schema)
        self._records = sqlite.SqliteEntityStorage(self.get_connection, record_schema)
        self._record_aging = sqlite.SqliteEntityStorage(self.get_connection, record_aging_schema)
        self._user_record_links = sqlite.SqliteLinkStorage(self.get_connection, user_record_schema)
        self._teams = sqlite.SqliteEntityStorage(self.get_connection, team_schema)
        self._team_user_links = sqlite.SqliteLinkStorage(self.get_connection, team_user_schema)
        self._roles = sqlite.SqliteEntityStorage(self.get_connection, role_schema)
        self._record_permissions = sqlite.SqliteLinkStorage(self.get_connection, record_permissions_schema)
        self._sf_record_links = sqlite.SqliteLinkStorage(self.get_connection, shared_folder_record_schema)
        self._sf_user_links = sqlite.SqliteLinkStorage(self.get_connection, shared_folder_user_schema)
        self._sf_team_links = sqlite.SqliteLinkStorage(self.get_connection, shared_folder_team_schema)
        self._shared_folders = sqlite.SqliteEntityStorage(self.get_connection, shared_folder_schema)
    
    def _get_history(self) -> storage_types.Metadata:
        """Get or create metadata record."""
        history = self._metadata.get()
        if history is None:
            history = storage_types.Metadata()
            history.account_uid = ''
        return history
    
    # Timestamp properties
    @property
    def last_prelim_data_update(self) -> int:
        """Timestamp of last preliminary data sync."""
        return self._get_history().prelim_data_last_update
    
    @property
    def last_compliance_data_update(self) -> int:
        """Timestamp of last full compliance sync."""
        return self._get_history().compliance_data_last_update
    
    @property
    def records_dated(self) -> int:
        """Timestamp when aging data was last fetched."""
        return self._get_history().records_dated
    
    @property
    def last_pw_audit(self) -> int:
        """Timestamp of last password audit."""
        return self._get_history().last_pw_audit
    
    @property
    def shared_records_only(self) -> bool:
        """Flag indicating if only shared records cached."""
        return self._get_history().shared_records_only
    
    # Update methods
    def set_prelim_data_updated(self, ts: Optional[int] = None) -> None:
        """Mark preliminary data as updated."""
        ts = int(datetime.datetime.now().timestamp()) if ts is None else ts
        history = self._get_history()
        history.prelim_data_last_update = ts
        self._metadata.store(history)
    
    def set_compliance_data_updated(self, ts: Optional[int] = None) -> None:
        """Mark compliance data as updated."""
        ts = int(datetime.datetime.now().timestamp()) if ts is None else ts
        history = self._get_history()
        history.compliance_data_last_update = ts
        self._metadata.store(history)
    
    def set_records_dated(self, ts: int) -> None:
        """Set records dated timestamp."""
        history = self._get_history()
        history.records_dated = ts
        self._metadata.store(history)
    
    def set_last_pw_audit(self, ts: int) -> None:
        """Set last password audit timestamp."""
        history = self._get_history()
        history.last_pw_audit = ts
        self._metadata.store(history)
    
    def set_shared_records_only(self, value: bool) -> None:
        """Set shared records only flag."""
        history = self._get_history()
        history.shared_records_only = value
        self._metadata.store(history)
    
    # Storage accessors
    @property
    def users(self):
        return self._users
    
    @property
    def records(self):
        return self._records
    
    @property
    def record_aging(self):
        return self._record_aging
    
    @property
    def user_record_links(self):
        return self._user_record_links
    
    @property
    def teams(self):
        return self._teams
    
    @property
    def team_user_links(self):
        return self._team_user_links
    
    @property
    def roles(self):
        return self._roles
    
    @property
    def record_permissions(self):
        return self._record_permissions
    
    @property
    def sf_record_links(self):
        return self._sf_record_links
    
    @property
    def sf_user_links(self):
        return self._sf_user_links
    
    @property
    def sf_team_links(self):
        return self._sf_team_links
    
    @property
    def shared_folders(self):
        return self._shared_folders
    
    # Clear methods
    def clear_aging_data(self) -> None:
        """Clear only aging data."""
        self._record_aging.delete_all()
        self.set_records_dated(0)
        self.set_last_pw_audit(0)
    
    def clear_non_aging_data(self) -> None:
        """Clear all data except aging."""
        self._records.delete_all()
        self._users.delete_all()
        self._user_record_links.delete_all()
        self._teams.delete_all()
        self._roles.delete_all()
        self._sf_team_links.delete_all()
        self._sf_user_links.delete_all()
        self._sf_record_links.delete_all()
        self._team_user_links.delete_all()
        self._record_permissions.delete_all()
        self._shared_folders.delete_all()
        self.set_prelim_data_updated(0)
        self.set_compliance_data_updated(0)
    
    def clear_all(self) -> None:
        """Clear everything including metadata."""
        self.clear_non_aging_data()
        self._record_aging.delete_all()
        self._metadata.delete_all()
    
    def delete_db(self) -> None:
        """Completely remove the database file."""
        try:
            if self.close_connection:
                self.close_connection()
            else:
                conn = self.get_connection()
                conn.close()
            if self.database_name and os.path.isfile(self.database_name):
                os.remove(self.database_name)
        except Exception as e:
            logger.info(f'Could not delete db from filesystem, name = {self.database_name}')
            logger.info(f'Exception: {e}')


def get_compliance_database_name(config_path: str, enterprise_id: int) -> str:
    """Get the compliance database file path.
    
    Args:
        config_path: Path to config file directory
        enterprise_id: Enterprise ID
        
    Returns:
        Full path to the compliance database file
    """
    path = os.path.dirname(os.path.abspath(config_path or ''))
    return os.path.join(path, f'compliance_{enterprise_id}.db')


# Module-level connection cache to ensure single connection per database
_connection_cache = {}  # type: dict[str, sqlite3.Connection]


def get_cached_connection(database_name: str) -> sqlite3.Connection:
    """Get or create a cached connection for the given database."""
    if database_name not in _connection_cache:
        _connection_cache[database_name] = sqlite3.connect(database_name)
    return _connection_cache[database_name]


def close_cached_connection(database_name: str) -> None:
    """Close and remove a cached connection."""
    if database_name in _connection_cache:
        try:
            _connection_cache[database_name].close()
        except Exception:
            pass
        del _connection_cache[database_name]
