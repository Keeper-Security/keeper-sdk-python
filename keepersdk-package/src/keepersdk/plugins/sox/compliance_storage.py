"""SQLite Storage for Compliance Data."""

import datetime
import logging
import os
import sqlite3
import threading
from typing import Callable, Optional

from ... import sqlite_dao
from ...storage import sqlite

from . import storage_types


logger = logging.getLogger(__name__)


class SqliteComplianceStorage:
    """SQLite storage for compliance reporting with full caching support."""
    
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], enterprise_id: int, owner: str = '') -> None:
        self.get_connection = get_connection
        self.enterprise_id = enterprise_id
        self.database_name = None
        self.close_connection = None
        
        metadata_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.Metadata, 'account_uid')
        
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
        
        sqlite_dao.verify_database(
            self.get_connection(),
            (metadata_schema, user_schema, record_schema, record_aging_schema,
             user_record_schema, team_schema, team_user_schema, role_schema,
             record_permissions_schema, shared_folder_record_schema,
             shared_folder_user_schema, shared_folder_team_schema,
             shared_folder_schema))
        
        self._metadata = sqlite.SqliteEntityStorage(self.get_connection, metadata_schema)
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
        # Use a fixed key for the singleton metadata record
        history = self._metadata.get_entity('_default_')
        if history is None:
            history = storage_types.Metadata()
            history.account_uid = '_default_'
        return history
    
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
    
    def set_prelim_data_updated(self, ts: Optional[int] = None) -> None:
        """Mark preliminary data as updated."""
        ts = int(datetime.datetime.now().timestamp()) if ts is None else ts
        history = self._get_history()
        history.prelim_data_last_update = ts
        self._metadata.put_entities([history])
    
    def set_compliance_data_updated(self, ts: Optional[int] = None) -> None:
        """Mark compliance data as updated."""
        ts = int(datetime.datetime.now().timestamp()) if ts is None else ts
        history = self._get_history()
        history.compliance_data_last_update = ts
        self._metadata.put_entities([history])
    
    def set_records_dated(self, ts: int) -> None:
        """Set records dated timestamp."""
        history = self._get_history()
        history.records_dated = ts
        self._metadata.put_entities([history])
    
    def set_last_pw_audit(self, ts: int) -> None:
        """Set last password audit timestamp."""
        history = self._get_history()
        history.last_pw_audit = ts
        self._metadata.put_entities([history])
    
    def set_shared_records_only(self, value: bool) -> None:
        """Set shared records only flag."""
        history = self._get_history()
        history.shared_records_only = value
        self._metadata.put_entities([history])
    
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
    
    The database file is placed in the directory of config_path as compliance_{enterprise_id}.db.
    config_path should be a trusted path (e.g. application config file path).
    
    Args:
        config_path: Path to config file directory
        enterprise_id: Enterprise ID
        
    Returns:
        Full path to the compliance database file
    """
    path = os.path.dirname(os.path.abspath(config_path or ''))
    return os.path.join(path, f'compliance_{enterprise_id}.db')


# Module-level connection cache to ensure single connection per database (thread-safe)
_connection_cache: dict[str, sqlite3.Connection] = {}
_connection_cache_lock = threading.Lock()


def get_cached_connection(database_name: str) -> sqlite3.Connection:
    """Get or create a cached connection for the given database (thread-safe).
    
    Args:
        database_name: Full path to the database file
        
    Returns:
        SQLite connection object
    """
    with _connection_cache_lock:
        if database_name not in _connection_cache:
            _connection_cache[database_name] = sqlite3.connect(database_name)
        return _connection_cache[database_name]


def close_cached_connection(database_name: str) -> None:
    """Close and remove a cached connection (thread-safe).
    
    Args:
        database_name: Full path to the database file
    """
    with _connection_cache_lock:
        if database_name not in _connection_cache:
            return
        try:
            _connection_cache[database_name].close()
        except sqlite3.Error as e:
            logger.debug('Error closing cached connection for %s: %s', database_name, e)
        del _connection_cache[database_name]
