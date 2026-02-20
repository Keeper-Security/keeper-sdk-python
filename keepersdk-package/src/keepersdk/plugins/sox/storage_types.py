"""SOX Storage Types for Compliance Reporting."""

from dataclasses import dataclass


@dataclass
class Metadata:
    """Metadata tracking cache timestamps."""
    account_uid: str = ''
    prelim_data_last_update: int = 0
    records_dated: int = 0
    last_pw_audit: int = 0
    compliance_data_last_update: int = 0
    shared_records_only: bool = False


@dataclass
class StorageUser:
    """Enterprise user information."""
    user_uid: int = 0
    email: bytes = b''
    status: int = 0
    job_title: bytes = b''
    full_name: bytes = b''
    node_id: int = 0


@dataclass
class StorageRecord:
    """Record information."""
    record_uid: str = ''
    record_uid_bytes: bytes = b''
    encrypted_data: bytes = b''
    shared: bool = False
    in_trash: bool = False
    has_attachments: bool = False


@dataclass
class StorageRecordAging:
    """Record aging/lifecycle data."""
    record_uid: str = ''
    created: int = 0
    last_pw_change: int = 0
    last_modified: int = 0
    last_rotation: int = 0


@dataclass
class StorageUserRecordLink:
    """Link users to records they own."""
    record_uid: str = ''
    user_uid: int = 0


@dataclass
class StorageTeam:
    """Enterprise team information."""
    team_uid: str = ''
    team_name: str = ''
    restrict_edit: bool = False
    restrict_share: bool = False


@dataclass
class StorageTeamUserLink:
    """Link teams to member users."""
    team_uid: str = ''
    user_uid: int = 0


@dataclass
class StorageRole:
    """Enterprise role information."""
    role_id: int = 0
    encrypted_data: bytes = b''
    restrict_share_outside_enterprise: bool = False
    restrict_share_all: bool = False
    restrict_share_of_attachments: bool = False
    restrict_mask_passwords_while_editing: bool = False


@dataclass
class StorageRecordPermissions:
    """User permissions on records."""
    record_uid: str = ''
    user_uid: int = 0
    permissions: int = 0


@dataclass
class StorageSharedFolderRecordLink:
    """Link shared folders to records."""
    folder_uid: str = ''
    record_uid: str = ''
    permissions: int = 0


@dataclass
class StorageSharedFolderUserLink:
    """Link shared folders to users."""
    folder_uid: str = ''
    user_uid: int = 0


@dataclass
class StorageSharedFolderTeamLink:
    """Link shared folders to teams."""
    folder_uid: str = ''
    team_uid: str = ''


@dataclass
class StorageSharedFolder:
    """Shared folder information."""
    folder_uid: str = ''
    folder_name: str = ''
    encrypted_data: bytes = b''
