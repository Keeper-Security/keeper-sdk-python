import dataclasses
from typing import List, Dict, Tuple, Sequence

# MSP Constants
MSP_FILE_PLANS = [
    (4, 'STORAGE_100GB', '100GB'),
    (7, 'STORAGE_1000GB', '1TB'),
    (8, 'STORAGE_10000GB', '10TB'),
]
MSP_PLANS = [
    (1, 'business', 'Business', 4),
    (2, 'businessPlus', 'Business Plus', 7),
    (10, 'enterprise', 'Enterprise', 4),
    (11, 'enterprisePlus', 'Enterprise Plus', 7),
]
MSP_ADDONS = [
    ('enterprise_breach_watch', 'BreachWatch', False, 'BreachWatch'),
    ('compliance_report', 'Compliance Reporting', False, 'Compliance'),
    ('enterprise_audit_and_reporting', 'Advanced Reporting & Alerts Module', False, 'ARAM'),
    ('onboarding_and_certificate', 'Dedicated Service & Support', False, 'Support'),
    ('msp_service_and_support', 'MSP Dedicated Service & Support', False, 'MSP Support'),
    ('secrets_manager', 'Keeper Secrets Manager (KSM)', False, 'Secrets Manager'),
    ('connection_manager', 'Keeper Connection Manager (KCM)', True, 'Connection Manager'),
    ('chat', 'KeeperChat', False, 'Chat'),
]


# Enforcement constants
ENFORCEMENT_GROUPS: List[str] = [
    "LOGIN_SETTINGS",
    "TWO_FACTOR_AUTHENTICATION",
    "PLATFORM_RESTRICTION",
    "VAULT_FEATURES",
    "RECORD_TYPES",
    "SHARING_AND_UPLOADING",
    "KEEPER_FILL",
    "ACCOUNT_SETTINGS",
    "ALLOW_IP_LIST",
    "ACCOUNT_SETTINGS",
]

@dataclasses.dataclass(frozen=True)
class EnforcementInfo:
    name: str
    id: int
    datatype: str
    group: str

_ENFORCEMENTS: List[EnforcementInfo] = [
    EnforcementInfo(name="MASTER_PASSWORD_MINIMUM_LENGTH", id=10, datatype="LONG", group="LOGIN_SETTINGS"),
    EnforcementInfo(name="MASTER_PASSWORD_MINIMUM_SPECIAL", id=11, datatype="LONG", group="LOGIN_SETTINGS"),
    EnforcementInfo(name="MASTER_PASSWORD_MINIMUM_UPPER", id=12, datatype="LONG", group="LOGIN_SETTINGS"),
    EnforcementInfo(name="MASTER_PASSWORD_MINIMUM_LOWER", id=13, datatype="LONG", group="LOGIN_SETTINGS"),
    EnforcementInfo(name="MASTER_PASSWORD_MINIMUM_DIGITS", id=14, datatype="LONG", group="LOGIN_SETTINGS"),
    EnforcementInfo(name="MASTER_PASSWORD_RESTRICT_DAYS_BEFORE_REUSE", id=16, datatype="LONG", group="LOGIN_SETTINGS"),
    EnforcementInfo(name="REQUIRE_TWO_FACTOR", id=20, datatype="BOOLEAN", group="TWO_FACTOR_AUTHENTICATION"),
    EnforcementInfo(name="MASTER_PASSWORD_MAXIMUM_DAYS_BEFORE_CHANGE", id=22, datatype="LONG", group="LOGIN_SETTINGS"),
    EnforcementInfo(name="MASTER_PASSWORD_EXPIRED_AS_OF", id=23, datatype="LONG", group="LOGIN_SETTINGS"),
    EnforcementInfo(name="MINIMUM_PBKDF2_ITERATIONS", id=55, datatype="LONG", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="MAX_SESSION_LOGIN_TIME", id=24, datatype="LONG", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="RESTRICT_PERSISTENT_LOGIN", id=25, datatype="BOOLEAN", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="STAY_LOGGED_IN_DEFAULT", id=26, datatype="BOOLEAN", group="ACCOUNT_ENFORCEMENTS"),
    EnforcementInfo(name="RESTRICT_SHARING_ALL", id=30, datatype="BOOLEAN", group="SHARING_AND_UPLOADING"),
    EnforcementInfo(name="RESTRICT_SHARING_ENTERPRISE", id=31, datatype="BOOLEAN", group="SHARING_AND_UPLOADING"),
    EnforcementInfo(name="RESTRICT_EXPORT", id=32, datatype="BOOLEAN", group="SHARING_AND_UPLOADING"),
    EnforcementInfo(name="RESTRICT_IMPORT", id=111, datatype="BOOLEAN", group="SHARING_AND_UPLOADING"),
    EnforcementInfo(name="RESTRICT_FILE_UPLOAD", id=33, datatype="BOOLEAN", group="SHARING_AND_UPLOADING"),
    EnforcementInfo(name="REQUIRE_ACCOUNT_SHARE", id=34, datatype="ACCOUNT_SHARE", group="SHARING_AND_UPLOADING"),
    EnforcementInfo(name="RESTRICT_SHARING_INCOMING_ALL", id=36, datatype="BOOLEAN", group="SHARING_AND_UPLOADING"),
    EnforcementInfo(name="RESTIRCT_SHARING_RECORD_AND_FOLDER", id=120, datatype="BOOLEAN", group="SHARING_AND_UPLOADING"),
    EnforcementInfo(name="RESTRICT_SHARING_RECORD_WITH_ATTACHMENTS", id=121, datatype="BOOLEAN", group="SHARING_AND_UPLOADING"),
    EnforcementInfo(name="RESTRICT_IP_ADDRESSES", id=40, datatype="IP_WHITELIST", group="ALLOW_IP_LIST"),
    EnforcementInfo(name="REQUIRE_DEVICE_APPROVAL", id=41, datatype="BOOLEAN", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="REQUIRE_ACCOUNT_RECOVERY_APPROVAL", id=42, datatype="BOOLEAN", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="RESTRICT_VAULT_IP_ADDRESSES", id=43, datatype="IP_WHITELIST", group="ALLOW_IP_LIST"),
    EnforcementInfo(name="TIP_ZONE_RESTRICT_ALLOWED_IP_RANGES", id=44, datatype="IP_WHITELIST", group="ALLOW_IP_LIST"),
    EnforcementInfo(name="AUTOMATIC_BACKUP_EVERY_X_DAYS", id=45, datatype="LONG", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="RESTRICT_OFFLINE_ACCESS", id=46, datatype="BOOLEAN", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="SEND_INVITE_AT_REGISTRATION", id=47, datatype="BOOLEAN", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="RESTRICT_EMAIL_CHANGE", id=48, datatype="BOOLEAN", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="RESTRICT_IOS_FINGERPRINT", id=49, datatype="BOOLEAN", group="LOGIN_SETTINGS"),
    EnforcementInfo(name="RESTRICT_MAC_FINGERPRINT", id=50, datatype="BOOLEAN", group="LOGIN_SETTINGS"),
    EnforcementInfo(name="RESTRICT_ANDROID_FINGERPRINT", id=51, datatype="BOOLEAN", group="LOGIN_SETTINGS"),
    EnforcementInfo(name="RESTRICT_WINDOWS_FINGERPRINT", id=83, datatype="BOOLEAN", group="LOGIN_SETTINGS"),
    EnforcementInfo(name="LOGOUT_TIMER_WEB", id=52, datatype="LONG", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="LOGOUT_TIMER_MOBILE", id=53, datatype="LONG", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="LOGOUT_TIMER_DESKTOP", id=54, datatype="LONG", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="RESTRICT_WEB_VAULT_ACCESS", id=60, datatype="BOOLEAN", group="PLATFORM_RESTRICTION"),
    EnforcementInfo(name="RESTRICT_EXTENSIONS_ACCESS", id=61, datatype="BOOLEAN", group="PLATFORM_RESTRICTION"),
    EnforcementInfo(name="RESTRICT_MOBILE_ACCESS", id=62, datatype="BOOLEAN", group="PLATFORM_RESTRICTION"),
    EnforcementInfo(name="RESTRICT_DESKTOP_ACCESS", id=63, datatype="BOOLEAN", group="PLATFORM_RESTRICTION"),
    EnforcementInfo(name="RESTRICT_MOBILE_IOS_ACCESS", id=64, datatype="BOOLEAN", group="PLATFORM_RESTRICTION"),
    EnforcementInfo(name="RESTRICT_MOBILE_ANDROID_ACCESS", id=65, datatype="BOOLEAN", group="PLATFORM_RESTRICTION"),
    EnforcementInfo(name="RESTRICT_MOBILE_WINDOWS_PHONE_ACCESS", id=66, datatype="BOOLEAN", group="PLATFORM_RESTRICTION"),
    EnforcementInfo(name="RESTRICT_DESKTOP_WIN_ACCESS", id=67, datatype="BOOLEAN", group="PLATFORM_RESTRICTION"),
    EnforcementInfo(name="RESTRICT_DESKTOP_MAC_ACCESS", id=68, datatype="BOOLEAN", group="PLATFORM_RESTRICTION"),
    EnforcementInfo(name="RESTRICT_CHAT_DESKTOP_ACCESS", id=84, datatype="BOOLEAN", group="PLATFORM_RESTRICTION"),
    EnforcementInfo(name="RESTRICT_CHAT_MOBILE_ACCESS", id=85, datatype="BOOLEAN", group="PLATFORM_RESTRICTION"),
    EnforcementInfo(name="RESTRICT_COMMANDER_ACCESS", id=88, datatype="BOOLEAN", group="PLATFORM_RESTRICTION"),
    EnforcementInfo(name="RESTRICT_TWO_FACTOR_CHANNEL_TEXT", id=70, datatype="BOOLEAN", group="TWO_FACTOR_AUTHENTICATION"),
    EnforcementInfo(name="RESTRICT_TWO_FACTOR_CHANNEL_GOOGLE", id=71, datatype="BOOLEAN", group="TWO_FACTOR_AUTHENTICATION"),
    EnforcementInfo(name="RESTRICT_TWO_FACTOR_CHANNEL_DNA", id=72, datatype="BOOLEAN", group="TWO_FACTOR_AUTHENTICATION"),
    EnforcementInfo(name="RESTRICT_TWO_FACTOR_CHANNEL_DUO", id=73, datatype="BOOLEAN", group="TWO_FACTOR_AUTHENTICATION"),
    EnforcementInfo(name="RESTRICT_TWO_FACTOR_CHANNEL_RSA", id=74, datatype="BOOLEAN", group="TWO_FACTOR_AUTHENTICATION"),
    EnforcementInfo(name="TWO_FACTOR_DURATION_WEB", id=80, datatype="TWO_FACTOR_DURATION", group="TWO_FACTOR_AUTHENTICATION"),
    EnforcementInfo(name="TWO_FACTOR_DURATION_MOBILE", id=81, datatype="TWO_FACTOR_DURATION", group="TWO_FACTOR_AUTHENTICATION"),
    EnforcementInfo(name="TWO_FACTOR_DURATION_DESKTOP", id=82, datatype="TWO_FACTOR_DURATION", group="TWO_FACTOR_AUTHENTICATION"),
    EnforcementInfo(name="RESTRICT_TWO_FACTOR_CHANNEL_SECURITY_KEYS", id=86, datatype="BOOLEAN", group="TWO_FACTOR_AUTHENTICATION"),
    EnforcementInfo(name="TWO_FACTOR_BY_IP", id=87, datatype="JSONARRAY", group="TWO_FACTOR_AUTHENTICATION"),
    EnforcementInfo(name="RESTRICT_DOMAIN_ACCESS", id=90, datatype="STRING", group="KEEPER_FILL"),
    EnforcementInfo(name="RESTRICT_DOMAIN_CREATE", id=91, datatype="STRING", group="KEEPER_FILL"),
    EnforcementInfo(name="RESTRICT_HOVER_LOCKS", id=92, datatype="BOOLEAN", group="KEEPER_FILL"),
    EnforcementInfo(name="RESTRICT_PROMPT_TO_LOGIN", id=93, datatype="BOOLEAN", group="KEEPER_FILL"),
    EnforcementInfo(name="RESTRICT_PROMPT_TO_FILL", id=94, datatype="BOOLEAN", group="KEEPER_FILL"),
    EnforcementInfo(name="RESTRICT_AUTO_SUBMIT", id=95, datatype="BOOLEAN", group="KEEPER_FILL"),
    EnforcementInfo(name="RESTRICT_PROMPT_TO_SAVE", id=96, datatype="BOOLEAN", group="KEEPER_FILL"),
    EnforcementInfo(name="RESTRICT_PROMPT_TO_CHANGE", id=97, datatype="BOOLEAN", group="KEEPER_FILL"),
    EnforcementInfo(name="RESTRICT_AUTO_FILL", id=98, datatype="BOOLEAN", group="KEEPER_FILL"),
    EnforcementInfo(name="RESTRICT_CREATE_FOLDER", id=100, datatype="BOOLEAN", group="VAULT_FEATURES"),
    EnforcementInfo(name="RESTRICT_CREATE_IDENTITY_PAYMENT_RECORDS", id=102, datatype="BOOLEAN", group="VAULT_FEATURES"),
    EnforcementInfo(name="MASK_CUSTOM_FIELDS", id=103, datatype="BOOLEAN", group="VAULT_FEATURES"),
    EnforcementInfo(name="MASK_NOTES", id=104, datatype="BOOLEAN", group="VAULT_FEATURES"),
    EnforcementInfo(name="MASK_PASSWORDS_WHILE_EDITING", id=105, datatype="BOOLEAN", group="VAULT_FEATURES"),
    EnforcementInfo(name="GENERATED_PASSWORD_COMPLEXITY", id=106, datatype="STRING", group="VAULT_FEATURES"),
    EnforcementInfo(name="GENERATED_SECURITY_QUESTION_COMPLEXITY", id=109, datatype="STRING", group="VAULT_FEATURES"),
    EnforcementInfo(name="DAYS_BEFORE_DELETED_RECORDS_CLEARED_PERM", id=107, datatype="LONG", group="VAULT_FEATURES"),
    EnforcementInfo(name="DAYS_BEFORE_DELETED_RECORDS_AUTO_CLEARED", id=108, datatype="LONG", group="VAULT_FEATURES"),
    EnforcementInfo(name="ALLOW_ALTERNATE_PASSWORDS", id=110, datatype="BOOLEAN", group="LOGIN_SETTINGS"),
    EnforcementInfo(name="RESTRICT_LINK_SHARING", id=122, datatype="BOOLEAN", group="SHARING_ENFORCEMENTS"),
    EnforcementInfo(name="RESTRICT_SHARING_OUTSIDE_OF_ISOLATED_NODES", id=123, datatype="BOOLEAN", group="SHARING_ENFORCEMENTS"),
    EnforcementInfo(name="DISABLE_SETUP_TOUR", id=140, datatype="BOOLEAN", group="VAULT_FEATURES"),
    EnforcementInfo(name="RESTRICT_PERSONAL_LICENSE", id=141, datatype="BOOLEAN", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="DISABLE_ONBOARDING", id=142, datatype="BOOLEAN", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="DISALLOW_V2_CLIENTS", id=143, datatype="BOOLEAN", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="RESTRICT_IP_AUTOAPPROVAL", id=144, datatype="BOOLEAN", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="SEND_BREACH_WATCH_EVENTS", id=200, datatype="BOOLEAN", group="VAULT_FEATURES"),
    EnforcementInfo(name="RESTRICT_BREACH_WATCH", id=201, datatype="BOOLEAN", group="VAULT_FEATURES"),
    EnforcementInfo(name="RESEND_ENTERPRISE_INVITE_IN_X_DAYS", id=202, datatype="LONG", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="MASTER_PASSWORD_REENTRY", id=203, datatype="JSON", group="KEEPER_FILL"),
    EnforcementInfo(name="RESTRICT_ACCOUNT_RECOVERY", id=204, datatype="BOOLEAN", group="ACCOUNT_SETTINGS"),
    EnforcementInfo(name="KEEPER_FILL_HOVER_LOCKS", id=205, datatype="TERNARY_DEN", group="KEEPER_FILL"),
    EnforcementInfo(name="KEEPER_FILL_AUTO_FILL", id=206, datatype="TERNARY_DEN", group="KEEPER_FILL"),
    EnforcementInfo(name="KEEPER_FILL_AUTO_SUBMIT", id=207, datatype="TERNARY_DEN", group="KEEPER_FILL"),
    EnforcementInfo(name="KEEPER_FILL_MATCH_ON_SUBDOMAIN", id=208, datatype="TERNARY_EDN", group="KEEPER_FILL"),
    EnforcementInfo(name="RESTRICT_PROMPT_TO_DISABLE", id=209, datatype="BOOLEAN", group="KEEPER_FILL"),
    EnforcementInfo(name="RESTRICT_HTTP_FILL_WARNING", id=210, datatype="BOOLEAN", group="KEEPER_FILL"),
    EnforcementInfo(name="RESTRICT_RECORD_TYPES", id=211, datatype="RECORD_TYPES", group="RECORD_TYPES"),
    EnforcementInfo(name="ALLOW_SECRETS_MANAGER", id=212, datatype="BOOLEAN", group="VAULT_FEATURES"),
    EnforcementInfo(name="REQUIRE_SELF_DESTRUCT", id=213, datatype="BOOLEAN", group="ACCOUNT_ENFORCEMENTS"),
    EnforcementInfo(name="KEEPER_FILL_AUTO_SUGGEST", id=214, datatype="TERNARY_DEN", group="KEEPER_FILL"),
    EnforcementInfo(name="MAXIMUM_RECORD_SIZE", id=215, datatype="LONG", group="ACCOUNT_ENFORCEMENTS"),
    EnforcementInfo(name="ALLOW_PAM_ROTATION", id=218, datatype="BOOLEAN", group="ACCOUNT_ENFORCEMENTS"),
    EnforcementInfo(name="ALLOW_PAM_DISCOVERY", id=219, datatype="BOOLEAN", group="ACCOUNT_ENFORCEMENTS"),
]

@dataclasses.dataclass(frozen=True)
class CompoundEnforcementInfo:
    name: str
    ids: Sequence[int]
    datatype: str
    group: str

_COMPOUND_ENFORCEMENTS = [
    CompoundEnforcementInfo(name="RESTRICT_SHARING_ALL", ids=(30, 36), datatype="BOOLEAN", group="SHARING_AND_UPLOADING"),
    CompoundEnforcementInfo(name="RESTRICT_SHARING_ENTERPRISE", ids=(31, 37), datatype="BOOLEAN", group="SHARING_AND_UPLOADING"),
]

def enforcement_list() -> List[Tuple[str, str]]:
    groups = {x[1]: x[0] for x in enumerate(ENFORCEMENT_GROUPS)}
    enforcements = [(x.name, x.group, i, groups.get(x.group, 100)) for i, x in enumerate(_ENFORCEMENTS)]
    enforcements.sort(key=lambda x: (x[2], x[3]))
    return [(x[1].title().replace('_', ' '), x[0].lower()) for x in enforcements]

ENFORCEMENTS: Dict[str, str] = {}
for e in _ENFORCEMENTS:
    ENFORCEMENTS[e.name.lower()] = e.datatype.lower()
