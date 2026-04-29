import base64
import json
import logging
import os
import sqlite3
from typing import Any, Dict, List, Optional

import boto3

from keepersdk import utils
from keepersdk.authentication import configuration, endpoint, keeper_auth, login_auth
from keepersdk.vault import sqlite_storage, vault_online, vault_record


logger = utils.get_logger()
logger.setLevel(logging.INFO)
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setLevel(logging.INFO)
    _handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")
    )
    logger.addHandler(_handler)


class SecretsManagerJsonLoader(configuration.IJsonLoader):
    """IJsonLoader implementation backed by AWS Secrets Manager."""

    def __init__(self, secret_id: str, region_name: Optional[str] = None) -> None:
        self.secret_id = secret_id
        self.client = boto3.client("secretsmanager", region_name=region_name)
        self._cached_bytes: Optional[bytes] = None
        self._dirty = False

    def load_json(self) -> bytes:
        if self._cached_bytes is not None:
            return self._cached_bytes

        response = self.client.get_secret_value(SecretId=self.secret_id)
        if "SecretString" in response:
            secret_bytes = response["SecretString"].encode("utf-8")
        else:
            # Secrets Manager returns base64-encoded bytes for SecretBinary.
            secret_bytes = base64.b64decode(response["SecretBinary"])

        # Normalize empty payloads to JSON object.
        payload = secret_bytes.strip() or b"{}"
        self._cached_bytes = payload
        return payload

    def store_json(self, data: bytes) -> None:
        # JsonConfigurationStorage.put() calls this; persist later with flush().
        self._cached_bytes = data
        self._dirty = True

    def flush(self) -> None:
        if not self._dirty or self._cached_bytes is None:
            return
        self.client.put_secret_value(
            SecretId=self.secret_id,
            SecretString=self._cached_bytes.decode("utf-8"),
        )
        self._dirty = False


def enable_persistent_login(keeper_auth_context: keeper_auth.KeeperAuth) -> None:
    """Enable persistent login and register device key for future resume login."""
    keeper_auth.set_user_setting(keeper_auth_context, "persistent_login", "1")
    keeper_auth.register_data_key_for_device(keeper_auth_context)
    mins_per_day = 60 * 24
    timeout_in_minutes = mins_per_day * 30
    keeper_auth.set_user_setting(
        keeper_auth_context, "logout_timer", str(timeout_in_minutes)
    )


def _fail_non_interactive(step: Any) -> None:
    raise RuntimeError(
        "Non-interactive Lambda login cannot continue. "
        f"Received step: {type(step).__name__}. "
        "Run one interactive login locally to fully approve/register this device, "
        "then update the same config JSON in Secrets Manager."
    )


def _configuration_health(conf: configuration.IKeeperConfiguration) -> Dict[str, Any]:
    """Return non-sensitive diagnostics for secret/config completeness."""
    user = conf.last_login or ""
    has_user = bool(user)
    has_server = bool(conf.last_server)
    user_cfg = conf.users().get(user) if user else None
    last_device_token = ""
    if user_cfg and user_cfg.last_device:
        last_device_token = user_cfg.last_device.device_token or ""
    has_last_device = bool(last_device_token)

    device_cfg = conf.devices().get(last_device_token) if last_device_token else None
    has_device = bool(device_cfg)
    has_private_key = bool(device_cfg and device_cfg.private_key)
    has_clone_code = bool(
        device_cfg
        and device_cfg.get_server_info()
        and device_cfg.get_server_info().get(conf.last_server)
        and device_cfg.get_server_info().get(conf.last_server).clone_code
    )
    return {
        "has_last_login": has_user,
        "has_last_server": has_server,
        "users_count": len(list(conf.users().list())),
        "devices_count": len(list(conf.devices().list())),
        "has_user_last_device": has_last_device,
        "has_device_entry_for_last_device": has_device,
        "has_device_private_key": has_private_key,
        "has_clone_code_for_last_server": has_clone_code,
    }


def _password_not_allowed_error() -> RuntimeError:
    return RuntimeError(
        "Keeper requested Password step in Lambda, but this function is configured "
        "for password-free persistent login only. Update Secrets Manager with your "
        "latest local Keeper config after enabling persistent login on the same device."
    )


def _fetch_password_from_secret(
    secret_id: str, region_name: Optional[str] = None
) -> str:
    """Read Keeper password from Secrets Manager secret string/binary."""
    client = boto3.client("secretsmanager", region_name=region_name)
    response = client.get_secret_value(SecretId=secret_id)
    if "SecretString" in response:
        secret_text = response["SecretString"]
    else:
        secret_text = base64.b64decode(response["SecretBinary"]).decode("utf-8")

    value = secret_text.strip()
    if not value:
        raise ValueError(f"Password secret '{secret_id}' is empty.")

    # Accept either a raw secret string or a JSON object with a password field.
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, dict):
        for key in ("password", "keeper_password", "value"):
            candidate = parsed.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
        raise ValueError(
            f"Password secret '{secret_id}' JSON must include one of: "
            "'password', 'keeper_password', or 'value'."
        )

    return value


def login_from_secret(
    secret_id: str, region_name: Optional[str] = None
) -> keeper_auth.KeeperAuth:
    """
    Login with Keeper config stored in Secrets Manager.
    Works only for resume/session-based non-interactive login in Lambda.
    """
    loader = SecretsManagerJsonLoader(secret_id=secret_id, region_name=region_name)
    config_storage = configuration.JsonConfigurationStorage(loader=loader)
    conf = config_storage.get()

    if not conf.last_server:
        conf.last_server = os.getenv("KEEPER_SERVER", "keepersecurity.com")
    if not conf.last_login:
        env_user = os.getenv("KEEPER_USERNAME", "").strip()
        if env_user:
            conf.last_login = env_user

    if not conf.last_login:
        raise ValueError(
            "Missing username in config secret. "
            "Set last_login/user in secret JSON or KEEPER_USERNAME env var."
        )

    config_storage.put(conf)

    keeper_endpoint = endpoint.KeeperEndpoint(config_storage, conf.last_server)
    password_secret_id = os.getenv("KEEPER_PASSWORD_SECRET_ID", "keeper-secret-2")
    password_from_secret: Optional[str] = None

    login_ctx = login_auth.LoginAuth(keeper_endpoint)
    login_ctx.resume_session = True
    login_ctx.login(conf.last_login)

    approval_attempted = False
    used_interactive_step = False

    while not login_ctx.login_step.is_final():
        step = login_ctx.login_step
        if isinstance(step, login_auth.LoginStepDeviceApproval):
            if approval_attempted:
                _fail_non_interactive(step)
            approval_attempted = True
            step.resume()
            used_interactive_step = True
            continue

        if isinstance(step, login_auth.LoginStepPassword):
            logger.info(
                "Config-based resume login is not valid for this run; "
                "falling back to master password from secret '%s'.",
                password_secret_id,
            )
            if password_from_secret is None:
                password_from_secret = _fetch_password_from_secret(
                    secret_id=password_secret_id, region_name=region_name
                )
            try:
                step.verify_password(password_from_secret)
                used_interactive_step = True
                continue
            except Exception as ex:
                raise RuntimeError(
                    "Keeper requested password fallback, but verification failed "
                    f"using secret '{password_secret_id}'."
                ) from ex

        if isinstance(
            step,
            (
                login_auth.LoginStepTwoFactor,
                login_auth.LoginStepSsoToken,
                login_auth.LoginStepSsoDataKey,
            ),
        ):
            _fail_non_interactive(step)

        if isinstance(step, login_auth.LoginStepError):
            raise RuntimeError(f"Keeper login error: ({step.code}) {step.message}")

        _fail_non_interactive(step)

    if not isinstance(login_ctx.login_step, login_auth.LoginStepConnected):
        raise RuntimeError("Login did not reach connected state.")

    keeper_ctx = login_ctx.login_step.take_keeper_auth()

    # If login needed any step loop, ensure persistent login/device key are set.
    if used_interactive_step:
        enable_persistent_login(keeper_ctx)

    # Persist refreshed config (clone codes/device/server mappings) back to secret.
    config_storage.put(config_storage.get())
    loader.flush()
    return keeper_ctx


def list_records(keeper_auth_context: keeper_auth.KeeperAuth) -> List[Dict[str, Any]]:
    """Sync vault and return records shaped like the example output."""
    conn = sqlite3.Connection("file::memory:", uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(
        lambda: conn,
        vault_owner=bytes(keeper_auth_context.auth_context.username, "utf-8"),
    )

    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
    try:
        vault.sync_down()
        output: List[Dict[str, Any]] = []
        for record in vault.vault_data.records():
            item: Dict[str, Any] = {
                "Title": record.title,
                "Record UID": record.record_uid,
                "Record Type": record.record_type,
            }
            if record.version == 2:
                legacy_record = vault.vault_data.load_record(record.record_uid)
                if isinstance(legacy_record, vault_record.PasswordRecord):
                    item["Username"] = legacy_record.login
                    item["URL"] = legacy_record.link
            output.append(item)
        return output
    finally:
        vault.close()
        keeper_auth_context.close()


def lambda_handler(event, context):
    """
    Lambda handler.
    Env vars:
      - KEEPER_SECRET_ID (default: keeper-secret-1)
      - KEEPER_PASSWORD_SECRET_ID (default: keeper-secret-2)
      - AWS_REGION / KEEPER_AWS_REGION (optional override)
      - KEEPER_USERNAME (optional fallback if secret lacks last_login)
      - KEEPER_SERVER (optional fallback if secret lacks last_server)
    """
    secret_id = os.getenv("KEEPER_SECRET_ID", "keeper-secret-1")
    region = os.getenv("KEEPER_AWS_REGION") or os.getenv("AWS_REGION")
    run_diagnostics = bool(event and event.get("diagnose_config"))

    try:
        if run_diagnostics:
            loader = SecretsManagerJsonLoader(secret_id=secret_id, region_name=region)
            config_storage = configuration.JsonConfigurationStorage(loader=loader)
            conf = config_storage.get()
            diagnostics = _configuration_health(conf)
            return {
                "statusCode": 200,
                "body": json.dumps({"ok": True, "diagnostics": diagnostics}),
            }

        keeper_ctx = login_from_secret(secret_id=secret_id, region_name=region)
        records = list_records(keeper_ctx)
        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "ok": True,
                    "record_count": len(records),
                    "records": records,
                }
            ),
        }
    except Exception as e:
        logger.exception("Keeper Lambda execution failed")
        return {
            "statusCode": 500,
            "body": json.dumps({"ok": False, "error": str(e)}),
        }
