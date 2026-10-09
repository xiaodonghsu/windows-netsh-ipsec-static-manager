"""Authenticated business adapter. No client command/path options are accepted."""

import hashlib
import hmac
import json
import os
import sqlite3
import time
import uuid
from pathlib import Path

from .errors import ManagerError

FIELDS = {
    "list": {"list"},
    "export": {"list", "format"},
    "check": {"list", "ip", "mode"},
    "add": {"list", "ip", "description", "dry_run"},
    "delete": {"list", "record_id", "revision", "dry_run"},
}


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def authenticate(raw, signature, operation, config, now=None, secret=None):
    settings = config.webhook
    if operation not in FIELDS:
        raise ManagerError("invalid_input", "不支持的固定 hook 操作")
    limit = settings.get("max_body_bytes", 16384)
    if len(raw) > limit:
        raise ManagerError("invalid_input", "请求体过大")
    secret = (
        secret if secret is not None else os.environ.get(settings.get("secret_env", "IPSEC_WEBHOOK_SECRET"))
    )
    if not secret or len(secret) < 32 or "REPLACE" in secret.upper():
        raise ManagerError("permission_denied", "服务器未配置有效签名密钥")
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(expected, signature):
        raise ManagerError("permission_denied", "请求签名无效")
    try:
        body = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
        if not isinstance(body, dict):
            raise TypeError("object required")
        common = {"operation", "timestamp", "request_id"}
        if set(body) - (common | FIELDS[operation]) or not common.issubset(body):
            raise ValueError("unsupported fields")
        if body["operation"] != operation:
            raise ValueError("operation mismatch")
        request_id = str(uuid.UUID(body["request_id"]))
        if type(body["timestamp"]) is not int:
            raise ValueError("integer timestamp required")
        if "list" not in body or not isinstance(body["list"], str):
            raise ValueError("alias required")
        config.target(body["list"])
        if "dry_run" in body and type(body["dry_run"]) is not bool:
            raise ValueError("boolean dry_run required")
        for field in FIELDS[operation] - {"dry_run"}:
            if field in body and not isinstance(body[field], str):
                raise ValueError("string field required")
        required = {"check": {"ip"}, "add": {"ip"}, "delete": {"record_id", "revision"}}.get(operation, set())
        if not required.issubset(body):
            raise ValueError("missing fields")
    except (UnicodeError, ValueError, TypeError, AttributeError, KeyError) as exc:
        raise ManagerError("invalid_input", "请求 JSON 或业务字段无效") from exc
    now = time.time() if now is None else now
    window = settings.get("window_seconds", 300)
    if abs(now - body["timestamp"]) > window:
        raise ManagerError("permission_denied", "请求时间戳过期或超前")
    try:
        config.audit_dir.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(config.audit_dir / "replay.sqlite3", timeout=config.lock_timeout) as connection:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS replay (id TEXT PRIMARY KEY, expires REAL NOT NULL)"
            )
            connection.execute("DELETE FROM replay WHERE expires < ?", (now,))
            # Reserve before performing any action, including dry-run and read operations.
            connection.execute("INSERT INTO replay VALUES (?, ?)", (request_id, now + 2 * window + 1))
    except sqlite3.IntegrityError as exc:
        raise ManagerError("permission_denied", "重复 request_id，拒绝重放请求") from exc
    except (OSError, sqlite3.Error) as exc:
        raise ManagerError("permission_denied", "重放记录不可用，拒绝请求") from exc
    body["request_id"] = request_id
    return body, settings.get("principal", "authenticated-management-client")


def read_environment(config):
    # These variables are set by administrator-owned webhook hooks, never request fields.
    path = os.environ.get("IPSEC_BODY_FILE")
    if not path:
        raise ManagerError("permission_denied", "缺少受信 webhook 请求体")
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(config.webhook.get("max_body_bytes", 16384) + 1)
    except OSError as exc:
        raise ManagerError("permission_denied", "无法读取 webhook 请求体") from exc
    return raw, os.environ.get("IPSEC_SIGNATURE", "")
