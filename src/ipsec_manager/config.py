import codecs
import json
import math
import unicodedata
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ManagerError


def safe_text(value, label, limit=256, allow_empty=False):
    if (
        not isinstance(value, str)
        or len(value) > limit
        or (not value and not allow_empty)
        or any(unicodedata.category(c) in {"Cc", "Cf", "Zl", "Zp", "Cs"} for c in value)
        or '"' in value
    ):
        raise ManagerError("invalid_input", f"{label} 长度或字符不合法（拒绝控制字符及双引号）")
    return value


@dataclass
class Config:
    lists: dict
    netsh_path: str
    export_dir: Path
    backup_dir: Path
    audit_dir: Path
    lock_path: Path
    encoding: str = "auto"
    encoding_fallbacks: list[str] = field(default_factory=list)
    command_timeout: float = 30
    lock_timeout: float = 30
    write_enabled: bool = False
    delete_semantics_verified: bool = False
    webhook: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
            for name in ("export_dir", "backup_dir", "audit_dir", "lock_path"):
                data[name] = Path(data[name])
                if not data[name].is_absolute():
                    raise ValueError("目录必须为绝对路径")
            config = cls(**data)
            if (
                not Path(config.netsh_path).is_absolute()
                or Path(config.netsh_path).name.casefold() != "netsh.exe"
            ):
                raise ValueError("netsh_path 必须是 netsh.exe 绝对路径")
            for timeout in (config.command_timeout, config.lock_timeout):
                if type(timeout) not in {int, float} or not math.isfinite(timeout) or timeout <= 0:
                    raise ValueError("超时必须为有限正数")
            if not isinstance(config.lists, dict) or not isinstance(config.webhook, dict):
                raise TypeError("配置必须使用对象")
            for key, default in (("window_seconds", 300), ("max_body_bytes", 16384)):
                value = config.webhook.get(key, default)
                if type(value) is not int or value <= 0:
                    raise ValueError("webhook 时间窗口与大小限制必须是正整数")
            safe_text(config.webhook.get("principal", "authenticated-management-client"), "认证身份")
            safe_text(config.webhook.get("secret_env", "IPSEC_WEBHOOK_SECRET"), "密钥环境变量名称")
            if type(config.write_enabled) is not bool or type(config.delete_semantics_verified) is not bool:
                raise ValueError("写开关必须是布尔值")
            for alias, entry in config.lists.items():
                safe_text(alias, "别名")
                safe_text(entry["name"], "列表名")
                if entry.get("expected_guid"):
                    entry["expected_guid"] = str(uuid.UUID(entry["expected_guid"].strip("{}")))
            for encoding in (
                [config.encoding] if config.encoding != "auto" else []
            ) + config.encoding_fallbacks:
                codecs.lookup(encoding)
            return config
        except (OSError, ValueError, TypeError, KeyError, LookupError, AttributeError) as exc:
            raise ManagerError("invalid_input", "配置无效或不可读取，请检查管理员配置") from exc

    def target(self, alias):
        if alias not in self.lists:
            raise ManagerError("permission_denied", "列表别名不在服务器允许管理列表中")
        return self.lists[alias]
