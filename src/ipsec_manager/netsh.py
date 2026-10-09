import ctypes
import locale
import os
import re
import subprocess
import uuid
from dataclasses import dataclass

from .config import safe_text
from .errors import ManagerError
from .parser import parse


@dataclass
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes = b""


def system_encodings():
    values = []
    if os.name == "nt":
        # Redirected netsh typically uses OEM; rely on OS APIs, not language guesses.
        values.extend([f"cp{ctypes.windll.kernel32.GetOEMCP()}", f"cp{ctypes.windll.kernel32.GetACP()}"])
    values.append(locale.getpreferredencoding(False))
    return list(dict.fromkeys(values))


def decode(raw, encoding="auto", fallbacks=()):
    if not raw:
        return ""
    if encoding == "auto":
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            candidates = ["utf-16"]
        elif raw.startswith(b"\xef\xbb\xbf"):
            candidates = ["utf-8-sig"]
        elif all(byte < 128 for byte in raw):
            candidates = ["ascii"]
        else:
            candidates = system_encodings() + list(fallbacks)
    else:
        candidates = [encoding] + list(fallbacks)
    decoded = []
    for candidate in dict.fromkeys(candidates):
        try:
            value = raw.decode(candidate, errors="strict")
            if "\x00" not in value:
                decoded.append(value)
        except (UnicodeError, LookupError):
            continue
    if not decoded or len(set(decoded)) != 1:
        raise ManagerError("unsupported", "输出解码失败或编码有歧义，请显式配置本机编码")
    return decoded[0]


def run_command(args, timeout):
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout, shell=False, check=False)
        return CommandResult(result.returncode, result.stdout, result.stderr)
    except subprocess.TimeoutExpired as exc:
        raise ManagerError("indeterminate", "netsh 超时；请重新查询，不要自动重试写操作") from exc
    except OSError as exc:
        raise ManagerError("unsupported", "无法执行配置的 netsh.exe") from exc


def is_admin():
    return os.name == "nt" and bool(ctypes.windll.shell32.IsUserAnAdmin())


class Netsh:
    def __init__(self, config, runner=run_command):
        self.config = config
        self.runner = runner

    def execute(self, args):
        # A fresh netsh process has the default local static store; no persisted domain session.
        return self.runner([self.config.netsh_path, "ipsec", "static", *args], self.config.command_timeout)

    def text(self, result):
        output = decode(result.stdout, self.config.encoding, self.config.encoding_fallbacks)
        error = decode(result.stderr, self.config.encoding, self.config.encoding_fallbacks)
        if result.returncode or error.strip() or re.search(r"(?im)^\s*(ERR\b|error\b|错误)", output):
            if re.search(r"(?i)(not found|does not exist|不存在|找不到)", output + error):
                raise ManagerError("not_found", "筛选器列表不存在")
            raise ManagerError("unsupported", "netsh 读取失败；请在本机检查权限和策略存储")
        return output

    def read(self, name=None):
        selector = "all" if name is None else f"name={safe_text(name, '列表名')}"
        items = parse(
            self.text(
                self.execute(
                    [
                        "show",
                        "filterlist",
                        selector,
                        "level=verbose",
                        "format=list",
                        "resolvedns=no",
                        "wide=yes",
                    ]
                )
            )
        )
        if name is not None and not any(item.name == name for item in items):
            raise ManagerError("not_found", "查询未返回指定列表")
        return items

    def backup(self):
        try:
            self.config.backup_dir.mkdir(parents=True, exist_ok=True)
            path = self.config.backup_dir / f"policy-{uuid.uuid4()}.ipsec"
            self.text(self.execute(["exportpolicy", f"file={path}"]))
            if not path.is_file() or path.stat().st_size == 0:
                raise OSError("missing or empty backup")
            with path.open("r+b") as stream:
                os.fsync(stream.fileno())
            return str(path)
        except (OSError, ManagerError) as exc:
            raise ManagerError("backup_failed", "完整策略备份失败，未执行写操作") from exc

    @staticmethod
    def add_args(name, ip, description):
        return [
            "add",
            "filter",
            f"filterlist={safe_text(name, '列表名')}",
            f"srcaddr={ip}",
            "srcmask=255.255.255.255",
            "dstaddr=me",
            "protocol=ANY",
            "srcport=0",
            "dstport=0",
            "mirrored=no",
            f"description={safe_text(description, '描述', allow_empty=True)}",
        ]

    @staticmethod
    def delete_args(name, record):
        if not record.supported_delete:
            raise ManagerError("unsupported", "记录无法安全表达为完整删除条件")
        args = ["delete", "filter", f"filterlist={safe_text(name, '列表名')}"]
        for prefix, address in (("src", record.source), ("dst", record.destination)):
            args.append(f"{prefix}addr={address.address}")
            if address.mask is not None:
                args.append(f"{prefix}mask={address.mask}")
        args.extend(
            [
                f"protocol={record.protocol}",
                f"srcport={record.source_port}",
                f"dstport={record.destination_port}",
                f"mirrored={'yes' if record.mirrored else 'no'}",
            ]
        )
        return args

    def help_report(self):
        result = {}
        for key, args in {
            "show": ["show", "filterlist", "?"],
            "add": ["add", "filter", "?"],
            "delete": ["delete", "filter", "?"],
            "backup": ["exportpolicy", "?"],
        }.items():
            result[key] = self.text(self.execute(args))
        return result
