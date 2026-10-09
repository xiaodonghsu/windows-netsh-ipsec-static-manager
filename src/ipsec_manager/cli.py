import argparse
import json
import logging
import sys
import uuid
from pathlib import Path

from .config import Config
from .errors import EXIT_CODES, ManagerError
from .exporting import csv_snapshot
from .netsh import Netsh
from .service import Service
from .webhook import authenticate, read_environment


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ManagerError("invalid_input", message)


def parser():
    root = Parser(prog="ipsec-manager", add_help=False)
    root.add_argument("--config", default="config.json")
    commands = root.add_subparsers(dest="operation", required=True, parser_class=Parser)
    for name in ("list", "export"):
        command = commands.add_parser(name, add_help=False)
        group = command.add_mutually_exclusive_group(required=True)
        group.add_argument("--all", action="store_true")
        group.add_argument("--list", dest="alias")
        command.add_argument("--format", choices=["json", "csv"], default="json")
        if name == "export":
            command.add_argument("--output")
    check = commands.add_parser("check", add_help=False)
    check.add_argument("--list", dest="alias", required=True)
    check.add_argument("--ip", required=True)
    check.add_argument("--mode", choices=["source-range", "add-coverage"], default="source-range")
    add = commands.add_parser("add", add_help=False)
    add.add_argument("--list", dest="alias", required=True)
    add.add_argument("--ip", required=True)
    add.add_argument("--description", default="")
    add.add_argument("--dry-run", action="store_true")
    delete = commands.add_parser("delete", add_help=False)
    delete.add_argument("--list", dest="alias", required=True)
    delete.add_argument("--record-id", required=True)
    delete.add_argument("--revision", required=True)
    delete.add_argument("--dry-run", action="store_true")
    hook = commands.add_parser("webhook", add_help=False)
    hook.add_argument(
        "--operation",
        dest="hook_operation",
        required=True,
        choices=["list", "export", "check", "add", "delete"],
    )
    commands.add_parser("doctor", add_help=False)
    return root


def dispatch(service, operation, body, request_id, public=False, actor=None):
    alias = body.get("list")
    if operation in {"list", "export"}:
        data = service.list(alias, public)
        format_ = body.get("format", "json")
        if format_ not in {"json", "csv"}:
            raise ManagerError("invalid_input", "format 仅支持 json/csv")
        output = body.get("output")
        if public and output:
            raise ManagerError("permission_denied", "网络入口不接受导出路径")
        if operation == "export" and not public and not output:
            try:
                service.config.export_dir.mkdir(parents=True, exist_ok=True)
                output = str(service.config.export_dir / f"snapshot-{request_id}.{format_}")
            except OSError as exc:
                raise ManagerError("permission_denied", "管理员导出目录不可用") from exc
        content = csv_snapshot(data) if format_ == "csv" else json.dumps(data, ensure_ascii=False, indent=2)
        if output:
            try:
                # Exclusive creation avoids accidentally overwriting program/config/backup files.
                with Path(output).open(
                    "x", encoding="utf-8-sig" if format_ == "csv" else "utf-8", newline=""
                ) as stream:
                    stream.write(content)
            except OSError as exc:
                raise ManagerError("invalid_input", "无法创建导出文件（目标必须不存在）") from exc
            return "success", {"output": str(Path(output).resolve()), "snapshot": data}
        return "success", data if format_ == "json" else {"format": "csv", "content": "\ufeff" + content}
    if operation == "check":
        return "success", service.check(alias, body["ip"], body.get("mode", "source-range"), public)
    if operation == "add":
        return service.add(
            alias,
            body["ip"],
            body.get("description", ""),
            request_id,
            body.get("dry_run", False),
            actor,
            public,
        )
    if operation == "delete":
        return service.delete(
            alias, body["record_id"], body["revision"], request_id, body.get("dry_run", False), actor, public
        )
    raise ManagerError("invalid_input", "不支持的操作")


def main(argv=None):
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    request_id = str(uuid.uuid4())
    data, error = None, None
    status = "success"
    try:
        args_list = list(sys.argv[1:] if argv is None else argv)
        if args_list in (["--help"], ["-h"]):
            data = {"usage": parser().format_help(), "help": "安装、命令示例和返回码见 README.md"}
        else:
            args = parser().parse_args(args_list)
            config = Config.load(args.config)
            service = Service(config)
            if args.operation == "webhook":
                raw, signature = read_environment(config)
                body, actor = authenticate(raw, signature, args.hook_operation, config)
                request_id = body["request_id"]
                status, data = dispatch(service, args.hook_operation, body, request_id, True, actor)
            elif args.operation == "doctor":
                import platform

                from .netsh import is_admin, system_encodings

                data = {
                    "platform": platform.platform(),
                    "admin": is_admin(),
                    "encodings": system_encodings(),
                    "help": Netsh(config).help_report(),
                    "write_enabled": config.write_enabled,
                    "notice": "只读帮助检查不能确认实际删除语义或流量生效",
                }
            else:
                body = vars(args).copy()
                body["list"] = body.pop("alias", None)
                status, data = dispatch(service, args.operation, body, request_id)
    except ManagerError as exc:
        status, error = exc.status, {"message": str(exc)}
    except Exception:  # noqa: BLE001 -- protocol boundary must not expose tracebacks
        status, error = "indeterminate", {"message": "发生非预期错误，请由管理员检查本地日志并重新查询"}
        logging.getLogger(__name__).error("非预期错误 request_id=%s", request_id)
    if status not in {"success", "already_covered"} and error is None:
        error = {"message": "操作结果未能确认，请重新查询"}
    print(
        json.dumps(
            {
                "ok": status in {"success", "already_covered"},
                "status": status,
                "request_id": request_id,
                "data": data,
                "error": error,
            },
            ensure_ascii=False,
        )
    )
    return EXIT_CODES[status]


if __name__ == "__main__":
    raise SystemExit(main())
