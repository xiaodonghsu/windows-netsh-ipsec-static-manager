import getpass
from collections import Counter

from .audit import Audit
from .config import safe_text
from .errors import ManagerError
from .exporting import snapshot
from .locking import file_lock
from .matching import check_range, ipv4
from .models import Address, Record, canonical
from .netsh import Netsh, decode, is_admin


def record_set(records):
    return Counter(canonical(record.revision_item()) for record in records)


class Service:
    def __init__(self, config, backend=None, audit=None, admin_check=is_admin):
        self.config = config
        self.backend = backend or Netsh(config)
        self.audit = audit or Audit(config.audit_dir)
        self.admin_check = admin_check

    def current(self, alias, writable=False):
        target = self.config.target(alias)
        items = [item for item in self.backend.read(target["name"]) if item.name == target["name"]]
        if len(items) != 1:
            raise ManagerError("not_found" if not items else "unsupported", "列表不存在或名称不唯一")
        item = items[0]
        if target.get("expected_guid") and item.guid != target["expected_guid"]:
            raise ManagerError("conflict", "列表 GUID 与管理员配置不一致")
        if writable and not item.complete:
            raise ManagerError("unsupported", "列表解析不完整，禁止写操作")
        return item

    def list(self, alias=None, public=False):
        if public and alias is None:
            raise ManagerError("permission_denied", "网络查询必须指定白名单别名")
        return snapshot([self.current(alias)] if alias else self.backend.read(), public)

    def check(self, alias, ip, mode="source-range", public=False):
        return check_range(self.current(alias), ip, mode, public)

    def permission(self, alias, dry_run):
        self.config.target(alias)
        if not dry_run and (not self.config.write_enabled or not self.admin_check()):
            raise ManagerError("permission_denied", "写功能关闭或进程未具有管理员权限")

    def add(self, alias, ip, description, request_id, dry_run=False, actor=None, public=False):
        ip = str(ipv4(ip))
        safe_text(description, "描述", allow_empty=True)
        self.permission(alias, dry_run)
        with file_lock(self.config.lock_path, self.config.lock_timeout):
            before = self.current(alias, writable=True)
            result = check_range(before, ip, "add-coverage", public)
            if result["unknown_records"]:
                raise ManagerError("unsupported", "存在可能影响覆盖判断的未知记录，拒绝添加")
            if result["matches"]:
                if not dry_run:
                    self.audit.append(
                        {
                            "actor": actor or getpass.getuser(),
                            "request_id": request_id,
                            "operation": "add",
                            "list": alias,
                            "before_revision": before.revision,
                            "after_revision": before.revision,
                            "result": "already_covered",
                            "backup_path": None,
                        }
                    )
                return "already_covered", result
            expected = Record(
                before.identity,
                description,
                Address("ipv4", ip, "255.255.255.255", f"{ip}/32"),
                Address("me", "me"),
                "ANY",
                0,
                0,
                False,
                "",
            )
            args = Netsh.add_args(before.name, ip, description)
            return self.mutate("add", alias, before, expected, args, request_id, dry_run, actor, public)

    def delete(self, alias, record_id, revision, request_id, dry_run=False, actor=None, public=False):
        import re

        if not all(
            isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in (record_id, revision)
        ):
            raise ManagerError("invalid_input", "record_id 和 revision 必须是 SHA-256 标识")
        self.permission(alias, dry_run)
        with file_lock(self.config.lock_path, self.config.lock_timeout):
            before = self.current(alias, writable=True)
            if before.revision != revision:
                raise ManagerError("conflict", "列表 revision 已改变，请重新查询")
            records = [record for record in before.records if record.record_id == record_id]
            if not records:
                raise ManagerError("not_found", "记录不存在")
            if len(records) != 1 or not records[0].supported_delete:
                raise ManagerError("unsupported", "重复条件或不支持精确删除的记录")
            if not dry_run and not self.config.delete_semantics_verified:
                raise ManagerError("unsupported", "管理员尚未确认专用测试列表的实际删除语义")
            args = Netsh.delete_args(before.name, records[0])
            return self.mutate("delete", alias, before, records[0], args, request_id, dry_run, actor, public)

    def mutate(self, operation, alias, before, record, args, request_id, dry_run, actor, public):
        if dry_run:
            return "success", {
                "dry_run": True,
                "operation": operation,
                "list": alias,
                "record_id": record.record_id,
                "revision": before.revision,
                **({} if public else {"arguments": args}),
                "write_enabled": self.config.write_enabled,
                "delete_semantics_verified": self.config.delete_semantics_verified,
            }
        event = {
            "actor": actor or getpass.getuser(),
            "request_id": request_id,
            "operation": operation,
            "list": alias,
            "before_revision": before.revision,
            "after_revision": None,
            "record_id": record.record_id,
            "backup_path": None,
        }
        self.audit.append({**event, "result": "preparing"})
        try:
            event["backup_path"] = self.backend.backup()
        except ManagerError:
            self.audit.append({**event, "result": "backup_failed"})
            raise
        # Detect GUI changes during backup, immediately before mutation.
        latest = self.current(alias, writable=True)
        if latest.revision != before.revision:
            self.audit.append({**event, "after_revision": latest.revision, "result": "conflict"})
            raise ManagerError("conflict", "备份期间列表发生变化，未执行写操作")
        self.audit.append({**event, "result": "intent"})
        status = "indeterminate"
        after = None
        timed_out = False
        command_result = None
        try:
            try:
                command_result = self.backend.execute(args)
            except ManagerError as exc:
                if exc.status != "indeterminate":
                    raise
                timed_out = True
            after = self.current(alias, writable=True)
            expected = record_set(before.records)
            actual = record_set(after.records)
            if operation == "add":
                delta = actual - expected
                removed = expected - actual
                candidates = [r for r in after.records if canonical(r.revision_item()) in delta]
                # netsh can display a mask for 'me'; retain it but validate the fixed template semantically.
                from .matching import compatible

                changed_as_expected = (
                    not removed
                    and sum(delta.values()) == 1
                    and len(candidates) == 1
                    and candidates[0].source == record.source
                    and compatible(candidates[0])
                    and candidates[0].description == record.description
                )
            else:
                expected[canonical(record.revision_item())] -= 1
                changed_as_expected = actual == +expected
            metadata_unchanged = (
                before.identity == after.identity
                and before.description == after.description
                and before.store == after.store
            )
            verified = metadata_unchanged and changed_as_expected
            # Timeout is never advertised as successful, even if the immediate read looks plausible.
            status = "indeterminate" if timed_out else "success" if verified else "verification_failed"
            if command_result is not None:
                import re

                output = decode(command_result.stdout, self.config.encoding, self.config.encoding_fallbacks)
                command_failed = (
                    command_result.returncode != 0
                    or bool(command_result.stderr.strip())
                    or bool(re.search(r"(?im)^\s*(ERR\b|error\b|错误)", output))
                )
                if command_failed:
                    status = "indeterminate" if verified else "verification_failed"
            event["after_revision"] = after.revision
        except (ManagerError, OSError):
            status = "indeterminate"
        try:
            self.audit.append({**event, "result": status})
        except ManagerError as exc:
            raise ManagerError("indeterminate", "写操作已尝试，但最终审计失败；请重新查询") from exc
        data = {
            "operation": operation,
            "list": alias,
            "record_id": record.record_id,
            "before_revision": before.revision,
            "revision": after.revision if after else None,
            "configuration_verified": status == "success",
            "traffic_verified": False,
        }
        if not public:
            data["backup_path"] = event["backup_path"]
        return status, data
