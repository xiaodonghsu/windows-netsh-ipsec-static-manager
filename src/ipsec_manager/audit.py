import json
import os
from datetime import UTC, datetime

from .errors import ManagerError


class Audit:
    def __init__(self, directory):
        self.directory = directory

    def append(self, event):
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            # Write intent is durably appended before any policy mutation.
            with (self.directory / "audit.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(
                    json.dumps({"time": datetime.now(UTC).isoformat(), **event}, ensure_ascii=False) + "\n"
                )
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            raise ManagerError("permission_denied", "审计持久化不可用，不能执行写操作") from exc
