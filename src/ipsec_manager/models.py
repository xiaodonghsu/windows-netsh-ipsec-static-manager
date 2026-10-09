import hashlib
import json
from collections import Counter
from dataclasses import asdict, dataclass, field


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


@dataclass
class Address:
    type: str
    address: str
    mask: str | None = None
    cidr: str | None = None


@dataclass
class Record:
    list_identity: str
    description: str
    source: Address
    destination: Address
    protocol: str | None
    source_port: int | None
    destination_port: int | None
    mirrored: bool | None
    raw_text: str
    diagnostics: list[str] = field(default_factory=list)
    supported_matching: bool = False
    supported_delete: bool = False
    duplicate_count: int = 1
    parsed_fields: dict = field(default_factory=dict)

    def selector(self):
        # CIDR is derived; raw address/mask are retained for exact netsh selection.
        return {
            "list_identity": self.list_identity,
            "source": asdict(self.source),
            "destination": asdict(self.destination),
            "protocol": self.protocol,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "mirrored": self.mirrored,
            "unparsed_fields": {
                key: value for key, value in self.parsed_fields.items() if key != "description"
            }
            if self.diagnostics
            else {},
        }

    @property
    def record_id(self):
        return digest(self.selector())

    def revision_item(self):
        return {
            **self.selector(),
            "description": self.description,
            "diagnostics": self.diagnostics,
            "extra_fields": {
                key: value for key, value in self.parsed_fields.items() if key.startswith("unknown:")
            },
        }

    def to_dict(self, public=False):
        value = asdict(self)
        value["record_id"] = self.record_id
        if public:
            value.pop("raw_text")
        return value


@dataclass
class FilterList:
    name: str
    guid: str | None = None
    description: str = ""
    store: str = "local"
    modified: str | None = None
    declared_count: int | None = None
    records: list[Record] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)

    @property
    def identity(self):
        return self.guid or f"local:name:{self.name} (GUID unavailable)"

    @property
    def complete(self):
        return (
            not self.diagnostics
            and self.declared_count == len(self.records)
            and all(not r.diagnostics for r in self.records)
        )

    @property
    def revision(self):
        return digest(
            {
                "identity": self.identity,
                "description": self.description,
                "records": sorted((r.revision_item() for r in self.records), key=canonical),
            }
        )

    def finalize(self):
        counts = Counter(r.record_id for r in self.records)
        for record in self.records:
            record.duplicate_count = counts[record.record_id]
            record.supported_delete &= self.complete and record.duplicate_count == 1

    def to_dict(self, public=False):
        return {
            "name": self.name,
            "guid": self.guid,
            "identity": self.identity,
            "description": self.description,
            "store": self.store,
            "modified": self.modified,
            "declared_count": self.declared_count,
            "parse_status": "complete" if self.complete else "incomplete",
            "revision": self.revision,
            "diagnostics": self.diagnostics,
            "records": [r.to_dict(public) for r in self.records],
        }
