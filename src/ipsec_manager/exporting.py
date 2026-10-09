import csv
import io
import json
import socket
from datetime import UTC, datetime


def snapshot(lists, public=False):
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        **({} if public else {"host": socket.gethostname()}),
        "warnings": [warning for item in lists for warning in item.diagnostics]
        + [warning for item in lists for record in item.records for warning in record.diagnostics],
        "lists": [item.to_dict(public) for item in lists],
    }


def safe_cell(value):
    if value is None:
        return ""
    value = str(value)
    if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
        return "'" + value
    return value


def csv_snapshot(data):
    # One row per record; empty lists receive a metadata-only row.
    stream = io.StringIO(newline="")
    columns = [
        "generated_at",
        "host",
        "warnings",
        "list_name",
        "list_guid",
        "list_identity",
        "list_description",
        "store",
        "modified",
        "declared_count",
        "parse_status",
        "revision",
        "list_diagnostics",
        "record_id",
        "description",
        "source_type",
        "source_address",
        "source_mask",
        "source_cidr",
        "destination_type",
        "destination_address",
        "destination_mask",
        "destination_cidr",
        "protocol",
        "source_port",
        "destination_port",
        "mirrored",
        "duplicate_count",
        "supported_matching",
        "supported_delete",
        "record_diagnostics",
        "parsed_fields",
        "raw_text",
    ]
    writer = csv.DictWriter(stream, fieldnames=columns)
    writer.writeheader()
    if not data["lists"]:
        writer.writerow(
            {
                "generated_at": safe_cell(data["generated_at"]),
                "host": safe_cell(data.get("host")),
                "warnings": safe_cell(json.dumps(data["warnings"], ensure_ascii=False)),
            }
        )
    for item in data["lists"]:
        metadata = {
            "generated_at": data["generated_at"],
            "host": data.get("host"),
            "warnings": json.dumps(data["warnings"], ensure_ascii=False),
            "list_name": item["name"],
            "list_guid": item["guid"],
            "list_identity": item["identity"],
            "list_description": item["description"],
            "store": item["store"],
            "modified": item["modified"],
            "declared_count": item["declared_count"],
            "parse_status": item["parse_status"],
            "revision": item["revision"],
            "list_diagnostics": json.dumps(item["diagnostics"], ensure_ascii=False),
        }
        for record in item["records"] or [None]:
            row = dict(metadata)
            if record:
                for key in (
                    "record_id",
                    "description",
                    "protocol",
                    "source_port",
                    "destination_port",
                    "mirrored",
                    "duplicate_count",
                    "supported_matching",
                    "supported_delete",
                    "raw_text",
                ):
                    row[key] = record.get(key)
                row["record_diagnostics"] = json.dumps(record["diagnostics"], ensure_ascii=False)
                row["parsed_fields"] = json.dumps(record.get("parsed_fields", {}), ensure_ascii=False)
                for side in ("source", "destination"):
                    for key, value in record[side].items():
                        row[f"{side}_{key}"] = value
            writer.writerow({key: safe_cell(value) for key, value in row.items()})
    return stream.getvalue()
