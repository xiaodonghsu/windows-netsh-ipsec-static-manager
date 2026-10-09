import ipaddress

from .errors import ManagerError


def ipv4(value):
    try:
        if not isinstance(value, str):
            raise TypeError("IPv4 text required")
        return ipaddress.IPv4Address(value)
    except (ValueError, TypeError, ipaddress.AddressValueError) as exc:
        raise ManagerError("invalid_input", "需要合法的 IPv4 单地址，不接受 CIDR") from exc


def network(address, mask):
    # ipaddress accepts host masks; explicitly reject those and noncontiguous masks.
    if mask is None:
        raise ValueError("缺少 IPv4 掩码")
    if "." in mask:
        bits = f"{int(ipaddress.IPv4Address(mask)):032b}"
        if "01" in bits:
            raise ValueError("非连续 IPv4 网络掩码")
        prefix = bits.count("1")
    else:
        prefix = int(mask.removeprefix("/"))
        if not 0 <= prefix <= 32:
            raise ValueError("非法 IPv4 前缀")
    return ipaddress.IPv4Network(f"{address}/{prefix}", strict=False)


def compatible(record):
    return (
        record.destination.type == "me"
        and record.protocol == "ANY"
        and record.source_port == 0
        and record.destination_port == 0
        and record.mirrored is False
    )


def check_range(filter_list, value, mode="source-range", public=False):
    ip = ipv4(value)
    if mode not in {"source-range", "add-coverage"}:
        raise ManagerError("invalid_input", "未知匹配模式")
    hits, unknown = [], []
    for record in filter_list.records:
        if mode == "add-coverage" and not compatible(record):
            # Missing selector fields can affect coverage; known incompatible fields cannot.
            known_incompatible = (
                record.destination.type in {"ipv4", "any"}
                or record.protocol not in {None, "ANY"}
                or record.source_port not in {None, 0}
                or record.destination_port not in {None, 0}
                or record.mirrored is True
            )
            if known_incompatible:
                continue
        if not record.supported_matching or (mode == "add-coverage" and not compatible(record)):
            unknown.append(
                {
                    "record_id": record.record_id,
                    "reason": "; ".join(record.diagnostics) or "未支持的地址或选择条件",
                }
            )
        elif ip in ipaddress.IPv4Network(record.source.cidr):
            hits.append(record.to_dict(public))
    return {
        "ip": str(ip),
        "list": filter_list.name,
        "revision": filter_list.revision,
        "mode": mode,
        "matches": hits,
        "unknown_records": unknown,
        "determinate": filter_list.complete and not unknown,
        "warnings": filter_list.diagnostics,
        "meaning": "仅表示源地址范围归属，不代表允许访问",
    }
