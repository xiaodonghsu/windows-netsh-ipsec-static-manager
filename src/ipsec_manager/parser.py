"""Fail-closed bilingual state machine for verbose netsh list output."""

import re
import uuid

from .errors import ManagerError
from .matching import network
from .models import Address, FilterList, Record

ALIASES = {
    "name": "name",
    "filter list name": "name",
    "filterlist name": "name",
    "名称": "name",
    "筛选器列表名称": "name",
    "筛选器列表名": "name",
    "description": "description",
    "描述": "description",
    "filter list id": "guid",
    "filterlist id": "guid",
    "guid": "guid",
    "id": "guid",
    "筛选器列表 id": "guid",
    "筛选器列表标识": "guid",
    "store": "store",
    "policy store": "store",
    "策略存储": "store",
    "存储位置": "store",
    "last modified": "modified",
    "last modified time": "modified",
    "上次修改时间": "modified",
    "上次修改": "modified",
    "修改时间": "modified",
    "number of filters": "count",
    "no. of filters": "count",
    "筛选器数": "count",
    "筛选器数量": "count",
    "筛选器的数量": "count",
    "source address": "src",
    "source ip address": "src",
    "源地址": "src",
    "源 ip 地址": "src",
    "source mask": "srcmask",
    "source subnet mask": "srcmask",
    "源掩码": "srcmask",
    "源子网掩码": "srcmask",
    "destination address": "dst",
    "destination ip address": "dst",
    "目标地址": "dst",
    "目标 ip 地址": "dst",
    "destination mask": "dstmask",
    "destination subnet mask": "dstmask",
    "目标掩码": "dstmask",
    "目标子网掩码": "dstmask",
    "protocol": "protocol",
    "协议": "protocol",
    "source port": "srcport",
    "源端口": "srcport",
    "destination port": "dstport",
    "目标端口": "dstport",
    "mirrored": "mirrored",
    "镜像": "mirrored",
    "镜像的": "mirrored",
}
SPECIAL = {
    "me": "me",
    "my ip address": "me",
    "我的 ip 地址": "me",
    "我的ip地址": "me",
    "any": "any",
    "any ip address": "any",
    "任何 ip 地址": "any",
    "任意 ip 地址": "any",
    "wins": "wins",
    "dns": "dns-server",
    "dhcp": "dhcp",
    "gateway": "gateway",
}
PROTOCOLS = {
    "any": "ANY",
    "任意": "ANY",
    "任何": "ANY",
    "0": "ANY",
    "tcp": "TCP",
    "6": "TCP",
    "udp": "UDP",
    "17": "UDP",
    "icmp": "ICMP",
    "1": "ICMP",
    "raw": "RAW",
}


def address(value, mask):
    value = value.strip()
    token = value.casefold()
    if token in SPECIAL:
        kind = SPECIAL[token]
        # Preserve observed mask; never fabricate a special-address mask.
        return Address(kind, kind, mask, "0.0.0.0/0" if kind == "any" else None)
    try:
        from ipaddress import IPv4Address

        fixed = str(IPv4Address(value))
    except ValueError:
        kind = "ipv6" if ":" in value else "range" if "-" in value else "dns" if value else "unknown"
        return Address(kind, value, mask)
    net = network(fixed, mask)
    return Address("ipv4", fixed, str(net.netmask), str(net))


def port(value):
    if value.casefold() in {"any", "任意", "任何", "所有", "*"}:
        return 0
    result = int(value)
    if not 0 <= result <= 65535:
        raise ValueError("端口超出范围")
    return result


def make_record(fields, raw, identity, warnings):
    diagnostics = list(warnings)
    required = {"src", "dst", "protocol", "srcport", "dstport", "mirrored"}
    diagnostics.extend(f"缺少字段 {key}" for key in sorted(required - fields.keys()))
    addresses = []
    for key in ("src", "dst"):
        try:
            addresses.append(address(fields.get(key, ""), fields.get(key + "mask")))
        except ValueError as exc:
            diagnostics.append(f"{key}: {exc}")
            addresses.append(Address("invalid", fields.get(key, ""), fields.get(key + "mask")))
    proto = fields.get("protocol", "").casefold()
    protocol = PROTOCOLS.get(proto)
    if protocol is None and proto.isdecimal() and 0 <= int(proto) <= 255:
        protocol = str(int(proto))
    if protocol is None:
        diagnostics.append("协议无法解析")
    ports = []
    for key in ("srcport", "dstport"):
        try:
            ports.append(port(fields.get(key, "")))
        except ValueError:
            diagnostics.append(f"{key} 无法解析")
            ports.append(None)
    mirror = {"yes": True, "no": False, "是": True, "否": False}.get(fields.get("mirrored", "").casefold())
    if mirror is None:
        diagnostics.append("镜像标志无法解析")
    record = Record(
        identity,
        fields.get("description", ""),
        *addresses,
        protocol or fields.get("protocol"),
        *ports,
        mirror,
        "\n".join(raw),
        diagnostics,
        parsed_fields=dict(fields),
    )
    record.supported_matching = addresses[0].type in {"ipv4", "any"} and bool(addresses[0].cidr)
    # Narrow deletion domain, including special-address masks only if absent.
    record.supported_delete = (
        not diagnostics
        and all(a.type in {"ipv4", "me", "any"} for a in addresses)
        and all(a.type == "ipv4" or a.mask is None for a in addresses)
    )
    return record


def parse(text):
    if re.search(r"(?im)^\s*(?:ERR\b|error\b|错误|访问被拒绝)", text):
        raise ManagerError("unsupported", "netsh 返回错误，未取得有效快照")
    # Status words can occur inside ordinary descriptions. Only classify them without a list header.
    has_header = any(
        ALIASES.get(re.sub(r"\s+", " ", m.group(1).strip().casefold())) == "name"
        for m in re.finditer(r"(?m)^\s*([^:：\r\n]+?)\s*[:：]", text)
    )
    if not has_header and re.fullmatch(
        r"(?i)\s*(no filter lists? (?:exist|found)|没有(?:可用的)?筛选器列表)[.!。]?\s*", text
    ):
        return []
    if not has_header and re.search(r"(?i)(not found|does not exist|不存在|找不到)", text):
        raise ManagerError("not_found", "筛选器列表不存在")
    lists, current = [], None
    fields, raw, warnings = {}, [], []
    in_record = False

    def flush():
        nonlocal fields, raw, warnings, in_record
        if in_record and current is not None:
            current.records.append(make_record(fields, raw, current.identity, warnings))
        fields, raw, warnings, in_record = {}, [], [], False

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or re.fullmatch(r"[-=]+", stripped):
            if in_record:
                raw.append(line)
            continue
        if re.fullmatch(r"(?i)(?:filter|筛选器)\s*\d*\s*[:：]?", stripped):
            flush()
            in_record = True
            raw.append(line)
            continue
        match = re.match(r"^\s*([^:：]+?)\s*[:：]\s*(.*)$", line)
        if not match:
            if in_record:
                raw.append(line)
                warnings.append("无法识别的记录行")
            elif current:
                current.diagnostics.append("无法识别的列表行")
            continue
        label, value = match.groups()
        key = ALIASES.get(re.sub(r"\s+", " ", label.strip().casefold()))
        if key != "description":
            value = value.strip()
        if key == "name":
            flush()
            current = FilterList(value)
            lists.append(current)
        elif current is None:
            continue
        elif key == "src":
            if "src" in fields:
                flush()
            in_record = True
            fields[key] = value
            raw.append(line)
        elif key == "description" and (
            (not in_record and current.declared_count is not None)
            or (in_record and "description" in fields and "src" in fields)
        ):
            # Some verbose layouts omit numbered Filter headings and start each block with Description.
            flush()
            in_record = True
            fields[key] = value
            raw.append(line)
        elif in_record:
            raw.append(line)
            if key is None or key in {"guid", "count", "modified", "store"}:
                warnings.append("无法识别的记录字段")
                fields["unknown:" + label] = value
            elif key in fields:
                warnings.append(f"重复字段 {key}")
            else:
                fields[key] = value
        elif key == "guid":
            try:
                current.guid = str(uuid.UUID(value.strip().strip("{}")))
            except ValueError:
                current.diagnostics.append("GUID 无法解析")
        elif key == "count":
            try:
                current.declared_count = int(value)
            except ValueError:
                current.diagnostics.append("声明数量无法解析")
        elif key in {"description", "store", "modified"}:
            setattr(current, key, value)
        else:
            current.diagnostics.append("无法识别的列表字段")
    flush()
    if not lists:
        raise ManagerError("unsupported", "未识别到列表；不能把未知输出当作空列表")
    for item in lists:
        if item.declared_count != len(item.records):
            item.diagnostics.append("解析记录数与声明数量不一致")
        if item.store.casefold() not in {"local", "local store", "本地", "本地存储", "本地存储区"}:
            item.diagnostics.append("非本地策略存储或存储无法识别")
        item.finalize()
    return lists
