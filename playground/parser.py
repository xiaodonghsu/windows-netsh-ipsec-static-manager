import sys
import argparse
import re
import json


def parse_filter_lists(text):
    # 按筛选器列表名称拆分各个列表
    sections = re.split(
        r"(?=^\s*筛选器列表名称\s*:)",
        text,
        flags=re.MULTILINE
    )

    results = []

    for section in sections:
        section = section.strip()
        if not section.startswith("筛选器列表名称"):
            continue

        # 解析列表基本信息和筛选器数量
        list_info = {}
        filter_count = 0

        header, sep, filter_part = section.partition("筛选器\n")
        if not sep:
            # 兼容分隔线前后可能存在空格的情况
            match = re.search(r"(?m)^筛选器\s*$", section)
            if match:
                header = section[:match.start()]
                filter_part = section[match.end():]
            else:
                header = section
                filter_part = ""

        for line in header.splitlines():
            match = re.match(r"^\s*([^:：]+?)\s*[:：]\s*(.*?)\s*$", line)
            if match:
                key, value = match.groups()
                if key == "筛选器数目":
                    filter_count = int(value)
                else:
                    list_info[key.strip()] = value.strip()

        # 解析每个筛选器
        filters = []
        current_filter = {}

        for line in filter_part.splitlines():
            line = line.strip()

            if not line or re.fullmatch(r"-+", line):
                continue

            match = re.match(r"^([^:：]+?)\s*[:：]\s*(.*?)\s*$", line)
            if not match:
                continue

            key, value = match.groups()
            key = key.strip()
            value = value.strip()

            # 每个筛选器都从“描述”字段开始
            if key == "描述" and current_filter:
                filters.append(current_filter)
                current_filter = {}

            current_filter[key] = value

        if current_filter:
            filters.append(current_filter)

        list_info["筛选器"] = filters
        results.append(list_info)

    return results

def read_all(path=None):
    """
    一次性读取全部内容。

    path: 文件路径；None 或 '-' 表示读取标准输入
    """
    # 二进制模式：不加 encoding
    if path in (None, "-"):
        if sys.stdin.isatty():
            raise RuntimeError(
                "没有输入：请用管道传入，或指定文件路径。\n"
                "  示例: cat data.txt | python read_input.py\n"
                "  示例: python read_input.py data.txt"
            )
        else:
            # 显式指定编码，避免不同系统默认编码不一致
            stdin_content = sys.stdin.read()
            return stdin_content

    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        with open(path, "r", encoding="GB2312") as f:
            return f.read()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="从管道或文件读取全部内容")
    parser.add_argument("file", nargs="?", help="输入文件路径（可选）")
    args = parser.parse_args()
    # 没给参数且没有管道输入时，给出友好提示
    if args.file is None and sys.stdin.isatty():
        parser.print_help()
        sys.exit(1)

    text = read_all(args.file)

    print(text)

    data = parse_filter_lists(text)

    with open("output.json", "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(json.dumps(data, ensure_ascii=False, indent=2))
