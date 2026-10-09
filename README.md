# Windows 本地 IPsec 筛选器管理

基于 Python 标准库、uv 和 `netsh ipsec static` 的保守管理工具。支持查询、JSON/CSV 导出、IPv4 源范围检查、固定模板幂等添加、按完整条件精确删除，以及 adnanh/webhook 集成。**命中筛选器列表仅表示范围归属，不代表允许访问。** 访问结果还取决于关联规则、筛选器操作和策略是否启用。

## 安装

目标：Windows 10、Python 3.11+、uv。运行依赖仅标准库；pytest 和 Ruff 为开发依赖。

```powershell
uv sync --locked
Copy-Item config.example.json config.json
uv run ipsec-manager --help
uv run pytest -q
uv run ruff check src tests
uv run ruff format --check src tests
```

发布部署建议将项目放在 `C:\Program Files\IpsecManager`，配置及数据放在 `C:\ProgramData\IpsecManager`。生产环境安装可用 `uv sync --locked --no-dev`；固定调用 `.venv\Scripts\python.exe -I -m ipsec_manager`。解释器、项目（包括 editable 安装对应源码）、配置、hooks、工作目录、锁、备份和审计目录均须由管理员维护 ACL，禁止普通用户修改。不要把用户可写工作区直接作为高权限部署目录。

无需安装服务、独立数据库或 HTTP 框架。本项目不会创建/指派策略、修改筛选器操作、自动重启服务或开放端口。

## 配置与权限

编辑 `config.json`；示例默认 `write_enabled=false`，`delete_semantics_verified=false`。

| 字段 | 用途 |
| --- | --- |
| `lists` | 别名 → 真实列表名与可选 `expected_guid`，建议始终固定 GUID |
| `netsh_path` | 本机 `netsh.exe` 的绝对路径 |
| `encoding` | `auto` 或实测编码，如 `utf-8`、`cp936`、`cp437`；不要根据系统语言猜测 |
| `encoding_fallbacks` | 管理员明确允许的候选编码；产生不同有效解码时拒绝，而非择一猜测 |
| `command_timeout` / `lock_timeout` | 命令与锁等待秒数 |
| `export_dir` | 本地 export 未指定 output 时的受管理目录 |
| `backup_dir` / `audit_dir` | 完整 `.ipsec` 备份、JSONL 审计与持久重放记录 |
| `lock_path` | 机器级跨进程锁路径；同一机器的所有实例必须使用同一个受保护路径 |
| `write_enabled` | 真正添加/删除开关；仍要求 Windows 管理员权限 |
| `delete_semantics_verified` | 管理员在专用测试列表验证实际精确删除语义后才能设为 true |
| `webhook` | 密钥环境变量名、时间窗口、请求体上限与服务器认证身份标签 |

读取本地策略也可能需要管理员权限。权限不足、策略存储不可打开、未知输出均报告错误，绝不当作空列表。所有命令均启动新的 netsh 进程，使用默认本地 static store，不接收域参数、不复用外部 netsh 会话。首次上线用 `netsh ipsec static show store` 确认显示 Local Store。

写锁使用 Windows 原生字节文件锁，崩溃后由系统释放。锁覆盖重新读取、去重、备份、修改、复查、审计；它不能锁住 GUI 或管理员的其他工具。程序在备份后再次核对 revision，写后比较完整记录多重集合，仍存在外部工具在最终检查与写入之间竞争的窗口。操作期间应停止其他修改工具；失败后不要自动回滚或重试。

## 本机兼容性检查

```powershell
uv run ipsec-manager --config config.json doctor
netsh ipsec static show store
netsh ipsec static show filterlist ?
netsh ipsec static add filter ?
netsh ipsec static delete filter ?
netsh ipsec static exportpolicy ?
```

`doctor` 只读取帮助、系统版本、权限及系统代码页，不修改策略。自动解码依赖 BOM、ASCII 和 Windows OEM/ANSI 代码页；严格解码失败、NUL 或候选解码歧义会停止处理，需要管理员指定实测编码。JSON 始终 UTF-8，CSV 文件为 UTF-8 BOM。帮助正常不意味着实际写入及删除语义已经验证。

当前开发机器的只读结果见 [兼容性记录](docs/COMPATIBILITY.md)。测试 fixture 是合成中英文样本，**不是 Windows 10 实机输出的声明**。遇到未知字段保留原始文本和已解析字段、记录诊断，并禁用相关写入；应收集脱敏样本后扩展解析器再测试。

## 命令示例

`--config` 放在子命令前；未指定时读取当前目录的 `config.json`。

```powershell
uv run ipsec-manager --config config.json list --all --format json
uv run ipsec-manager --config config.json list --list inbound --format json
uv run ipsec-manager --config config.json export --all --format csv --output C:\Temp\filters.csv
uv run ipsec-manager --config config.json export --list inbound --format json
uv run ipsec-manager --config config.json check --list inbound --ip 122.192.10.20
uv run ipsec-manager --config config.json check --list inbound --ip 203.0.113.10 --mode add-coverage
uv run ipsec-manager --config config.json add --list inbound --ip 203.0.113.10 --description 手工添加 --dry-run
uv run ipsec-manager --config config.json delete --list inbound --record-id <record_id> --revision <revision> --dry-run
```

真实添加/删除须由管理员授权和配置启用后去掉 `--dry-run`。dry-run 会重新读取、校验完整性并取得写锁，返回预计操作，但不备份、不写策略、不追加写审计；允许在写功能关闭时查看计划，不代表已获得执行权限。删除 dry-run 仍要求记录唯一、条件支持且 revision 匹配，并返回实际删除语义开关状态。

`source-range` 检查 IPv4 源网段，返回全部命中与无法判断的记录。连续掩码用 `strict=False` 规范化；网络地址与广播地址均属于网段。`add-coverage` 只认定目标 me、协议 ANY、任意端口、非镜像的已支持条件。未知条件可能影响覆盖时拒绝添加。支持读取 DNS、IPv6、范围、DHCP/DNS/WINS/GATEWAY 等特殊地址，第一版不将它们转换为写操作。

固定添加条件：源单 IPv4 `/32`、目标 me、ANY、源/目标端口 0、mirrored=no。描述上限 256 字符，拒绝双引号、换行、NUL、其他 C0 控制字符和 DEL。命令以参数数组传递，不经过 shell；合法描述中的 `&`、`;`、`$()` 等保持字面值。

删除必须从最新 `list` 结果取 `record_id` 与列表 `revision`。record_id 是包含列表身份、地址、掩码、协议、端口和镜像条件的 SHA-256；描述不参与定位。完全重复的条件生成同一标识，`duplicate_count>1` 时禁止删除。revision 稳定排序且保留重复数量，包含描述变化，过期 revision 返回 conflict。缺少 GUID 时身份明确标注为名称回退。删除只支持完整且可安全表达的 IPv4/me/any 条件；特殊地址带无法确认语义的掩码也拒绝删除。

JSON 导出保留描述原值、完整条件、原始记录和解析诊断。CSV 将全部条件展开并包含快照生成时间、主机、列表元数据、revision、告警，空列表也有元数据行。文本公式前缀（包括前置空白后 `= + - @` 及起始制表/换行）会加单引号，避免 Excel 执行公式。输出路径仅本地 CLI 可用，目标文件必须不存在，避免覆盖其他文件。网络导出直接返回白名单列表的数据，不接受路径。

## 返回协议

stdout 始终只有一个 JSON 对象，日志写 stderr；正常 CLI 退出码如下。`list --format csv` 把 CSV 放入 `data.content`，避免破坏 JSON 协议。`export --output` 返回输出路径和查询快照。

```json
{"ok":true,"status":"success","request_id":"UUID","data":{},"error":null}
```

| status | 退出码 | 含义 |
| --- | ---: | --- |
| success / already_covered | 0 | 完成 / 已有相容条件覆盖，无新增写调用 |
| invalid_input | 2 | 输入、配置或导出路径无效 |
| not_found | 3 | 列表或记录不存在 |
| conflict | 4 | revision/GUID 冲突、备份期间变更或锁超时 |
| unsupported | 5 | 不完整解析、不支持的选择条件、兼容性未确认、读取失败 |
| permission_denied | 6 | 开关、权限、白名单、签名、重放或审计不可用 |
| backup_failed | 7 | 完整备份失败，未调用写命令 |
| verification_failed | 8 | 复查得到快照，但未满足预期的唯一变更 |
| indeterminate | 9 | 超时、无法复查、写后审计失败或非预期异常；重新查询 |

范围检查可以 `ok=true` 但 `data.determinate=false`：这表示查询完成且仍有无法判断条件，不能解释为“不在范围”。写入结果同时提供 `configuration_verified` 与 `traffic_verified=false`；本工具从不承诺真实流量已通过。netsh 返回成功文字或退出码 0 均不能单独认定写入成功。超时即使即时复查看似符合也返回 indeterminate，不自动重试。

## 备份、审计与恢复

每次写操作先追加并同步审计 preparing，使用 `exportpolicy file=<唯一文件>.ipsec` 备份完整策略；同时要求命令无错误、文件存在且非空，并同步备份文件。然后重新查询防止备份期间变更，追加并同步 intent，最后执行一次写命令、复查记录集合、追加结果。审计包含服务器认证操作者、request_id、时间、操作、别名、前后 revision、结果与备份路径，不含密钥。已经覆盖的实际添加请求也记录审计。读请求不进行写审计。

备份不进行自动导入测试；非空文件检查不能替代人工在隔离环境验证恢复。最终审计失败时可能已经写入，此时返回 indeterminate，并保留之前的 intent。磁盘耗尽/掉电无法由普通文件同步完全消除风险，管理员须监控数据目录与备份保留策略。

修改可能影响远程桌面或 webhook 链路。上线前保留本机控制台/带外管理渠道，在专用列表验证并备份。程序不会自动 importpolicy。恢复流程：

1. 通过本机恢复渠道登录，停止管理入口并将 `write_enabled` 设为 false。
2. 查审计中的 request_id、备份路径与前后 revision，重新读取当前策略确定实际变化。
3. 优先通过本地安全策略界面人工恢复精确条件；若必须恢复完整备份，先备份当前策略并评估其他列表、策略和指派的影响。
4. 经管理员明确授权，在维护窗口手工执行 `netsh ipsec static importpolicy file="C:\ProgramData\IpsecManager\backups\policy-....ipsec"`。
5. 重新读取完整配置，并独立验证 RDP、管理入口和目标业务流量。需要延迟回滚任务时由管理员单独设计部署，不能依赖已断网的客户端。

## webhook

见 [webhook 部署说明](webhook/README.md) 和 [hooks.example.json](webhook/hooks.example.json)。提供固定 list/export/check/add/delete 五个 POST hook，签名覆盖原始完整请求体，Python 再验证签名、操作绑定、时间窗口和持久 request_id 防重放。所有解释器/配置路径与 operation 均由服务器固定；客户端只能传白名单别名和业务字段。

## 测试与真实验收

```powershell
uv run pytest -q
```

默认所有测试只使用合成 fixture、mock 或磁盘模拟存储；并发测试启动两个进程使用真实文件锁，最终仅模拟创建一条。覆盖中英文、多列表/空列表/39 条、数量/字段/解码错误、IPv4 边界和非法掩码、覆盖保守判断、重复添加、删除冲突/重复条件、备份/审计失败、注入、超时、复查异常，以及签名/过期/重放与 hook 固定参数检查。

真实写测试默认跳过。完整流程和实机验收记录模板见 [集成测试说明](docs/INTEGRATION.md)。它需要明确授权的独立、空白、未指派测试列表与独立配置，不能使用生产列表；本次实现未执行任何真实写测试、服务安装或网络部署。

参考接口：[Microsoft netsh IPsec](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-ipsec)、[adnanh/webhook 2.8.2](https://github.com/adnanh/webhook/tree/2.8.2)。本机帮助和专用测试列表验证优先于网络参考文档。
