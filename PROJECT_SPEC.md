# Windows 10 本地 IPsec 筛选器管理项目

本文是交给 Codex 实现项目的需求与工程约束。请依据本文生成可运行的 Python 项目、测试、配置示例和中文使用文档。实现过程中可以读取系统配置，但不得未经用户明确授权修改当前机器的真实 IPsec 策略、安装服务或开放网络端口。

## 1. 项目目标

管理 Windows 10「本地安全策略 → IP 安全策略」中的筛选器列表，通过 `netsh ipsec static` 查询和修改本地存储。

必须提供：

- 查询所有筛选器列表及其记录，导出 JSON 和 CSV。
- 查询一个 IPv4 地址是否落在指定列表的源地址范围内，返回全部命中记录。
- 添加一个 IPv4 单地址记录；先检查覆盖关系，已覆盖时不重复添加。
- 精确删除一条筛选器记录。
- 提供本地 CLI，以及通过 adnanh/webhook（webhook.exe）调用 CLI 的配置示例。

“属于筛选器列表”不等于“允许访问”。允许、阻止或协商 IPsec 取决于关联规则、筛选器操作和策略启用情况。用户界面与返回结果不得混淆这两个概念。

## 2. 第一版范围

- 使用 uv 管理 python 项目，目标运行环境为 Windows 10，IPv4。
- 本地策略存储；不修改域策略。
- 查询和导出保留所有能识别的筛选条件及特殊地址类型。
- 添加仅支持固定模板：源 IPv4 `/32`、目标 `me`（我的 IP 地址）、协议 ANY、源/目标端口任意、`mirrored=no`。
- 删除仅支持能够完整解析、唯一定位且属于服务器允许管理列表的记录。
- DNS、IPv6、地址范围表达式和不支持的特殊类型必须明确标记；不得静默忽略或转换后用于写操作。
- 不创建、删除或指派策略，不修改筛选器操作，不自动重启服务。

## 3. 推荐项目结构

```text
ipsec-manager/
  pyproject.toml
  README.md
  config.example.json
  src/ipsec_manager/
    cli.py
    config.py
    models.py
    netsh.py
    parser.py
    matching.py
    service.py
    locking.py
    audit.py
  tests/
    fixtures/
    test_parser.py
    test_matching.py
    test_service.py
  webhook/
    hooks.example.json
    README.md
```

优先使用标准库；跨进程锁可使用维护中的库或 Windows 原生文件锁。将命令调用、文本解析、业务逻辑分离，便于通过模拟命令结果测试。无需 Web 前端、数据库或独立 HTTP 框架。

## 4. 配置

服务器配置包含：

- 允许修改的列表别名、真实名称和可选的预期 GUID。
- `netsh.exe` 绝对路径。
- 输出编码设置及自动检测策略。
- 命令超时、锁等待超时。
- 导出、备份、审计目录。
- 写功能开关，示例配置默认关闭。

网络请求只传列表别名，不接受任意列表名称、程序路径、文件路径或命令参数。配置、程序和目录必须由管理员维护。

## 5. 数据模型

列表字段：名称、GUID、描述、存储位置、修改时间、声明的记录数量、解析状态。

记录字段：

- `record_id`：规范化完整选择条件的 SHA-256 标识。
- 列表 GUID（无法获取时使用明确标注的列表身份）。
- 描述。
- 源地址类型、地址、掩码、规范化 CIDR。
- 目标地址类型、地址、掩码。
- 协议、源端口、目标端口、镜像标志。
- 原始文本、是否支持匹配、是否支持删除。

完整选择条件包含列表身份、源/目标地址与掩码、协议、端口及镜像标志。描述不参与删除定位。完全相同的选择条件生成相同标识，并标记重复数量，禁止假装能区分其中某一条。

列表快照生成 `revision`：对包含描述在内的规范化完整记录集合稳定排序后求哈希，保留重复数量。删除必须提交预期 revision，防止基于过期查询结果执行操作。

## 6. 查询与解析

参考读取命令：

```powershell
netsh ipsec static show filterlist all level=verbose format=list resolvedns=no wide=yes
netsh ipsec static show filterlist name="特定网段到本机的访问" level=verbose format=list resolvedns=no wide=yes
```

实现前在目标机器读取相关 `?` 帮助，确认 Windows 10 实际支持的参数。网络文档不能替代本机兼容性验证。

- 使用字节方式捕获 stdout/stderr，再按配置和可靠的系统编码信息解码；不能假定 UTF-8 或仅凭中文系统假定某个固定编码。
- 支持中文和英文输出字段；用状态机识别列表头与筛选器块，不依赖固定行号或简单全局分割“描述”。
- 兼容空描述、空行、CRLF、额外空格和特殊地址标记。
- 解析记录数必须与声明数量一致；字段缺失、解码失败、数量不一致时保留诊断信息并禁止相关写操作。
- 读取原始命令结果可用于诊断，但网络响应不要暴露不必要的主机信息。
- 实测空列表、不存在的列表及命令失败输出，不能把异常输出解析成空列表成功。

JSON 使用 UTF-8；CSV 使用 UTF-8 BOM，便于 Excel 打开。CSV 对来自描述等文本字段的公式前缀进行安全处理，原始值在 JSON 中保留。导出整个查询快照，并包含生成时间、主机标识和解析告警。

## 7. IP 范围查询

使用 `ipaddress.IPv4Address` 和 `IPv4Network`。支持连续 IPv4 掩码，并使用 `strict=False` 规范化网络地址；对非连续掩码明确报错，不自行推断。

返回字段：输入 IP、列表、revision、全部命中记录、无法判断的记录及原因。

区分：

- `source-range`：仅检查源地址范围，不能推断访问权限。
- `add-coverage`：仅计算与添加模板相容的记录是否覆盖输入 IP；第一版采用保守规则，只认定目标 me、ANY、任意端口、非镜像的已支持记录。

存在未知记录时可以返回部分查询结果，但不得把“不确定”表述为“不在范围”。添加流程发现可能影响覆盖判断的未知记录时，应拒绝写入并提供原因。

## 8. 添加流程

1. 验证写功能开关、管理员权限、列表白名单和合法 IPv4；第一版不接受 CIDR 作为添加输入。
2. 获取机器级跨进程写锁。
3. 重新读取列表，校验列表身份及解析完整性。
4. 检查与添加模板相容的覆盖记录。已覆盖返回 `already_covered` 和命中记录，不执行写命令。
5. 创建完整策略备份；备份失败则停止写入。
6. 使用固定模板构造参数数组；描述限制长度并拒绝换行、NUL 等控制字符。
7. 执行添加命令，再重新读取列表确认预期记录存在、其他记录未出现意外变化。
8. 写审计日志并释放锁。

命令形态（需本机确认）：

```powershell
netsh ipsec static add filter filterlist="特定网段到本机的访问" srcaddr=203.0.113.10 srcmask=255.255.255.255 dstaddr=me protocol=ANY mirrored=no description="xxxx用途"
```

不要仅凭进程退出码或某个中文成功字符串判断操作成功。超时或无法确认修改结果时返回 `indeterminate`，让客户端重新查询，不自动重复执行写命令。

## 9. 删除流程

客户端提交列表别名、record_id 和预期 revision。

1. 验证权限及配置，获取跨进程写锁。
2. 重新查询并核对 revision；不同则返回 `conflict`。
3. 根据 record_id 获取服务器保存/重新计算的完整条件，不使用客户端提交的 netsh 参数。
4. 若不存在、存在多个相同条件、解析不完整或无法表达为安全的删除命令，拒绝操作。
5. 备份后按完整条件调用 `delete filter`，显式指定能够指定的掩码、协议、端口和镜像参数。
6. 重新查询，确认目标条件消失且其他记录保持一致，记录审计日志。

不允许按描述、行号或单独源 IP 删除。不允许暴露 `delete all`、`delete filterlist` 或其他宽泛删除命令。不要假定缺省参数一定只删除一条；先在独立测试列表确认实际删除语义。

## 10. CLI 与返回协议

建议入口 `ipsec-manager`：

```text
ipsec-manager list --all --format json
ipsec-manager list --list inbound --format json
ipsec-manager export --all --format csv --output <本地路径>
ipsec-manager check --list inbound --ip 122.192.10.20
ipsec-manager add --list inbound --ip 203.0.113.10 --description 手工添加
ipsec-manager delete --list inbound --record-id <id> --revision <revision>
ipsec-manager add ... --dry-run
ipsec-manager delete ... --dry-run
```

`--dry-run` 读取并验证当前状态，返回预计操作，不执行写命令。网络入口不可接受任意导出路径；网络导出直接返回数据或返回服务器管理的导出标识。

stdout 只输出一个 JSON 对象；日志写 stderr。统一包含 `ok`、`status`、`request_id`、`data`、`error`。非预期异常不向客户端返回堆栈。

业务状态包括 `success`、`already_covered`、`not_found`、`conflict`、`invalid_input`、`unsupported`、`permission_denied`、`backup_failed`、`verification_failed`、`indeterminate`。CLI 提供稳定退出码并在 README 中说明。

## 11. webhook.exe 集成

使用 adnanh/webhook，配置固定的读取、检查、添加和删除 hook。每个 hook 启动固定绝对路径的 Python 解释器及固定程序，operation 为服务器端固定值；请求只提供允许的业务字段。

- 限制 HTTP 方法；写操作只能 POST。
- 配置请求签名校验，推荐 HMAC-SHA256；具体字段按选用版本文档验证。
- 签名保护完整请求体，其中包含时间戳和 request_id；Python 再检查时间窗口与重放记录，不能依赖签名本身防止重放。
- 启用等待程序执行并返回输出，避免返回“已接收”被误解为修改成功。
- 明确 webhook 的 HTTP 状态行为与业务 JSON 状态的区别；不要承诺它自动提供自定义 REST 状态映射。
- 优先仅监听本机，由支持 HTTPS、认证、请求大小限制和限流的反向代理暴露到管理网或 VPN。直接监听管理网需明确配置允许来源。
- webhook 与 Python 的权限继承必须验证。高权限部署时，程序、配置、工作目录和解释器路径必须受管理员 ACL 保护。
- 不使用 `cmd /c`、PowerShell 拼接脚本、`shell=True` 或客户端控制的 execute-command。

提供可修改的 hooks.example.json 和部署说明，所有密钥均为明确占位符，不生成可误用于生产的默认密钥。不得把密钥写入审计日志。

如后续要求低权限网络入口与高权限执行隔离，再扩展管理员 Windows 服务和受 ACL 保护的本地 IPC；第一版不必自行增加这套复杂架构。

## 12. 并发、备份与恢复

- 所有写操作通过机器级跨进程锁串行执行；锁覆盖读取、去重、备份、修改、验证和审计。
- 锁不能阻止管理员在 GUI 或其他工具中修改，必须通过 revision 和前后快照检测外部变更，文档明确这一限制。
- 写操作前使用 `netsh ipsec static exportpolicy` 备份到受保护目录；确认命令结果和备份文件有效。
- 完整导入可能影响其他策略，程序不自动盲目执行 importpolicy。
- 审计记录操作者身份（只信任已认证链路）、request_id、时间、操作、列表、前后 revision、结果和备份路径。
- 审计持久化不可用时，在执行写操作前拒绝写入。
- 说明修改可能阻断远程桌面或 webhook；上线测试应保留本地恢复方式。超时回滚任务作为可选扩展，不能依赖可能已断网的客户端恢复。
- 不保证配置写入后立即生效；实际流量验证与配置验证分别报告。

## 13. 测试与验收

默认测试不修改真实系统策略。通过 fixture 和模拟命令执行器覆盖：

- 中文/英文输出，多列表、空列表、39 条等数量校验、空描述和特殊地址。
- 解码失败、缺字段、数量不符、不存在列表、命令超时。
- `/16`、`/24`、`/32`、网络与广播地址边界、非法 IP、非法掩码。
- 地址命中但协议/目标不相容时，不误判添加已覆盖。
- 重复添加无写调用；未知匹配条件阻止写入。
- 删除过期 revision、重复条件、不存在记录均不执行删除。
- 备份失败、审计不可用时不执行写入。
- 并发进程添加同一 IP 最终仅创建一条；该测试可使用模拟存储。
- 描述和输入中包含命令注入内容时不进入 shell，非法输入被拒绝。
- 写命令返回成功但复查不符合预期时报告失败或不确定。
- webhook 未认证、签名无效、过期时间戳和重复 request_id 被拒绝。

真实 Windows 集成测试必须单独启用，并由用户明确授权在专用测试列表上执行。记录实际 Windows 版本、命令帮助、输出编码、重复记录删除行为、权限及策略生效表现；不使用生产列表做破坏性验证。

验收要求：CLI 四类功能可运行；导出保留完整条件；添加幂等；删除精确且防止过期操作；错误不会误报成功；测试通过；中文 README 包含安装、权限、配置、示例、webhook 部署和恢复步骤。

## 14. Codex 执行顺序

1. 检查工作区现有工程约束，创建项目结构和示例配置。
2. 实现数据模型、解析器、范围匹配及离线测试。
3. 实现只读 netsh 适配器和 CLI，核实目标环境兼容性。
4. 实现带锁、备份、审计、复查的写操作，通过模拟测试验证。
5. 提供 webhook 配置与部署说明，验证参数传递及认证流程。
6. 完成 README、运行测试，汇报实现内容和尚未实测的 Windows 行为。
7. 只有获得明确授权后，才进行真实策略修改、服务安装或网络部署。

## 15. 参考资料

- Microsoft netsh IPsec：https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-ipsec
- adnanh/webhook：https://github.com/adnanh/webhook
- webhook Hook Definition：https://github.com/adnanh/webhook/blob/master/docs/Hook-Definition.md

以上资料用于接口参考；Windows 10 本机帮助和专用测试列表验证结果具有实现兼容性上的优先级。
