# 真实 Windows 集成验收（明确授权后执行）

默认 `pytest` 不修改任何真实策略。下面的 opt-in 测试会调用真实添加和删除，只有用户明确授权后才能运行。首先由管理员在隔离机器上手工准备**未指派策略的、空白的**专用列表，名字以 `__ipsec_manager_test_` 开头；本项目不会创建列表或策略。

1. 在目标 Windows 10 管理员会话保存版本、`show store` 和四项 `?` 帮助，确认本地存储和参数语义。
2. 实测编码，收集真实 verbose 中英文/空列表/不存在列表输出，检查 parser 对计数、GUID、掩码及所有字段的识别；禁止通过删字段让诊断“消失”。新增脱敏 fixture 后运行离线测试。
3. 在独立列表上使用手工准备的两条仅一个字段不同的条件验证删除精度，以及相同完整条件重复记录的删除行为。工具自身拒绝重复条件删除，不要在生产列表探索缺省参数。
4. 在隔离环境检查 exportpolicy 文件及手动恢复效果；由管理员确认之后才在专用集成配置设置 `delete_semantics_verified=true`。
5. 专用配置只保留一个别名 `integration`，固定预期 GUID；`write_enabled=true`，独立备份/审计目录，锁仍须与该机器其他实例共用。确认测试列表为空。
6. 记录实际子进程权限，并在明确授权后手工设置以下环境变量、运行单个集成测试：

```powershell
$env:IPSEC_INTEGRATION_CONFIG = 'C:\ProgramData\IpsecManager\integration.json'
$env:IPSEC_INTEGRATION_AUTHORIZE = 'I_AUTHORIZE_WRITES_TO_DEDICATED_TEST_LIST'
uv run pytest tests/test_windows_integration.py -q
Remove-Item Env:IPSEC_INTEGRATION_CONFIG,Env:IPSEC_INTEGRATION_AUTHORIZE
```

测试以 RFC 5737 文档地址 203.0.113.10 添加一条，确认重复添加无变化，再用最新 revision 删除该唯一记录。没有自动重试/异常自动清理；失败时可能留下一条记录，使用控制台检查状态、审计和备份再决定恢复。测试不会创建/指派/删除策略或列表，不作真实流量成功断言。

## 验收记录模板

| 项目 | 实测结果/证据 |
| --- | --- |
| 日期、Windows 版本/构建、语言 | 待填写 |
| 实际 OEM/ANSI/输出代码页与显式 encoding | 待填写 |
| 帮助原始字节、stdout/stderr、退出码 | 保存到管理员诊断目录 |
| 本地存储、管理员身份、目录 ACL | 待填写 |
| 真列表、空列表、不存在列表和失败输出 | 待填写 |
| 完整字段、数量、GUID 和特殊地址掩码 | 待填写 |
| 地址范围命中与未知条件处理 | 待填写 |
| 第一次添加、重复添加、复查与审计 | 待填写 |
| revision 冲突、完整条件唯一删除 | 待填写 |
| 两条相似条件及重复记录实际删除语义 | 待填写 |
| 完整备份有效性与隔离环境手动恢复 | 待填写 |
| webhook 签名、时间、重放、方法、raw body 传递 | 待填写 |
| webhook 继承权限与 HTTP 非零退出行为 | 待填写 |
| 配置验证与实际流量验证 | 分别记录，工具仅验证配置 |
| 本机/带外恢复渠道 | 待填写 |

确认所有项后才能评估生产启用；当前 COMPATIBILITY.md 仅为只读探测记录。

