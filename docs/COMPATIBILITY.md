# 当前只读兼容性记录

检查日期：2026-10-09（用户所在时区 Asia/Shanghai）。未执行任何真实策略写入、策略备份、导入、服务安装或端口开放。

| 项目 | 观察 |
| --- | --- |
| 开发机器版本 | Windows NT 10.0.26100.0（Windows 11；不能替代 Windows 10 验证） |
| show store | `Store : Local Store`，新进程默认本地存储 |
| show filterlist ? | 支持 name/rule/all、level、format、resolvedns、wide |
| add filter ? | 支持 filterlist、srcaddr/dstaddr、description、protocol、mirrored、srcmask/dstmask、srcport/dstport；端口 0 表示任意 |
| delete filter ? | 支持地址、掩码、协议、端口和 mirrored；帮助声明 exact match，尚未通过真实删除确认 |
| exportpolicy ? | 支持 file 参数，默认追加 `.ipsec` 扩展名 |
| all 查询 | `ERR IPsec[05073] : Unable to open Policy Store` |
| 不存在列表只读查询 | 同样返回策略存储错误，不能确认不存在列表的实际输出格式 |
| 当前编码自动检测 | 英文 ASCII 错误输出可解码，帮助包含非 ASCII 标点导致 OEM/ANSI 候选歧义，程序正确拒绝自动选择 |
| 空列表与完整列表样本 | 未能从真实存储取得；tests/fixtures 中为合成样本 |
| webhook.exe | 未在本机启动；参考 2.8.2 文档及原始 body 参数提取源码 |

尚未实测：目标 Windows 10 的字段变体/输出编码、真实空列表与不存在列表行为、管理员权限下存储访问、备份恢复文件有效性、重复条件删除语义、特殊地址掩码显示、真实修改与流量生效、webhook 临时文件/参数传递及 HTTP 错误输出行为。

这些限制不影响离线测试，但上线须按 INTEGRATION.md 验证。写功能默认关闭，真实删除还需要管理员确认 `delete_semantics_verified`。

