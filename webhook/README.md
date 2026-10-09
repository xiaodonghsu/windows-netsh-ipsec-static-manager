# webhook.exe 部署

配置以 adnanh/webhook **2.8.2** 为参考。已核对该版本 [Hook Definition](https://github.com/adnanh/webhook/blob/2.8.2/docs/Hook-Definition.md)、[HMAC 规则](https://github.com/adnanh/webhook/blob/2.8.2/docs/Hook-Rules.md) 和 [参数提取源码](https://github.com/adnanh/webhook/blob/2.8.2/internal/hook/hook.go)。`raw-request-body` 从原始字节取得请求体，`pass-file-to-command` 产生每请求独立临时文件并把路径传入环境；因此 Python 可以独立验证同一个 HMAC。**不要改为 entire-payload**，它重新序列化 JSON 后会破坏原始字节签名。更换版本前重新验证这些字段和执行行为。本机未安装/运行 webhook.exe，配置的实际进程传递须部署时验收。

## 配置步骤

1. 将项目部署到管理员维护的 `C:\Program Files\IpsecManager`，用 uv 创建虚拟环境；填写受保护的 `C:\ProgramData\IpsecManager\config.json`。确保 Python `-I -m ipsec_manager --help` 能从固定工作目录导入安装的包。
2. 复制 hooks.example.json 到受保护目录。修改所有固定绝对路径，保留 `-I`、固定模块、固定配置与固定 operation。所有 hook 均只接收 POST，包括查询，这是因为查询也使用带签名的完整 JSON 请求体。
3. 管理员生成至少 32 字符高熵共享密钥，替换每个 hook 中明确的 `REPLACE_...` 占位符，并通过受保护的进程环境变量 `IPSEC_WEBHOOK_SECRET` 提供相同密钥。Python 拒绝未配置、过短或含 REPLACE 的密钥。此仓库不提供可用于生产的默认密钥；不得提交生产 hooks、配置或密钥。
4. 配置程序与解释器 ACL，尤其源码、site-packages、工作目录、hook 临时文件目录、配置、审计/replay.sqlite3 和锁目录。请求不能提交 actor；审计身份来自配置 `webhook.principal`，代表此共享密钥的持有人。需要多操作者归因时部署独立凭据/独立固定 hook 与服务器可信身份映射，不信任客户自己填的姓名或 HTTP 头。
5. 先保持 `write_enabled=false`，启动仅监听本机的入口，再验证认证和读取。真实写入必须经授权，由管理员启用写功能和已验证的删除开关。确认 webhook.exe 子进程实际继承管理员权限，不能根据“以服务运行”推断提权。

以下只是人工部署命令示例，本项目不会替你执行或安装服务：

```powershell
& 'C:\Program Files\webhook\webhook.exe' -hooks 'C:\ProgramData\IpsecManager\hooks.json' -ip 127.0.0.1 -port 9000
```

由支持 HTTPS、身份认证、来源限制、请求大小限制和限流的反向代理将管理网/VPN 请求转发到本机。对原始请求体不得重写；代理应要求 JSON Content-Type，并限制请求体到配置上限（默认 16 KiB）。网络错误/中间代理重试不得自动重复写操作。若直接监听管理网，必须另行明确配置允许的来源网段、传输保护与防火墙规则；代理场景由代理限制真实来源，不能将 webhook 所见的代理 IP 当成客户来源。

## 请求协议

所有请求体都是 UTF-8 JSON 对象，公共必填字段：

| 字段 | 说明 |
| --- | --- |
| operation | 与端点固定值相同，防止把读签名用于写 hook |
| timestamp | Unix UTC 秒数，整数，默认允许服务器时间 ±300 秒 |
| request_id | 每次新请求的 UUID；跨 hook 持久去重，失败请求也不能重用 |
| list | 服务器配置白名单别名，如 inbound |

签名头为 `X-IPsec-Signature: sha256=<HMAC-SHA256 十六进制>`，使用共享密钥对**实际发送的原始请求体字节**签名；包括时间戳和 request_id。Python 拒绝重复 JSON 键、未知字段和操作不匹配。不得使用 URL 查询参数代替业务请求体。

| 端点 | operation | 额外业务字段 |
| --- | --- | --- |
| /hooks/ipsec-list | list | 无 |
| /hooks/ipsec-export | export | format：json 或 csv，可选 |
| /hooks/ipsec-check | check | ip 必填；mode 可选 source-range / add-coverage |
| /hooks/ipsec-add | add | ip 必填；description 可选；dry_run 可选布尔值 |
| /hooks/ipsec-delete | delete | record_id、revision 必填；dry_run 可选布尔值 |

网络入口不接受全部列表枚举、真实列表名、程序/文件路径、任意命令参数、actor 或导出路径。导出直接返回数据，网络快照去除主机标识、原始记录文本与备份路径。签名无效时不消费 request_id；已通过签名、字段及时间检查的请求会在动作前持久消费 request_id。重放记录保留到整个有效时间窗口结束之后；重复请求被拒绝，不返回缓存执行结果。发生 timeout/indeterminate 时使用新 request_id 查询当前状态后由人决定下一步。

## 客户端示例

以下 Python 示例只查询，密钥从管理员提供的环境读取。修改 operation 时必须相应使用固定端点。

```python
import hashlib, hmac, json, os, time, uuid
import urllib.request

body = json.dumps({
    "operation": "check", "timestamp": int(time.time()),
    "request_id": str(uuid.uuid4()), "list": "inbound", "ip": "203.0.113.10"
}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
signature = "sha256=" + hmac.new(
    os.environ["IPSEC_WEBHOOK_SECRET"].encode("utf-8"), body, hashlib.sha256
).hexdigest()
request = urllib.request.Request(
    "https://management.example.invalid/hooks/ipsec-check", data=body,
    headers={"Content-Type": "application/json", "X-IPsec-Signature": signature}, method="POST"
)
# 实际代理地址由管理员填写；对 HTTPError 也读取业务 JSON，但不要自动重试写操作。
with urllib.request.urlopen(request, timeout=120) as response:
    result = json.load(response)
print(result)
```

## 返回与 HTTP 状态

开启 `include-command-output-in-response=true`，webhook 会等待 Python 退出。Python stdout 为单个统一 JSON，客户必须读取其中 `ok/status`，不得把“请求已接收”或 HTTP 200 当成已修改成功。

webhook 2.8.2 正常进程退出通常 HTTP 200，非零退出通常 HTTP 500；启用了错误输出返回以保留业务 JSON。规则不匹配配置 403；无效签名可能经过 webhook 错误处理而产生其他状态码，方法错误/代理拒绝也可能由入口产生。其 HTTP 状态机制不会自动把 conflict 映射到 409 或 permission_denied 映射到 403。`include-command-output-in-response-on-error` 还可能包含 stderr 或进程启动错误，因此部署验收必须测试错误路径；客户应允许入口错误无业务 JSON，不据此推断写结果。

代理超时应覆盖锁等待、备份及读写复查总时间（多个 netsh 调用），必要时按配置提高；不要仅根据单个 command_timeout 设置 HTTP 超时。收到网络超时，即使进程仍在执行也不能重复提交写请求。

## 部署验收

先验证：无签名、错误签名、超期时间戳、重复 UUID、读签名投递写 hook 均被拒绝；错误路径输出无堆栈/密钥。确认 POST 限制、完整原始 body 临时文件、固定参数数组、不调用 shell、真实子进程身份和管理员 ACL。再在独立专用测试列表进行授权后的添加/重复添加/带 revision 删除及配置复查。不要在生产列表上尝试未知删除语义，不自动导入完整备份。进一步的低权限入口/高权限服务与本地 IPC 隔离不在第一版实现范围。

