<p align="right">
  <b>简体中文</b> · <a href="README.md">English</a>
</p>

# NexaPipe

把位于 NAT 之后的 HTTP、HTTPS、WebSocket、TCP 与 UDP 服务，通过**一个**
[iroh](https://github.com/n0-computer/iroh) 端点暴露出去 —— **全程不持有证书、
没有控制平面、也不需要租任何服务器。**

一句话：**代理是一条管道，不是一个中间人。** 它读不到自己搬运的内容，不是你必须
信任的某个账号，也不租用别人的机器。代价见[为什么选择 NexaPipe](#为什么选择-nexapipe)。

NexaPipe 是一个 Rust workspace，由四部分组成：

- **`nexapipe`** —— 服务端：一个 L7 反向代理加一条 L4 隧道，通过 iroh/QUIC 接收
  流量并转发到真实后端；也可以直接提供明文 HTTP。TLS 不在这里终止 —— 而是透传给
  持有证书的后端。
- **`nexapipe-client`** —— 客户端库：连接池、域名到节点的路由、本地 HTTP 代理，
  以及基于 smoltcp 的 TUN 代理。以 `rlib`、`cdylib`（Android JNI）和 UniFFI 绑定
  三种形式发布。
- **`nexapipe-proto`** —— L4 隧道的线格式：`0x05` 前导、状态字节与 UDP 分帧。
  零依赖，两侧共用同一份代码，因此不可能对格式产生分歧。
- **两个应用** —— Android 客户端（`ui-android`，TUN/VpnService）与桌面客户端
  （`ui-desktop`，Tauri 2 + Vue 3），都在本仓库内（从原先的独立仓库导入，完整保留
  了 git 历史）。

[工作原理](#工作原理) · [为什么选择](#为什么选择-nexapipe) ·
[嵌入你的应用](#嵌入你的应用) · [目录结构](#目录结构) ·
[快速开始](#快速开始服务端) · [命令行](#命令行) ·
[配置](#配置) · [最小配置](#最小配置) · [TLS](#tls) · [TCP 与 UDP](#tcp-与-udp) ·
[2FA](#2fa-totp) · [端点邀请码](#端点邀请码) ·
[安全边界](#安全边界) ·
[客户端库](#使用客户端库) · [客户端应用](#客户端应用) ·
[开发](#开发) · [贡献](CONTRIBUTING.md) · [路线图](docs/ROADMAP.md) ·
[变更日志](CHANGELOG.md) · [v0.4.0 发布说明](https://open-nexa.github.io/nexapipe/v0.4.0.html)

---

## 工作原理

```
   客户端                        nexapipe 服务端                     你的局域网 / 主机
   ───────                       ───────────────                     ───────────────
   任意 HTTP 客户端 ── TLS ───►  按 SNI 的 passthrough     ── TCP ──►  Caddy :443（证书）
   nexapipe-client  ── QUIC ──►  L7 路由（Host + path）    ── HTTP ──► 后端 A   后端 B
   （本地代理 / TUN）             L4 隧道（tcp / udp）                  :18080  :15432  :3478
```

一条内层 TCP 连接对应一条 QUIC 双向流。这条流承载什么，取决于谁打开了它：一个
HTTP 请求（或 WebSocket 升级）、一个 TLS 会话，或一条 L4 流 —— 裸 TCP 连接或
UDP 流。对于 HTTP，服务端按 `Host` 路由，与普通反向代理完全一致 —— NAT 穿透发生
在底层，对应用和后端都是透明的。

流的**首字节**决定由哪个处理器接手，因此四类流量从不需要靠猜测来区分：

| 首字节 | 处理器 | 章节 |
| --- | --- | --- |
| `0x16` | TLS `ClientHello` → 按 SNI 路由，以字节转发 | [TLS](#tls) |
| `0x05` | L4 前导 → 裸 TCP 或 UDP，发往指定后端 | [TCP 与 UDP](#tcp-与-udp) |
| 其他 | HTTP 请求 | 本页 |

---

## 为什么选择 NexaPipe

三个特性，以及各自的代价 —— 因为天下没有免费的午餐。

- **它永不终止 TLS。** `ClientHello` 按 SNI 匹配后原样复制字节，因此会话在访客与
  你的后端之间端到端运行。代价：不透明的管道无法改写路径、无法基于请求做决策、
  无法探测 `/health`，访问日志记录的是字节数而不是请求行。（`mode = "http"` 是
  例外 —— 那里代理确实会解析请求。见[安全边界](#安全边界)。）
- **没有控制平面。** 一个二进制加一份 `config.toml`；不用注册账号，没有协调服务器，
  也没有第三方掌握着你的节点清单。代价：没有中心化的设备列表、没有远程吊销、没有
  SSO —— 新增客户端意味着编辑配置（运行中的服务端会在数秒内拾取）。
- **没有什么需要租。** 客户端通过 QUIC 直接打洞连到你的端点。代价：打洞大约只对
  90–95% 的连接成功，其余回落中继，所以凡是要依赖的服务都应自建中继 —— 而一旦你
  无论如何都要维护一台公网机器，"不用租服务器"就不再是什么明显优势。

什么情况下不要用它：

- **你的访客无法安装任何东西** —— NexaPipe 需要客户端；托管隧道对任何浏览器都只
  提供一个普通 URL。
- **你需要 SSO、ACL 和审计日志** —— NexaPipe 只认证客户端身份，然后对它开放全部
  路由。
- **一条经过中继的连接不可接受** —— 请用带固定中间机的方案。

---

## 嵌入你的应用

客户端本身是一个库，所以你的应用无需调用外部程序就能访问私有网络 —— 以 `rlib`、
Android JNI 用的 `cdylib`，以及面向 Swift/Kotlin/Python 的 UniFFI 绑定三种形式
发布。见[使用客户端库](#使用客户端库)。

---

## 目录结构

| 路径 | 说明 |
| --- | --- |
| `crates/nexapipe/` | 服务端二进制与库：CLI（`src/main.rs`）、配置、iroh 流处理（`src/conn/`）、HTTP/WebSocket 代理（`src/http/`、`src/proxy/`）、TLS 透传、L4 隧道（`src/l4/`）、路由（`src/routes/`、`src/lb/`）、健康检查、TOTP 2FA（`src/auth/`）。 |
| `crates/nexapipe-client/` | 客户端库（`lib` + `cdylib`）：连接池、域名→节点映射、本地代理、L4 客户端、smoltcp TUN 代理、QUIC 调优、JNI、UniFFI。 |
| `crates/nexapipe-proto/` | L4 线格式：`preface.rs` 与 `udp.rs`。零依赖，因此服务端与客户端都能链接它。 |
| `third_party/smoltcp` | 内置的 smoltcp 0.12，附带序列号下溢 panic 的补丁。通过 `[patch.crates-io]` 接入。不要改动。 |
| `ui-android/` | Android 应用（Kotlin + Compose）。 |
| `ui-desktop/` | Tauri 2 桌面应用（Vue 3 + TypeScript）。 |
| `config.toml.example` | 覆盖全部配置项的示例（服务端 + 客户端，2FA 关闭）。复制成 `config.toml` —— 该文件名已被 gitignore，它是运维者的实际配置。 |
| `config.toml.2fa.example` | 同上，但启用 2FA 并带有 `[auth.clients]` 条目。 |
| `run_android.ps1` | 一键 Android 调试循环（构建 → 安装 → 启动 → logcat）。 |

---

## 快速开始（服务端）

```bash
cargo build --release -p nexapipe

cat > config.toml <<'EOF'               # config.toml 已被 gitignore；这就是一份完整的服务端配置
[[routes]]
host_pattern = "*"
backends = ["http://127.0.0.1:3000"]    # 你想暴露出去的服务
EOF

cargo run -p nexapipe -- --config config.toml
```

三行就是一个能跑的服务端：一条全捕获路由、一个后端，其余配置全部取默认值。客户端
同样只需要几行，见[最小配置](#最小配置)（那里也列出了每个省略的键默认是什么）。
想要每个配置段都写出来的版本请从 `config.toml.example` 开始，想开启 2FA 则从
`config.toml.2fa.example` 开始。

启动时服务端会打印客户端需要的信息：

```
========================================
Proxy Connection Information
========================================
Node ID (stable, for server_node_id): 2f9c...
Ticket (for clients):                 endpoint:...
========================================
```

把 **Node ID**（稳定，但需要发现机制）或 **Ticket**（包含地址，地址变化时它也会变）
交给客户端。设置 `[iroh] secret_key` 可以让 Node ID —— 以及所有以 Node ID 为前提的
东西 —— 在重启后保持不变。Ticket 不同：它固化的是打印时的那组地址，`secret_key`
拦不住它过期，端点搬家后必须重新生成：

```bash
cargo run -p nexapipe -- --generate-secret
```

### Docker

```bash
mkdir -p config && cp config.toml.example config/config.toml   # config.toml 已被 gitignore
docker compose up -d --build
docker compose exec nexapipe tail -f /app/logs/nexapipe.log
```

`docker-compose.yaml` 挂载的是**目录** `config/`（你的 `config.toml` 就放在里面）
和一个 `logs/` 卷，并把 `NEXAPIPE_LOG_DIR` 指向该挂载点。`host.docker.internal`
已配置好，因此运行在 Docker 宿主机上的后端可以被访问到。已有部署迁移过来只需一条：
`mkdir -p config && mv config.toml config/config.toml`。

镜像也已发布到 GHCR（`linux/amd64` 与 `linux/arm64`），不必自己构建：
`docker pull ghcr.io/open-nexa/nexapipe:latest`。

#### 修改配置文件

配置文件每 5 秒重新读取一次，改动无需重启 —— 但**凡是会写入这个文件的操作，
都建议在容器内执行**：

```bash
# 用镜像自带的二进制，操作服务端真正在读的那份文件
docker compose exec nexapipe /usr/local/bin/nexapipe \
    --config /app/config/config.toml --generate-invite client-001 --registration
```

在宿主机上直接对这个挂载文件执行同样的命令，问题出在这几处：

- **挂载必须是目录。** 单文件 bind mount 锁定的是容器启动时该路径对应的 inode，
  凡是"写临时文件再 rename"的操作 —— `sed -i`、开了 atomic save 的编辑器、`mv` ——
  都会让容器继续读那个被换走的文件：改动永远进不来，而且**不报任何错**。
  `docker compose restart` 也没用，它不重建挂载；要 `docker compose up -d --force-recreate`。
  compose 里写的 `./config:/app/config` 正是为此 —— 目录挂载每次按名字解析，
  永远看得到当前那个文件；改回 `./config.toml:/app/config/config.toml` 就又把坑请回来了。
- **两个写者，没有锁。** 每次发生 2FA 尝试时，服务端都会重写整个文件，把
  `failed_attempts` / `locked_until` / `last_used` 落盘（`save_auth_state`）。
  两边的每次写入都是无锁的"读—改—写"，宿主机上的编辑和服务端的落盘一旦重叠，
  就会丢掉其中一次。最坏的情况是 `pending_enrollment` 令牌：服务端从不把它写回，
  所以输掉这次竞争等于白丢一个邀请码，日志里什么都不留。
- **宿主机的二进制不是服务端的二进制。** `--generate-invite` 的端点由
  `[iroh] secret_key` 推导，宿主机上那份配置若缺这个键 —— 或者 `nexapipe`
  是另一个提交编出来的 —— 生成的邀请码会指向一个没人在跑的端点。
- **权限与属主会被改掉。** 从宿主机重写后，文件可能变成 `0644` 或换了属主：
  持有凭据的配置随后会在启动时被拒绝，而且权限不恢复到 `0600`，reload 就无法
  把 2FA 打开。

挂载刻意是**可写**的：服务端要把 2FA 计数写回这个文件，挂成 `:ro` 会让锁定期
失去持久化，并且每次尝试都打一条错误日志。

用编辑器改没问题，前提是**原地保存**（`vim` 的默认行为，以及 shell 的 `>`
重定向）。改什么都别假设生效了，去日志里确认一次：

```bash
docker compose logs -f --tail=50 nexapipe | grep -i reload
# Detected config change, reloading...  →  Config reloaded: 3 routes now live
# Config not reloaded, keeping the current routes: ... → 被拒绝，旧路由继续服务
```

---

## 命令行

| 参数 | 说明 |
| --- | --- |
| `-c, --config <PATH>` | 配置文件（默认 `config.toml`）。 |
| `--local-proxy` | 以客户端本地 HTTP 代理运行，而非服务端。 |
| `--generate-secret` | 打印一个新的 iroh 密钥，用于稳定的端点身份。 |
| `--generate-2fa <CLIENT_ID>` | 生成 TOTP 密钥，写入配置并打印注册用二维码。 |
| `--force` | 配合 `--generate-2fa`：轮换已有客户端的密钥。 |
| `--show-2fa <CLIENT_ID>` | 打印已存在于 `[auth.clients]` 中客户端的二维码。 |
| `--issuer <NAME>` | 认证器应用显示的签发者标签。 |
| `--qr-format <FMT>` | `unicode`（默认）、`plain`、`ascii`、`svg`、`none`。 |
| `--qr-invert` | 反色绘制二维码（深底浅色）。 |
| `--qr-out <PATH>` | 同时把二维码写入文件（`.svg` → SVG，其他 → ASCII）。 |
| `--generate-invite [CLIENT_ID]` | 打印可扫描的 `nexapipe://` 邀请码。带 `CLIENT_ID` 时把 2FA 密钥也放进去；不带时只携带端点与域名。 |
| `--registration` | 配合 `--generate-invite CLIENT_ID`：用一次性注册令牌代替密钥。 |
| `--create-client` | 配合 `--generate-invite CLIENT_ID`：客户端尚不存在时创建它，并在同一次运行中生成并写入其密钥。 |
| `--invite-domains <LIST>` | 邀请码中的域名，逗号分隔（默认：`[local_proxy] proxy_domains`，否则取路由主机名）。 |
| `--invite-name <NAME>` | 与端点一同保存的标签。 |
| `--invite-relay <URL>` | 邀请码中的中继 URL（默认：`[iroh] relay_url`）。 |
| `--endpoint-id <NODE_ID>` | 要对外公布的端点（默认：由 `[iroh] secret_key` 推导）。 |

---

## 配置

`config.toml` 是服务端与客户端模式的唯一事实来源。所有配置项都是可选的。

文件每 5 秒重新读取一次并**即时生效**：`[[routes]]` 与
`[auth.clients]` 表无需重启；解析或校验失败的配置会被报告并忽略，因此一次只写了一
半的编辑不会把代理搞 down。其余配置在启动时只读取一次，需要重启：
`[server] listen_addr`、`[iroh]`、`[peers]`、`[auth]` 的 TOTP 参数，以及 `[log]`。

`[auth]` 这一段也可以在原本没有的情况下出现：启动时没有该段的服务端，同样会在后续
重载时拾取它的 `clients` 与 `enabled = true`，因此第一次开启 2FA 不需要重启。

有两处改动在运行中的服务端上被刻意做成单向的：`[auth] enabled = true` 会被配置
监视器拾取，但把 2FA 关掉会被拒绝（要禁用请重启）；而 `enabled = true` 与暴露的明文
监听器同时出现则直接被拒绝启动。

### 最小配置

一份完整的**服务端**配置 —— 一条全捕获 `http` 路由指向一个后端：

```toml
[[routes]]
host_pattern = "*"
backends = ["http://127.0.0.1:3000"]
```

一份完整的**客户端**配置（`nexapipe --local-proxy`），把 `127.0.0.1:8081` 变成
一个只隧道转发所列域名的 HTTP 代理：

```toml
[local_proxy]
enabled = true
listen_addr = "127.0.0.1:8081"
proxy_domains = ["app.example.com"]

[[local_proxy.nodes]]
server_node_id = "<服务端打印出来的 Node ID>"
domains = ["app.example.com"]
```

简写省略了什么，以及对应的默认值：

| 省略的键 | 得到的行为 |
| --- | --- |
| `[server] listen_addr` | 不监听明文端口 —— 流量只能经由 iroh 进来 |
| `[iroh] secret_key` | 每次重启都是新的 Node ID；不想让客户端每次都找不到服务端，就加上它（`--generate-secret`） |
| `[iroh] relay_mode` | `default`：使用 N0 中继，按延迟挑选 home relay |
| `mode` | `http` |
| `path_pattern` | `/`，前缀匹配 |
| `strategy` | `round_robin`（或 `random`，或 `least_conn` —— 优先给当前在途请求最少的后端） |
| `[health_check]` | 开启：每 10 秒 `GET {backend}/health`。后端没有这个端点时会被记为失败，但**只有一个后端的路由仍然照常转发** —— 那里没有第二个可挑的选项 —— 所以那只是日志噪音，不是故障；有多个后端且全部不健康时，直接回 503 且不再拨号。设 `enabled = false` 即可消停。 |
| `[log]` | `./logs` 下的滚动日志 + 控制台输出，查询参数值会被脱敏 |
| `[auth]`、`[peers]` | 不做任何认证 —— 启动时服务端会打印一条警告横幅。本机试用没问题；要拿去面对真正在意的服务时，至少加上 `[peers] allow`（或 2FA）。 |

本节之后的所有内容都是可选的。只有两个键不是：一条路由必须有 `host_pattern` 和
`backends`，一个 `[local_proxy]` 段必须有 `listen_addr` 和 `proxy_domains`。

### 顶层

`debug`（默认 `false`）开启调试日志。

**没有回落。** 没有任何路由的主机，HTTP 请求得到 404，`passthrough`、`tcp`、`udp`
查找则直接拒绝。"把所有请求都发到这里"写成一条全捕获路由 —— `host_pattern = "*"` ——
它和其它路由一样具备负载均衡与健康检查。旧的顶层 `default_backend` 已**移除**：仍然
写着它的配置会在启动时被拒绝，而不是被静默忽略，这样已有配置不会在无人察觉的情况下
从"转发"变成"404"。

通配符只有两种写法：单独的 `*`，或以 `*.` 开头。那个点是标签边界 —— 少了它，
`*.example.com` 会连 `notexample.com` 一起匹配，而后一个域名只是恰好以同样的字母
结尾，属于别人。`*example.com` 这类写法会在启动时被拒绝，`host_pattern` 与客户端的
`allow_hosts` 一视同仁。

### `[server]` —— 直接入口（默认关闭）

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `listen_addr` | *未设置 —— 不绑定* | 明文 HTTP 监听器。对该地址发起的 TLS 会话会被透传，而非终止。 |
| `expose` | `false` | `listen_addr` 要指定回环以外的地址时必须为 true。当 `[auth] enabled = true` 时启动会被拒绝。 |

**这个监听器上的任何流量都不经过认证**：2FA 握手运行在 iroh 的 accept 循环里，所以
从这里到达的请求在从未被要求出示凭证的情况下就能抵达路由。不设置 `listen_addr`
（默认值）或保持绑定在 `127.0.0.1`，只用于本机内部；绑定非回环地址还需要
`expose = true`，那会把每一条 `http` 路由和每一个 `passthrough` 后端都暴露给任何能
访问该端口的人。`expose = true` 与 `[auth] enabled = true` 同时出现时**启动会被
拒绝** —— 开着 2FA 时，这个组合读起来像受保护的代理，实际并不是。（旧版本只记一条
警告就照常启动。）

与隧道路径的一个差异：**WebSocket 升级在 iroh 上会被正常代理，在这里则返回
`426 Upgrade Required`** —— 该监听器没有 WebSocket 客户端。需要 WebSocket 的客户端
必须走隧道。

`tls_enabled`、`tls_listen_addr`、`cert_path` 与 `key_path` 仍被接受以便已有的
`config.toml` 能解析，但不再有任何作用，并会在启动时报告 —— 请删除它们并参见
[TLS](#tls)。

### `[iroh]` —— 隧道端点

| 配置项 | 说明 |
| --- | --- |
| `secret_key` | 由 `--generate-secret` 生成的十六进制密钥；保持 Node ID 稳定。 |
| `bind_port` | 固定 UDP 端口，而非临时端口。 |
| `bind_ipv6` | 同时在该端口上绑定 `[::]`，使端点也能通过 IPv6 应答。IPv4 套接字保留 —— 这是**增加一个**，不是替换；且 IPv6 绑定允许失败，没有 IPv6 的主机仍能启动。未设置 `bind_port` 时此项无效。 |
| `relay_mode` | `pinned` / `default` / `disabled` / `custom`。缺省即 `default`。 |
| `relay_url` | `relay_mode = "custom"` 时使用的中继；只设置它而不设 `relay_mode` 等同于 `custom`。 |
| `relay_auth_token` | 需要鉴权的 `custom` 中继所用的可选 bearer token。 |

中继模式：

- **`default`** —— 使用所有 N0 中继，按延迟选择归属中继。它可能在中继之间迁移，
  迁移会切断经由该中继的连接。
- **`pinned`** —— 固定使用一个 N0 中继（`aps1-1`，新加坡）。当中继迁移比稍慢的中继
  更难受时用它。
- **`disabled`** —— 完全不使用中继传输。这比听上去更强：你也无法通过*对端*的中继
  拨号。
- **`custom`** —— 一个你自己运行的中继，且**只用它**：既不作为归属中继，也不作为
  探测目标。把它指向 `*.relay.n0.iroh.link` 形式的 URL 会被拒绝；那类地址请用
  `pinned` 或 `default`。

写了 `relay_mode` 但不可用 —— 例如 `custom` 却没有 URL，或拼写无法识别 —— 会直接
阻止启动，而不是悄悄回落。在不接受 `relay_url` 的模式旁写了 `relay_url` 会被忽略
并记日志。

**任何 `relay_mode` 都无法改变的**：Endpoint ID 发现仍然会查询 `dns.iroh.link`，
而 `custom` 约束的是**本**端点 —— 广播了 N0 中继的对端仍会经由该中继被拨号。发现服务没有 NexaPipe
暴露出来的开关 —— iroh 1.2.0 本身有 `clear_address_lookup()`，但 NexaPipe 没有调用它。[仍然依赖第三方基础设施的部分](docs/iroh-boundaries.md)
完整写明了这条边界，包括 `custom` 买到了什么、没买到什么。

### `[[routes]]` —— 路由

```toml
[[routes]]
host_pattern = "comfyui.example.com"
path_pattern = "/"
path_is_prefix = true
strategy = "round_robin"          # 或 "random" / "least_conn"
backends = ["http://192.0.2.20:18188"]
mode = "http"                     # 默认
# path_rewrite = "/api"

[[routes]]
host_pattern = "app.example.com"
mode = "passthrough"              # TLS，按 SNI 路由；见下文 TLS
backends = ["caddy:443"]

[[routes]]
host_pattern = "db.example.com"   # 裸 TCP 服务，任意端口
mode = "tcp"
backends = ["192.0.2.30:15432"]

[[routes]]
host_pattern = "turn.example.com"
mode = "udp"                      # UDP 流，空闲超时以秒计
backends = ["192.0.2.40:13478"]
idle_timeout_secs = 60

# 同一个主机既要应答请求又要承载隧道 —— Android TUN 客户端的常见形态。
# `modes` 可写多个；`mode` 只写一个。
[[routes]]
host_pattern = "app.example.com"
modes = ["http", "tcp"]
backends = ["http://host.docker.internal:18080"]
```

| 模式 | 作用 | 传输安全 |
| --- | --- | --- |
| `http`（默认） | 解析请求，应用 `path_pattern` / `path_rewrite`，然后用共享的 HTTP 客户端重新发起。后端必须是 `http://` —— `https://` 后端在启动时会被拒绝。 | 入口段加密（QUIC；经 `listen_addr` 到达时是明文 HTTP），但**从服务端到后端是明文 HTTP**。任何敏感内容都应放在 `passthrough` 路由上，或放在载荷自带 TLS 的 `tcp` 路由上。 |
| `passthrough` | 复制字节。路由由 SNI 选择，因此 `path_pattern` 与 `path_rewrite` 不适用，后端也可以是裸 `host:port`。 | 端到端：字节是 TLS，服务端从不终止它，因此客户端校验的是后端自己的证书。见 [TLS](#tls)。 |
| `tcp` | 把裸 TCP 流送到 `backends`，由 L4 前导中的主机名选择。不做 HTTP 解析，不适用 `path_pattern`，没有健康检查。见 [TCP 与 UDP](#tcp-与-udp)。 | 到服务端为止由 QUIC 加密；之后是隧穿协议的原始字节 —— TLS、SSH 或任何东西都由你自己提供。 |
| `udp` | 承载 UDP 流 —— 每条流一条 QUIC 双向流，每个数据报一帧。选择方式同 `tcp`，另有 `idle_timeout_secs`。 | 到服务端为止由 QUIC 加密；载荷安全由隧穿协议负责（DTLS、WireGuard 等）。 |

没有任何模式会为后端终止 TLS：从服务端到 `backends` 这一段，加密程度取决于你放上
去的东西，只有 `passthrough` 能让客户端的 TLS 会话一直完整地抵达后端。

一条路由用 `mode = "..."` 提供**一种**模式，用 `modes = [...]` 提供**多种**模式；
两者可以同时写，路由提供的是并集，重复项会被合并。一条*连接*用哪种模式，仍然由它的
首字节决定，所以一条连接只会走一条路径。

共享同一份 `backends` 列表的代价是：该地址必须同时满足所有声明的模式，而 L4 的规则
更严格 —— **端口必须写出来**（`http://host` 单独用于 `http` 没问题，隐含 80 端口；
一旦加上 `tcp` 就会被拒绝）。一条路由只有一个后端池，所以不同模式需要不同后端时请
写成两条条目。

已移除但仍能解析并被忽略（启动时报告）的路由配置项：`cert_path`、`key_path` 与
`redirect_to_https`。

### `[health_check]` —— 探测 http 后端

```toml
[health_check]
enabled = true     # 默认 true —— 后端无法应答探测时改成 false
interval = 10      # 两轮检查之间的秒数
timeout = 5        # 单次检查超时秒数
threshold = 3      # 连续失败多少次后该后端离开后端池
path = "/health"   # 追加到后端 URL 之后
```

每个 `mode = "http"` 的后端都会被 `GET {backend}{path}` 探测，**连续**失败
`threshold` 次后离开后端池 —— 单次失败永远不会摘除它 —— 第一次探测成功即恢复。
`passthrough`、`tcp`、`udp` 路由从不探测：TLS 监听器和数据库无法回答一个 HTTP 请求。

**当你的后端无法提供健康检查端点时，请设 `enabled = false`** —— 静态文件服务器、
设备管理的 Web UI。关闭后所有后端都留在池里、流量照常转发。`enabled` 是热生效的：
重载配置会暂停已经在跑的检查；其余四个键在检查器启动时读取，改动需要重启，或对重载
中出现的新路由立即生效。

`interval`、`timeout`、`threshold` 都至少为 `1`：写 `0` 过去会被静默改成 `1`，而三者
各自的含义都不是任何人想要的 —— 每秒一轮探测、永远无法完成的探测、或一次失败就摘空
后端池。写 `0` 的配置在加载时会被拒绝。

### `[timeouts]` —— 等待后端的时间

```toml
[timeouts]
connect_secs = 10     # 默认：10 —— 拨号连接后端的上限秒数
response_secs = 30    # 默认：30 —— 等待后端应答的上限秒数
```

两个键的单位都是秒、都可以不写，默认值就是服务端一直以来的行为，所以写上这一段但
什么都不填，什么都不会改变。它们**都不限制一次请求能持续多久**：各自只覆盖「与后端
打交道的某一步」，而一旦响应头到达，之后的响应体要传多久都不受它约束。

| 键 | 约束的是什么 | 何时调大 |
| --- | --- | --- |
| `connect_secs` | 拨号。所有「朝一个后端开一条连接」的路径都用它：HTTP 请求（包括 WebSocket 升级）、TLS passthrough 与 `tcp` 隧道。 | 后端在慢链路或丢包严重的链路上 —— 太小会让每个请求都失败，而且表现得像后端挂了。 |
| `response_secs` | 等待后端的应答：状态行；对 WebSocket 而言是升级响应。响应头一到就结束。 | 后端需要先把结果算出来才回答。它同时也是「后端接受连接后一句话不说」这种情况的上限。 |

`0` 会在加载时被拒绝，超过 `3600` 同样如此：前者是任何后端都达不到的期限，后者描述的
已经不是慢后端，而是一台根本不再应答的机器 —— 那时没人会替你拿着这个请求槽。

等待**客户端**自己字节的超时刻意不在这里 —— L4 前导、TLS `ClientHello`、明文监听器
的首字节。那些是协议机制，不是「我该容忍后端多久」。

这两个键在启动时读取一次，改动需要重启。

### `[admin]` —— 辅助监听（默认关闭）

```toml
[admin]
listen_addr = "127.0.0.1:9090"   # 不写 => 完全不绑定这个监听

[metrics]
enabled = true                   # 在该监听上提供 /metrics；默认 false
```

第二个监听，回答的是**本实例自身**的问题，而不转发流量：

| 路径 | 认证 | 用途 |
|---|---|---|
| `GET /healthz` | 无 | 只要进程还在服务就返回 `200 ok`。 |
| `GET /metrics` | 无 | Prometheus 文本格式的实例指标，仅在 `[metrics] enabled = true` 时提供。 |
| `GET /v1/status` | token | 运行时长、计数器、后端健康度、各项开关。 |
| `GET /v1/routes` | token | 当前生效的路由表 —— 即最后一次重载之后的内容。 |
| `GET /v1/clients` | token | 有哪些客户端。绝不含它们的密钥。 |
| `GET /v1/connections` | token | 当前连接着的对端。 |
| `GET /v1/health` | token | 后端池，在/不在轮转中。 |

命令行下用 **`nexapipe status`** 读，除配置外无需参数：

```bash
nexapipe status --config config.toml          # 分组输出，给人看
nexapipe status --config config.toml --json   # 单个 JSON 文档，给脚本看
```

它问的是正在运行的进程，而不是重新打开配置文件，所以打印出来的是**已加载**的内容
—— 包括启动之后任何一次重载改动过的部分。

**token 是生成的，不是配置的。** 首次启动时服务端把它写进 `<config>.admin-token`，
权限为仅运行服务的账户可读，并在日志里说明位置。配置里**故意没有** `token` 键：那会
把凭据放进一个你会编辑、复制、提交的文件里，而且回写它会触发监听配置文件 mtime 的
重载。`nexapipe status` 读同一个文件，且绝不创建它 —— 它自己造的 token 服务端并不
认识。要轮换就删掉文件再重启。

`/v1/*` 有意只做只读。`client add` 和 `client revoke` 依赖尚未落地的按设备身份模型，
而一个只回答问题的接口，是没法被说服去改动任何东西的。

`[metrics] enabled` 默认是关的，因为它所依附的监听没有认证：必须**同时**开启它
并绑定地址，才会有东西暴露出来。只开 `enabled` 而没有 `[admin]` 段会记一条警告且
不提供任何内容。监听已起但指标关闭时，`/metrics` 返回 **404 而不是空** —— 指向一个
从未开启指标的部署的采集器，必须能区分"没开"和"还没流量"。

**只允许 loopback，且没有 `expose` 开关。** `[server] expose` 存在是因为明文监听可能
位于另一个做鉴权的组件之后；而这个监听上的任何内容都不该从网络可达 —— 它会说出你的
路由、客户端和后端。绑定非 loopback 地址会在启动时被拒绝。要从别的主机采集，用隧道
（`ssh -L 9090:127.0.0.1:9090 …`）。

**`listen_addr` 不支持热重载** —— 迁移监听等同于重启。这两段里的其余键都只在启动时
读取一次。

完整的重载规则见[重载会应用哪些配置](#重载会应用哪些配置)。

`/metrics` 报告的内容：连接数（累计、当前，以及按路径是直连还是中继分）、按状态码
分类的请求数与耗时毫秒、按协议和状态分类的 L4 流、在/不在轮转中的后端数、仍在处理的
连接数，以及运行时长。后端健康度在渲染页面时从活动的后端池读取，所以重载配置改动了
后端池会在下一次采集时体现。请求与流是分开计的，这是有意的：一条 L4 流是一条想开多久
就开多久的隧道，把它算作请求会把两种不同单位塞进同一个数字。

### `[local_proxy]` —— 客户端模式

```toml
[local_proxy]
enabled = true
listen_addr = "127.0.0.1:8081"
proxy_domains = ["app.example.com"]
strategy = "round_robin"

[[local_proxy.nodes]]
server_node_id = ""               # 服务端的稳定 Node ID
domains = ["app.example.com"]
```

同一个域名可以出现在多个节点上，这正是跨多台服务器做负载均衡的方式。
`[local_proxy]` 层级的 `server_ticket` 与 `server_node_id` 仍然可用但已废弃 ——
优先使用 `[[local_proxy.nodes]]`。

### `[peers]` —— 允许哪些 Node ID 连接

这是最先执行的一道检查：在 QUIC 握手期间、连接被接受之前生效的客户端公钥
白名单。名单外的对端只会收到一个应用错误码为 `5` 的关闭帧，此外什么都没有 ——
不打开任何流，也不占用任何配额。

```toml
[peers]
# 客户端的 Node ID，与应用中显示的完全一致。没有通配符形式：
# 这些是 ed25519 公钥，不是主机名。
allow = [
  "a1b2c3d4e5f6...",
  "0f1e2d3c4b5a...",
]
```

它不是第二重因子，也不替代 2FA：它回答的是*这个 Node ID 是否该出现在这里*，
而 2FA 回答的是*它是谁* —— 所以它是给关闭了 2FA 的服务端准备的开关，两者
可以叠加使用。

- **缺省或省略该键** —— 任何能连到端点的对端都继续进入下一道检查。
- **写错会在启动时失败** —— 不是合法 Node ID 的条目是错误，不会被静默跳过。
- **`allow = []` 会被拒绝** —— 那会把运维者自己锁在服务端之外。
- **目前仅启动时读取**，与 `[iroh]` 一样。

### `[log]`

轮转日志文件加控制台输出。`file`、`dir`、`file_name`、`access_log`、
`rotation`（`daily` / `hourly` / `never`）、`max_size_mb`、`max_files`、
`console`、`redact_query`。`NEXAPIPE_LOG_DIR` 会覆盖 `dir`。

`redact_query`（默认 `true`）会替换访问日志查询串中的取值，保留参数名 —— 令牌、
签名和一次性验证码都在查询参数的值里传递，而日志文件会被轮转、归档并转手。没有
`=` 的参数（`?raw`）是一个标志位，保持原样；路径不处理。设置
`redact_query = false` 可原样记录 URI。

```text
/api/v1/items?token=hunter2&page=2   ->   /api/v1/items?token=<redacted>&page=<redacted>
```

**每个请求都有一个 id。** 32 位十六进制，追加在该请求的访问日志行末尾，并作为
`x-request-id` 返回给客户端 —— 谁要报一个异常的响应，就能直接指出对应的那一行：

```text
203.0.113.9 - - [29/Sep/2026:13:52:04 +0800] "GET /api/v1/items" 200 512 12ms id=3f9ac1…
```

同一个 id 也是包裹该请求的 `request` span 上的一个字段，因此 `tracing` 的输出里
也带着它，连同 `method`、`uri`、`status`。L4 流量与 TLS 透传是隧道而非请求：它们
的 id 出现在访问日志与 span 上，但没有 HTTP 响应可供加头。

### `[acme]`

已移除。证书现在归后端所有；该配置节仍能解析但会被忽略，并在启动时报告。
见 [TLS](#tls)。

### 重载会应用哪些配置

配置文件被监视，改动无需重启即可生效 —— 但不是每个键都可以。与其把这条规则散落在
上面各节里，这里汇总成一张表：

| 键 | 重载时 |
|---|---|
| `[[routes]]` | 生效。后端会被重新探测；已建立的连接保留其授权时所用的路由。 |
| `[auth]` | 生效，含 `enabled` —— 打开 2FA 会开始对重载之后新建的连接生效。含密钥的文件必须是 `0600`，否则重载被拒。 |
| `[health_check]` | 生效。`enabled` 暂停/恢复探测；其余键对重载新增或改动的路由生效。 |
| `[timeouts]` | 需重启：启动时读取一次，与 `[server] listen_addr` 同理。 |
| `[peers] allow` | 目前需重启。 |
| `[iroh]` | 需重启：端点只绑定一次。 |
| `[server] listen_addr` | 需重启 —— 迁移监听等同于重启。 |
| `[admin] listen_addr` | 需重启，原因同上。其余部分是实时的：`/v1/*` 每次请求都读当前的路由、客户端与后端池。 |
| `[metrics] enabled` | 需重启，只在启动时读取一次。 |
| `[log]`、`[local_proxy]` | 需重启。 |

被拒绝的重载会继续用旧配置服务，并在日志里说明原因，所以一个拼写错误不会让正在工作
的实例下线。

---

## TLS

TLS 由**后端**终止，而不是本代理：代理不持有任何证书，也永远看不到一个 `https://`
请求的明文。

1. 客户端照常发起 TLS 会话 —— 经由本地 HTTP 代理、TUN，或直接连到
   `[server] listen_addr`。
2. 代理识别出 `ClientHello`：它的首字节是 `0x16`，任何 HTTP 请求都不可能以它开头。
3. SNI 与 `mode = "passthrough"` 路由匹配，该会话的每一个字节都被复制到那条路由的
   后端。

全程不解密，所以 WebSocket、gRPC 与 HTTP/2 都不需要改动即可工作。经 `CONNECT` 或
TUN 到达的 TLS 会话走的是另一条路径：客户端用 L4 前导声明 host 与 port，而不是交出
`ClientHello`，因此它匹配的是 `mode = "tcp"` 路由。所以，一个你希望两种方式都能访问
的域名需要**两种**模式 —— 写成两条条目，或写成一条带
`modes = ["passthrough", "tcp"]` 的条目（当同一个后端同时服务两者时）。见
[TCP 与 UDP](#tcp-与-udp)。

### Caddy

把一条 passthrough 路由指向 Caddy，让 Caddy 持有证书：

```toml
[[routes]]
host_pattern = "app.example.com"
mode = "passthrough"
backends = ["caddy:443"]          # 或 "https://caddy:443"，scheme 会被忽略
```

```caddyfile
{
	email you@example.com
}

*.example.com {
	tls {
		dns cloudflare {env.CF_API_TOKEN}
	}
	@app   host app.example.com
	@comfy host comfyui.example.com
	reverse_proxy @app   http://host.docker.internal:18080
	reverse_proxy @comfy http://192.0.2.20:18188
}
```

请使用 **DNS-01** 质询：被代理的域名在隧道内部解析为一个回环地址，因此入站的
`HTTP-01` 请求永远到不了 Caddy —— 而 DNS-01 还意味着 Caddy 不需要公网 IP。像
`*.example.com` 这样的通配符让新增子域名不再有成本。官方的 `caddy` 镜像不附带任何
DNS provider：用 `xcaddy` 或 `-builder` 镜像把
`github.com/caddy-dns/cloudflare` 构建进去。

### passthrough 的代价

passthrough 路由是不透明的，因此访问日志记录的是字节数而不是请求行，`/health`
探测不适用，代理也无法改写路径或把 `http://` 重定向到 `https://`。这些工作交给
Caddy，它能看到解密后的请求。普通的 `http://` 路由保留全部能力。

---

## TCP 与 UDP

数据库线协议、MQTT 或 STUN socket、游戏服务器 —— 它们都不说 HTTP 或 TLS，而 UDP
根本不携带主机名，所以无法通过读取载荷字节来路由。L4 隧道也不读取载荷：客户端把
一段**前导**写在双向流的开头，服务端恰好回复一个字节的状态码。它只属于 **iroh**
入口路径 —— 明文 `[server] listen_addr` 监听器对 `0x05` 一无所知：

```text
client → server   0x05  version=0x01  proto(0x01 tcp | 0x02 udp)  len  host  port(u16-be)
server → client   status   0x00 ok       0x01 no route        0x02 backend failed
                           0x03 too many flows                0x04 bad preface
```

`0x05` 既不会开启一个 HTTP 请求，也不会开启一条 TLS 记录，所以三个处理器只差一个
`if` —— 见[工作原理](#工作原理)。在收到 `0x00` 之后：

- **TCP** —— 双向原始字节，与 TLS passthrough 路径完全一致。
- **UDP** —— 每条流一条 QUIC 双向流，数据报以 `u16` 长度前缀分帧，因为字节流本身
  没有消息边界。双向都静默达到 `idle_timeout_secs`（默认 60）的流会被关闭。

### 由服务端决定拨号目标

客户端指定**主机与端口**；由路由决定拨号到哪个地址，而 `backends` 是地址唯一出现
的地方 —— 因此持有有效 2FA 凭证的客户端也无法把服务端当作开放中继使用。L4 查找
**永不回落**：没有 `tcp`/`udp` 路由的主机是一次调用方可以据此行动的拒绝，而不是
一条被悄悄转发到别处的流。

### `client_ports`

一个可选的选择器 —— 路由服务哪些端口 —— 而不是目标：

```toml
[[routes]]
host_pattern = "db.example.com"
mode = "tcp"
backends = ["192.0.2.30:15432"]
client_ports = [15432, 16432]       # 这条路由应答的端口
```

它只决定*哪条*路由与一条流匹配，因此同一个主机可以在不同端口上有 `tcp` 路由、指向
不同后端。不写 `client_ports` 时，所有端口都匹配。

同一主机上两条路由都能匹配一条流时，**写了 `client_ports` 的那条胜出**（胜过"收所有
端口"的那条）。没有这个优先级规则时，先声明的路由会永久胜出、后写的那条永远匹配不上，
与书写顺序无关地失效。

### 代价

L4 流是不透明的：访问日志记录的是字节数而不是请求行，也没有健康检查。并发按 QUIC
连接计上限 —— 打开过多流的客户端会收到 `0x03 too many flows`。因为一条 UDP 流就是
一条双向流，一个 TUN 设备可能同时持有数百条；见[QUIC 调优](#quic-调优)中的
`NEXAPIPE_QUIC_MAX_BIDI_STREAMS`。

### 哪些客户端可以用

| 客户端 | TCP | UDP |
| --- | --- | --- |
| 本地 HTTP 代理（`--local-proxy`、桌面端） | `CONNECT host:port` | — |
| Android TUN | 任意端口 | 任意端口 |
| 桌面 TUN | 任意端口 | — |

TUN 交给应用程序的是**每个域名一个虚拟地址**（Android 上从 `10.0.1.16+` 起，
桌面端从 `10.0.0.2+` 起），所以目的地*就是*域名。全程不做任何嗅探，这正是 UDP 得以
可行的原因。两个地址族都会应答（AAAA 取自 `fd00:10:0:1::16+`，一个 VPN 自己路由的
ULA 段），因此通过 IPv6 解析出来的名字和通过 IPv4 解析的一样可路由 —— 唯一例外是
桌面端 TUN 的网卡拒绝了 IPv6 地址的情况，此时 AAAA 应答为空，解析器回落到 A。

注意这隐含的路由模式：TUN 发往某个域名的流量以 L4 形式到达，所以该域名需要一条
`tcp`（或 `udp`）路由 —— **即使是 80 端口上的明文 HTTP**，因为 TUN 交出的是 IP
报文，客户端在前导里声明主机与端口。因此，一个 TUN 要访问 HTTPS 服务时，是把
`tcp` 路由指向会说 TLS 的后端（`backends = ["caddy:443"]`，与 [TLS 透传](#caddy)
用的是同一个 Caddy，只是明确写出了端口）；`mode = "passthrough"` 保留给那些直接向
代理自身地址发起 `ClientHello` 的客户端。如果同一个后端既要应答 TUN 又要应答普通
请求，在一条条目里用 `modes = ["http", "tcp"]` 说明。

---

## 2FA (TOTP)

当 `[auth] enabled = true` 时，每一条客户端连接都必须在任何流量被代理之前完成
TOTP 握手。

1. 生成密钥与可扫描的二维码。密钥会随打印一同写入 `config.toml` 的
   `[auth.clients]`，所以第 2 步只是把 2FA 打开：

   ```bash
   cargo run -p nexapipe -- --generate-2fa client-001 --qr-format unicode
   ```

2. 确认服务端配置里 `[auth]` 是打开的。该命令会为你添加
   `[auth.clients.client-001]`，但绝不擅自翻转 `enabled` —— 那个开关影响每一个
   客户端，所以由你自己来拨：

   ```toml
   [auth]
   enabled = true
   algorithm = "sha1"      # sha1 | sha256 | sha512
   time_step = 30
   digits = 6
   window = 1
   max_attempts = 5
   lockout_duration = 300

   [auth.clients.client-001]     # 由 --generate-2fa 写入
   secret = "JBSWY3DPEHPK3PXP"
   ```

3. 在客户端上，要么在应用里扫描二维码，要么在 `[local_proxy.two_factor]` 里设置
   凭证：

   ```toml
   [local_proxy.two_factor]
   enabled = true
   client_id = "client-001"
   secret = "JBSWY3DPEHPK3PXP"
   algorithm = "sha1"
   ```

新增和变更的 `[auth.clients]` 条目会被配置监视器即时拾取，新增客户端无需重启；
`[auth] enabled = true` 同样即时生效（对重载之后新建的连接）—— 启动时完全没有
`[auth]` 段的服务端也是如此。TOTP 参数
（`algorithm`、`time_step`、`digits`）在启动时只读取一次，需要重启。见
`config.toml.2fa.example`。

这些密钥是**唯一**把守 iroh 监听器的凭证，因此只要 `config.toml` 里存着凭证 ——
TOTP 种子、`[iroh] secret_key` 或 `relay_auth_token` —— 而它又可被其属主之外的
任何账号读取或写入，服务端就**拒绝启动**（`chmod 600 config.toml`）。三者都没有的
配置只记录同样的警告后照常启动，Docker bind mount 拿到的正是这种文件。没有凭证的
客户端面对要求凭证的服务端同样会被拒绝：QUIC 握手成功，而服务端在握手期限（5 秒）内
没有收到 `AUTH_START` 时会关闭连接。

二维码携带的是标准 `otpauth://` URI，所以任何认证器应用都能导入：

```text
otpauth://totp/NexaPipe:client-001?secret=JBSWY3DPEHPK3PXP&issuer=NexaPipe&algorithm=SHA1&digits=6&period=30
```

- 在 `[auth]` 下设置 `issuer` 可改变应用显示的标签；`--issuer` 可覆盖单次运行的
  取值。两者默认都是 `NexaPipe`。
- `--show-2fa CLIENT_ID` 可以再次打印已配置客户端的二维码，用于另一台设备。
- 对一个已有密钥的客户端执行 `--generate-2fa` 会打印**那个**密钥而不是生成新的。
  加上 `--force` 可轮换它：所有用旧密钥注册过的设备都必须重新扫描。
- 写入是就地编辑 `config.toml`，保留注释与格式。如果文件无法读取或写入，密钥只会
  被打印出来。
- `algorithm`、`time_step` 与 `digits` 是在*生成二维码*时读取的，而不是扫描时 ——
  设备注册完成后请保持它们稳定。
- **密钥才是凭证，不是那六位数字。** 服务端在查看验证码*之前*先校验响应签名（以
  密钥为密钥的 HMAC-SHA256）。任何带 `secret=` 的 `nexapipe://` 邀请码与注册二维码
  都以**明文**携带它 —— 把两者都当作密码对待（`--qr-out` 在 Unix 上以 `0600` 写入）。

---

## 端点邀请码

一个二维码可以携带整份客户端配置 —— 端点、域名和 2FA —— 因此注册一台手机是扫一下，
而不是手输三个字段：

```bash
cargo run -p nexapipe -- --generate-invite client-001 --qr-format unicode
```

```text
nexapipe://endpoint/a612…7063?v=1&name=Home&domains=app.example.com,comfyui.example.com
    &relay=https://relay.example&client=client-001&issuer=NexaPipe
    &secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30
```

| 部分 | 含义 |
| --- | --- |
| `endpoint/<node-id>` | 要拨号的端点。`ticket/<ticket>` 则携带一个完整的端点 ticket。 |
| `domains` | 逗号分隔；客户端只代理这些名字。 |
| `name` | 客户端列表中显示的标签。 |
| `relay` | 中继 URL，用于无法直连的端点。 |
| `client` + `secret`/`algorithm`/`digits`/`period` | 2FA 凭证 —— 仅在你传入 `CLIENT_ID` 时出现。 |
| `otpauth` | 上述六个参数的替代形式：一整条 `otpauth://` URI，在扁平形式缺失时使用。 |

不带 `CLIENT_ID` 时，邀请码只携带端点与其域名，别无其他。域名默认取
`[local_proxy] proxy_domains`，其次取 `[[routes]]` 的主机名；端点默认取
`[iroh] secret_key` 的公钥，因此二维码在重启后依然有效。可用
`--invite-domains`、`--invite-name`、`--invite-relay`、`--endpoint-id` 覆盖其中
任何一项。

- 客户端会**忽略它不认识的参数**，因此较新的服务端可以增加字段而不破坏旧版应用。
  严格的是 `v`（必须是 `1` 或 `2`）与 `algorithm` —— 未知的名字是错误，绝不静默
  回落到 SHA1。
- 让二维码保持在约 400 字符以内，以便扫描；超出时命令会给出警告。
- 带 `secret=` 的邀请码是**明文密码**，它的二维码渲染同样如此 —— 任何扫到它的人都
  持有该客户端的凭证。
- **吊销即轮换。** 没有按设备吊销：`--generate-2fa client-001 --force` 会就地重写
  `config.toml`，所有用旧密钥注册过的设备都必须重新扫描；删除
  `[auth.clients.client-001]` 这一段则一次性吊销所有人。
- 两种吊销都只作用于**之后建立的连接**：握手里拿到的授权是当时的快照，已经通过认证的
  连接会一直用到它自己结束，轮换或删除都不会把它掐断。要立刻断开，重启服务端。

### 邀请一个尚不存在的客户端（`--create-client`）

`--generate-invite CLIENT_ID` 交出的是某个客户端*已经拥有*的密钥，因此不在
`[auth.clients]` 中的 `CLIENT_ID` 会被拒绝。`--create-client` 把"创建"与"邀请"合为
一次运行 —— 密钥被生成、写入配置并放进邀请码：

```bash
cargo run -p nexapipe -- --generate-invite client-001 --create-client
cargo run -p nexapipe -- --generate-invite client-001 --create-client --registration
```

- **它绝不触碰已存在的客户端。** 对已配置的客户端运行会复用已存的密钥，而不是再生
  成一个 —— 后者会让所有已用第一个密钥注册的设备全部被锁在外面。轮换仍然是显式的
  `--generate-2fa CLIENT_ID --force`。
- **它只补全完全缺失的客户端。** 一个存在但没有 `secret` 的 `[auth.clients.x]` 段
  是坏文件，不是一个待填的空白。
- **它不是独立的"添加客户端"命令** —— 它要求配合 `--generate-invite`，因此密钥只会
  作为即将被交出去的邀请码的一部分而被创建。

由于新密钥是写入 `config.toml` 的，请记住 TOTP 参数在启动时只读取一次：添加到
`[auth.clients]` 下的客户端会被自行拾取（文件每 5 秒被重新读取一次），但改动
`algorithm`、`time_step` 或 `digits` 仍需重启。

### 注册邀请码（`--registration`）

上面那个码的问题在于：只要密钥还在，它就一直是凭证。`--registration` 改为在链接中
放入一个**一次性注册令牌**：

```bash
cargo run -p nexapipe -- --generate-invite client-001 --registration
```

```text
nexapipe://endpoint/a612…7063?v=2&domains=app.example.com&client=client-001
    &enroll=9f2c…c41b
```

第一台连接的设备发送该令牌，服务端回复一个新生成的密钥，并**在同一次写入中烧掉
令牌**，因此一个在传输途中被复制的链接在被使用的瞬间就不再是凭证。因此注册同时也会
轮换该客户端的密钥，所有已在用它的设备都必须重新扫描；一个你从未送达的链接，通过再
生成一个来吊销，这会替换掉尚未使用的令牌。

- `v=2` 是一个**独立的版本号**，因此只认识 `v=1` 的应用会拒绝该码，而不是把它当作
  一个凭证丢失的端点分享来读取。
- 完成注册的设备必须**持久化它被签发的密钥** —— 令牌已被花掉，所以一个持有该邀请码
  重启的应用无法注册两次。两个应用都做到了：桌面端调用 `take_issued_credential`，
  Android 从 `IrohProxy.nativeTakeIssuedCredential()` 读出同样的内容。

扫码功能在 Android 应用中实现（"Add Node" 旁边的 "Scan Invite" 按钮），它只接受
`endpoint/` 形式 —— 它存储的节点只持有 Node ID 而没有地址，所以 ticket 形式的邀请码
会被拒绝。

---

## 安全边界

**明文出现在哪里。** 在 `passthrough` 模式下，哪里都没有：会话在访客与你的后端之间
端到端加密，代理除字节之外什么都不持有。在 `http` 模式下代理会解析请求并重新向
`http://` 后端发起，所以对于那一跳它就是 L7 中间盒 —— 与 nginx 或 Caddy 所处的位置
相同。那最后一跳通常留在同一台主机（`127.0.0.1`）或你自己的局域网内。

**查询串不会被记录。** 访问日志保留参数名，把取值替换为 `<redacted>`
（`[log] redact_query`，默认开启），因为令牌与签名正是在那里传递的。

报告漏洞：开一个 issue，或者如果可以实际利用，直接联系维护者。

---

## 使用客户端库

```toml
[dependencies]
nexapipe-client = { path = "../crates/nexapipe-client", features = ["local-proxy"] }
```

```rust
use std::sync::Arc;

use nexapipe_client::{EndpointGroup, LoadBalancingStrategy, LocalProxy, NodeConfig};

// 一个节点（服务端 Node ID 或完整 Ticket）加上它服务的域名。
let group = EndpointGroup::new_with_nodes(
    vec![NodeConfig {
        server_node_id: Some(server_node_id),
        server_ticket: None,
        domains: vec!["app.example.com".to_string()],
    }],
    None,
    LoadBalancingStrategy::RoundRobin,
)
.await?;

// 127.0.0.1:8081 上的 HTTP 代理，只转发已配置的域名。
let proxy = LocalProxy::new(
    "127.0.0.1:8081",
    vec!["app.example.com".to_string()],
    Arc::new(group),
)
.await?;
proxy.run().await?;   // run() 阻塞；从别处调用 stop() 来结束它
```

同一个 `EndpointGroup` 由本地代理与 TUN 代理共用，因此一个连接池同时服务两者。

Cargo feature：

| Feature | 用途 |
| --- | --- |
| `native-certs`（默认） | 使用操作系统的证书存储。 |
| `webpki-roots` | 改为内置 Mozilla 根证书。 |
| `local-proxy` | 本地 HTTP 代理：`CONNECT` 打开一条 L4 TCP 流，直接向它发起的 TLS `ClientHello` 走 SNI 路径。 |
| `tun-proxy` | 面向 TUN fd 的 smoltcp 用户态 TCP/IP 栈，按域名分配虚拟 IP，使一条流自带端口（并让 UDP 成为可能）。隐含 `local-proxy`。 |
| `jni` | 面向 `com.nexa.pipe.IrohProxy` 的 JNI 入口。 |
| `uniffi` | 面向 Swift/Kotlin/Python 的 UniFFI 绑定。 |
| `tracing`（默认） | `tracing` 集成。 |

### QUIC 调优

因为一条内层 TCP 连接就是一条 QUIC 双向流，**每条流的接收窗口**就是每条被代理连接
的吞吐上限 —— iroh 的默认值（1.25 MB）在 200 ms RTT 下把单条连接限制在约 50 Mbps。
`TransportTuning` 会提高它，并且无需重新编译即可覆盖：

| 环境变量 | 默认值 | 含义 |
| --- | --- | --- |
| `NEXAPIPE_QUIC_STREAM_WINDOW` | `4194304` | 每条流的接收窗口，字节。 |
| `NEXAPIPE_QUIC_SEND_WINDOW` | `16777216` | 连接级发送窗口，字节。 |
| `NEXAPIPE_QUIC_INITIAL_MTU` | `0` | `0` 表示保持 iroh 的 1200；否则取 1200..=65535。 |
| `NEXAPIPE_QUIC_KEEPALIVE_MS` | `0` | `0` 表示保持 iroh 的 5 秒。 |
| `NEXAPIPE_QUIC_MAX_BIDI_STREAMS` | `1024` | 一条连接可同时承载的双向流数。库默认值（100）在每条 UDP 流都占用一条流之后就不够用了。 |

绝不要覆盖 iroh 的多路径或 NAT 穿透相关开关 —— 那会破坏打洞。`TUN_MTU` 是 1400，
并且在每一个 TUN 实现中都必须完全一致。

---

## 客户端应用

| 应用 | 目录 | 功能 |
| --- | --- | --- |
| Android | [`ui-android`](ui-android/README.md) | VpnService TUN，带 DNS 劫持 + TCP/UDP 重定向；Compose UI；二维码 2FA 导入。 |
| 桌面端 | [`ui-desktop`](ui-desktop/README.md) | Tauri 2 + Vue 3；本地 HTTP 代理或经可选提权服务的系统 TUN（WinTun）。 |

<table>
  <tr>
    <td align="center"><img src="screenshots/android-disconnected.jpg" width="240" alt="Android 客户端，未连接"><br><sub>Android —— 未连接</sub></td>
    <td align="center"><img src="screenshots/android-connected.jpg" width="240" alt="Android 客户端，已连接到端点"><br><sub>Android —— 已连接</sub></td>
  </tr>
  <tr>
    <td align="center"><img src="screenshots/desktop-disconnected.png" width="400" alt="桌面客户端，代理已停止"><br><sub>桌面端 —— 已停止</sub></td>
    <td align="center"><img src="screenshots/desktop-connected.png" width="400" alt="桌面客户端，代理以 TUN 模式运行"><br><sub>桌面端 —— 运行中（TUN）</sub></td>
  </tr>
</table>

两者都是本仓库中的普通目录（从先前的独立仓库导入时保留了 git 历史），并与服务端从
同一个 tag 发布。

---

## 开发

```bash
cargo build                                   # 构建整个 workspace
cargo test --workspace                        # 运行全部测试
cargo clippy --workspace --all-targets        # lint（保持在零警告）
cargo fmt --all -- --check                    # 报告格式漂移
```

**不要**运行 `cargo fmt --all`：代码树在你没有改动的文件里存在既有的格式漂移。只格式化
你自己的文件 —— `rustfmt --edition 2024 <path>` —— 这就够了，因为 `rustfmt` 本身会
顺着 `mod` 声明走。

workspace 构建覆盖不到的分目标检查：

```bash
cargo ndk -t arm64-v8a check -p nexapipe-client --features jni,tun-proxy
cargo ndk -t x86_64   check -p nexapipe-client --features jni,tun-proxy
cd ui-desktop/src-tauri && cargo check
cd ui-android && ./gradlew.bat :app:compileDebugKotlin
```

TUN 栈由 Android 与桌面端共用，只有它基于 fd 的入口是 `cfg(target_os = "android")`，
所以那两行 `cargo ndk` 仍是唯一会对 Android 那一半做类型检查的东西 —— 很容易忘。
两个 ABI 各要一次：应用按 ABI 分别出包，CI 也两个都跑。
`ui-desktop/src-tauri` 是一个独立的 cargo 项目，因此 workspace 的 lint 门禁也覆盖
不到它。

说明：

- workspace 锁定 edition 2024，并通过 `[patch.crates-io]` 内置 smoltcp；请把
  `third_party/` 留在构建上下文中（Docker 已经这么做了）。平台相关代码始终放在
  cargo feature 之后（`jni`、`local-proxy`、`tun-proxy`、`uniffi`）。
- CI（`.github/workflows/ci.yml`）在 Linux 与 macOS 上跑测试；桌面端 crate 在
  Linux、macOS、Windows 上做 `cargo check`。`release.yml` 在打 tag 时覆盖多平台
  构建。含连字符的 tag（`v0.2.0-rc.1`）会作为 GitHub **pre-release** 发布，因此
  永远不会占据 "latest"。
- 行内注释使用英文。

关于接下来要做什么 —— 以及为什么有些东西是刻意不做的 —— 见
[docs/ROADMAP.md](docs/ROADMAP.md)（英文）。

## License

MIT —— 见 [LICENSE](LICENSE)。
