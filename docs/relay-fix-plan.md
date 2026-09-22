# Relay 修复计划

> 面向开发者的内部文档。若要并入仓库公开文档（README / docs），需按仓库约定改写成英文。
> 基于 2026-09-22 的代码核对，iroh 版本 1.0.1。

## 0. 现状：事实清单

### 0.1 同一件事有五份实现

`relay_mode` / `relay_url` 这组开关目前被重复实现了：

| 位置 | 作用 |
| --- | --- |
| `crates/nexapipe/src/proxy/mod.rs:152-175` | 服务端 |
| `crates/nexapipe-client/src/jni.rs:878-897` | Android |
| `ui-desktop/src-tauri/src/proxy/manager.rs:255-286` | 桌面端 |
| `ui-android/.../ui/VpnControlScreen.kt:454-458` | Android UI 的选项列表 |
| `ui-desktop/src/stores/config.ts:127-132` + `SettingsPage.vue:157-160` | 桌面 UI 的选项列表 |

`pinned` 的目标 URL 也被硬编码了两遍（`jni.rs:90` 与 `manager.rs:278`）。
这三份 Rust 实现的分支条件各不相同，是下面大部分 bug 的根源。

### 0.2 服务端

| # | 问题 | 位置 | 后果 |
| --- | --- | --- | --- |
| S1 | **整个 relay 配置块被 `if let Some(relay_url)` 包住**，没有 `relay_url` 时 `relay_mode` 完全不处理 | `proxy/mod.rs:152` | `relay_mode = "disabled"` 单独配置 → 静默失效，服务端照常连 N0 relay |
| S2 | 只配 `relay_url`、不配 `relay_mode` → 走 else 分支只打一行日志，从不调用 `relay_mode()` | `proxy/mod.rs:171-173` | `config.toml` 把 `relay_url` 标为 optional，用户填了却不生效 |
| S3 | `relay_mode = "default"/"native"` 且设了 `relay_url` → warn 后忽略 URL | `proxy/mod.rs:158-160` | 行为合理，但 warn 文案没说清 URL 被丢弃 |
| S4 | 未知 mode 值只 `warn!`，继续以 N0 默认启动 | `proxy/mod.rs:167-169` | 拼写错误（`custome`）不会暴露 |
| S5 | 无 auth token 字段 | `config.rs:39-47` | 需要鉴权的自建 relay 无法使用 |
| S6 | `PkarrPublisher` 默认 `AddrFilter::relay_only()`（iroh `address_lookup/pkarr.rs:168`） | `presets::N0` | 服务端关 relay 且无公网直连地址时，只发布不出任何可解析信息；客户端仅持裸 EndpointId 会报 `No addressing information available` |
| S7 | 服务端没有 `pinned` 概念，默认按延迟在全部 N0 relay 中漂移 | `presets::N0` | 与客户端"钉死一个 relay"的做法不一致；服务端 home relay 漂移会拖断长连接 |

### 0.3 客户端（Android 与桌面共通）

| # | 问题 | 位置 | 后果 |
| --- | --- | --- | --- |
| C1 | **`forceRelay` / `force_relay` 完全没接线**：持久化、进 UI、传到后端，然后只被 `tracing::info!` 打一行 | `manager.rs:291`；Android 根本没有对应 JNI 函数 | UI 声明"禁用直连"，实际无效 |
| C2 | `custom` + 空 URL 的回落不一致：Android 落回 `pinned`，桌面落回 N0 默认，而桌面日志写的是 "using pinned default" | `jni.rs:881` vs `manager.rs:263-273` | 同一份配置在两个平台行为不同，且日志说谎 |
| C3 | 配置全局、且只在 endpoint bind 时读取 | — | 运行中改动不生效，UI 无提示 |
| C4 | 无 auth token 入口 | — | 客户端连需要鉴权的 relay 时，`start_active_relay` 取不到 token 会鉴权失败 |
| C5 | 导入 `nexapipe://` 邀请会静默把**全局** `relay_mode` 改成 `custom` | `VpnControlScreen.kt:131`、`useConfigStore.ts:234` | 导入一条邀请会改掉所有节点的 home relay |
| C6 | `EndpointGroup::new_with_nodes` 自建 endpoint，不带 relay 配置也不带 QUIC tuning | `endpoint_group.rs:149` | 当前无人调用，但作为公开 API 是陷阱 |
| C7 | `relay_mode = "disabled"` 会连带失去**对端** relay 能力（iroh `RelayMode::Disabled` ⇒ 无 `TransportConfig::Relay`） | `endpoint.rs:153-157` | UI 上写的是 "direct only"，没说清"连服务端的 relay 也用不了" |

### 0.4 已确认可用的部分（不要误改）

- 客户端拨号到**不在自己 RelayMap 里**的 relay 是支持的：`RelaySender::is_valid_send_addr` 无条件返回 `true`（`socket/transports/relay.rs:259`），`RelayActor::active_relay_handle` → `start_active_relay(url)` 会按需建连（`socket/transports/relay/actor.rs:1214`）。本地 RelayMap **只**在 `start_active_relay` 里被用来取 auth token（`actor.rs:1236`）。
- 因此**客户端与服务端的 relay 可以不同，且这是常态**。计划里所有改动都不能破坏这一点。

### 0.5 不变量：custom 必须独占（新增需求）

**需求**：一旦配置了自定义 relay，就不应再触碰 iroh 官方（`*.relay.n0.iroh.link`）的 relay。

已核对的事实：

- **home relay 已经是"替换"而不是"追加"**。`Builder::relay_mode()` 会找到已有的
  `TransportConfig::Relay` 并整体覆盖（`endpoint.rs:557-577`），所以
  `RelayMode::Custom(RelayMap::from_iter(vec![our_url]))` 之后，N0 的四个默认 relay
  （`defaults.rs:36-42`）不在 map 里。
- **net_report 也用同一个 map**。`net_report::Client::new(..., relay_map.clone(), ...)`
  （`socket.rs:1061-1067`），且 map 为空时整个 net_report 被跳过（`socket.rs:799-803`）。
  所以自定义 relay 下不会再向 N0 发探测。

但有三条路径仍在偷偷回落到官方 relay，违反该需求：

| # | 违反点 | 位置 |
| --- | --- | --- |
| V1 | `custom` 但 URL 为空 → Android 落回 `pinned`（aps1-1，官方）、桌面落回 N0 默认 | `jni.rs:881`、`manager.rs:263-273` |
| V2 | `relay_mode` 缺省或为未知值 → 两端都落回 `pinned`（官方） | `jni.rs:889`、`manager.rs:275`、`proxy/mod.rs:167` |
| V3 | 拨号时若**对端**广播的是 N0 relay，客户端仍会按需连上去（`start_active_relay`） | `socket/transports/relay/actor.rs:1214` |

另外还有一处同类问题，但属于"官方基础设施"而非"官方 relay"：

- **V4**：`presets::N0` 里的地址发现走 `PkarrPublisher::n0_dns()` / `DnsAddressLookup::n0_dns()`，
  目标是 `https://dns.iroh.link/pkarr`（`address_lookup/pkarr.rs:127`）。即便 relay 全自建，
  只要客户端用裸 EndpointId 连接，就仍然要访问 n0 的 DNS/pkarr 服务。

### 0.6 一个被推翻的前提：`addr_filter` 是发布侧的

计划第一版把 F2 和 F11c 都押在 `AddrFilter` 上，读源码后发现押错了：

- `AddressLookupServices::publish` 会 `data.apply_filter(filter)`（`address_lookup.rs:517-521`）；
- `AddressLookupServices::resolve` **不**过过滤器（同文件 `553-566`），`FilteredAddressLookup::resolve`
  也是直接透传（`180-189`）。

也就是说 `Builder::addr_filter` 约束的是**自己发布出去的地址**，不是拨号时用的地址。
`AddrFilter::relay_only()` 之所以是 `PkarrPublisher` 的默认值，正是因为要避免把 IP 泄到公开
pkarr 服务器——它是"我发什么"，不是"我连什么"。

---

## 1. 目标形态

引入**单一实现**，让服务端、Android、桌面共用同一套解析逻辑：

```
crates/nexapipe-client/src/relay.rs   （新增）
    pub const PINNED_RELAY_URL: &str = "https://aps1-1.relay.n0.iroh.link.";

    pub enum RelayModeSpec {
        Disabled,
        Default,
        Pinned,
        Custom { url: String, auth_token: Option<String> },
    }

    impl RelayModeSpec {
        /// 严格解析：未知值返回 Err，不再静默 warn；
        /// custom 缺 URL、或 URL 属于 n0 官方域名时同样返回 Err（见 F11a）。
        pub fn parse(mode: Option<&str>, url: Option<&str>, token: Option<&str>) -> Result<Self>;
        /// 同时处理 auth token（需要时把 relay 加进 map）。
        pub fn relay_mode(&self) -> iroh::RelayMode;
        /// 给 F11c 用：该模式下允许出现的 relay URL 集合。
        pub fn allowed_relay_urls(&self) -> Option<&[RelayUrl]>;
    }
```

服务端已经依赖 `nexapipe-client`（`proxy/mod.rs:180` 用了 `nexapipe_client::transport`），所以这一层可以被三处直接复用，不必新建 crate。

`relay_url` 与 `relay_mode` 解耦：`relay_mode` 独立生效（修掉 S1），`relay_url` 单独出现时视为 `custom`（修掉 S2）。

`parse` 的返回值就是"最终生效的那个 relay"，**不允许有隐式回落**——这是 §0.5 那条不变量的落点。

---

## 2. 修复项

### P0 — 配置静默失效 / 声明与行为不符

#### F1. 服务端 relay 配置重构（S1、S2、S3、S4）

文件：`crates/nexapipe/src/proxy/mod.rs:152-175`、`crates/nexapipe/src/config.rs:39-47`

- `IrohConfig` 增加 `relay_auth_token: Option<String>`。
- 把 relay 分支整体替换成 `RelayModeSpec::parse(...)`，未知值 → 启动失败并给出合法值列表，不再只 warn。
- `relay_mode` 缺省但 `relay_url` 存在 → 按 `custom` 处理（而不是只打日志）。
- `relay_mode = "default"` 且带了 `relay_url` → 明确报错"二者冲突"，而不是 warn 后忽略。

验收：
- `relay_mode = "disabled"` 单独配置 → 启动日志出现 `relay: disabled`，`ep.addr()` 的 `relay_urls()` 为空。
- 只配 `relay_url` → 日志 `relay: custom <url>`，且 `ep.home_relay()` 确为该 URL。
- `relay_mode = "custome"` → 进程退出并打印合法值。

#### F2. Force relay：做不到，开关已从两端移除（C1）

**结论（2026-09-22 核对后推翻原方案）**：iroh 1.0.1 的稳定 API 里没有"禁用直连"这回事，原计划
写的 `addr_filter(AddrFilter::relay_only())` 也是误读——见下面 §0.6。三条可行的路都堵死了：

| 设想 | 结果 |
| --- | --- |
| `addr_filter` 过滤掉直连地址 | 它是**发布侧**过滤，不影响拨号（`address_lookup.rs:517-566`）。且连接建立后 iroh 会用握手里交换到的地址打洞，与地址发现无关 |
| 只保留 relay transport、去掉 IP transport | `TransportConfig` 是 `pub(crate)`（`socket/transports.rs:99`），没有公开的移除或替换入口 |
| 关掉打洞 | `QuicTransportConfigBuilder::max_remote_nat_traversal_addresses` 的文档说"非 0 即启用打洞"，但 setter 会拒绝 < 8 的值（`endpoint/quic.rs:537-541`），无法设成 0 |
| 自定义 `PathSelector` 只选 relay 路径 | `Builder::path_selector` 被 `unstable-custom-transports` feature 门控（`endpoint.rs:839`） |

所以按计划里的另一条路执行：**把开关摘掉**，不留一个声明了却做不到的事。
已删除：桌面 `types/index.ts` / `stores/config.ts` / `useConfigStore.ts` / `stores/proxy.ts`
/ `ProxyStatusControl.vue` / `SettingsPage.vue`，以及后端 `lib.rs`、`service/ipc.rs`、
`service/ipc_client.rs`、`service/runner.rs`、`proxy/manager.rs` 的 `force_relay` 字段（含 IPC
协议里的那个字段）；Android `SettingsManager`（含 `KEY_FORCE_RELAY`）、`VpnViewModel`、
`VpnControlScreen` 的开关与状态。旧的 `forceRelay` / `force_relay` 只是被忽略，不会让已有配置
读不出来。

顺带：Android `updateRelayConfig` 现在在切到非 `custom` 模式时会顺手清掉 `relayUrl`，避免留下
一个"和当前模式不匹配"的残留字段。

#### F11c. strict 白名单：同样做不到，降级为"接受现状"（V3）

原设想用 `AddrFilter::new(闭包)` 把对端广播的 N0 relay 挡掉。既然 `addr_filter` 只作用于发布侧，
这条路也不成立。剩下唯一能拦截的地方是我们自己构建 `EndpointAddr` 的地方
（`connection_pool.rs` 的 `parse_endpoint_addr`）——但那只能管 ticket 携带的地址，管不到
node-id 连接时由 pkarr/DNS 发现返回的地址。

结论：**V3 在 iroh 1.0.1 下无法彻底关闭**。§0.5 的不变量因此只在"本端用哪个 relay"这一层成立：
home relay、net_report 探测都是独占的；对端广播的 relay 仍会被按需连接。这一点必须写进文档，
不能让人以为配了 custom 就与 n0 完全无关了（V4 说的 pkarr 同理）。

#### F3. `custom` + 空 URL 不再回落到官方 relay（C2 + V1）

**取消回落**。URL 为空时直接报错，不再替用户选一个官方 relay：

- Android 与桌面统一：启动/连接阶段返回错误 `custom relay mode requires a non-empty URL`。
- 桌面端那句 "using pinned default" 日志必须删掉。

同时 UI 上在 `custom` 模式下把 URL 输入框设为必填，空值时禁止保存。

#### F11. custom 模式下的独占校验（V1、V2、V3）

**F11a（必做）**：`RelayModeSpec::parse` 在 `Custom` 分支做两件事——
1. URL 为空 → `Err`（与 F3 同源）；
2. 解析出的 URL 若属于 `*.relay.n0.iroh.link`，**不算 custom**，而是提示用户改用 `pinned` 或直接指定该 URL 的 `default`。原因是混淆这两者会让"我到底有没有脱离官方 relay"变得无法判断。

**F11b（必做）**：未知或缺失的 `relay_mode` 不再静默回落到 `pinned`。服务端启动失败（F1 已覆盖），客户端同样报错而不是替用户选。

**F11c（可选，默认关）**：新增 `relay_strict`（服务端 `[iroh]`，客户端设置项），开启后用
`AddrFilter::new(...)` 把地址发现的结果限制在白名单内——只保留直连地址与白名单内的 relay URL：

```rust
Endpoint::builder(presets::N0)
    .relay_mode(spec.relay_mode())
    .addr_filter(AddrFilter::new(move |addrs| {
        Cow::Owned(addrs.iter().filter(|a| match a {
            TransportAddr::Relay(url) => allowed.contains(url),
            _ => true,
        }).cloned().collect())
    }))
```

`AddrFilter::new` 接受任意闭包（`iroh-dns-1.0.1/src/endpoint_info.rs:257`），所以这条可行。
注意它只作用于**发现层**（pkarr/DNS 返回的地址），ticket 里携带的地址是否同样被过滤需要实测——
这一条与 F2 共用同一个待验证风险。

**F11d（配套）**：启动日志明确打出是否独占，例如
`relay: custom https://relay.example (exclusive, n0 relays not used)`，便于事后核对。

#### F12. 自建 pkarr / 关闭官方地址发现（V4）

若目标是彻底不依赖 n0 基础设施，还需要处理地址发现：

- 服务端自建 `iroh-dns-server`，把 `PkarrPublisher::n0_dns()` 换成指向自建服务的
  `PkarrPublisher::builder(pkarr_relay)`；客户端侧同步换掉 `DnsAddressLookup::n0_dns()`。
- 或者干脆 `clear_address_lookup()`，全部改用 ticket 分发（`endpoint.rs:585`）——
  代价是只能靠 ticket 连接，裸 EndpointId 不可用。

这一步工作量最大，且需要自建基础设施，建议单独立项；在它完成前，README 里应写清
"自定义 relay ≠ 脱离 n0 基础设施，地址发现仍走 dns.iroh.link"。

### P1 — 可观测性与一致性

#### F4. 生效时机提示（C3）

- 桌面 `SettingsPage.vue` 的 relay 区域加一行提示："改动在下一次启动代理后生效"（文案复用现有 `relayHint` 的写法，两条 locale 都要加）。
- Android `VpnControlScreen.kt` 同样加提示行。

#### F5. 启动日志打印最终生效的 relay（S7 + 可观测）

服务端与客户端在 bind 之后统一打一行：

```
relay: mode=pinned url=https://aps1-1.relay.n0.iroh.link.  force_relay=false
```

排查问题时不用再去猜哪条分支命中了。

#### F6. 服务端补 `pinned` 模式（S7）

`RelayModeSpec::Pinned` 在服务端同样可用（钉到 `PINNED_RELAY_URL`），让两端默认值语义一致。是否需要成为服务端默认值另行决定——服务端通常是长期运行的机器，漂移带来的断连风险比客户端小。

#### F7. `disabled` 的真实语义写进 UI 与文档（C7）

桌面 `SettingsPage.vue:159` 的 `Disabled (direct only)` 改为
`Disabled — no relay at all, the server's relay cannot be used either`；Android 同步。
README 第 293-294 行的表格补一句同样的话。

### P2 — 能力补全

#### F8. Auth token（S5、C4）

- 服务端 `[iroh] relay_auth_token` → `RelayMap::from_iter([RelayConfig { url, auth_token }])`。
- 客户端：新增 `relay_auth_token` 配置项，构建 endpoint 时把它放进 `RelayMode::Custom(RelayMap)`；运行时如需给对端的 relay 补 token，用 `Endpoint::insert_relay(url, config)`（`endpoint.rs:982`）。
- 桌面 UI：只在 `custom` 模式下显示 token 输入框，类型 `password`。
- 注意：需要鉴权的 relay 必须在**两端**各自的 map 里带 token，只配一端没有用。

#### F9. Invite 的 relay 不再静默改全局（C5）

现状是导入一条邀请就把全局 `relay_mode` 改成 `custom`。改为：
- 预览对话框里明确列出"将把全局 relay 改为 <url>"并让用户确认；
- 或按 per-node 记录 relay hint（工作量更大，与 2FA per-endpoint 化是一类改造）。
先做前者。

#### F10. 收敛 `EndpointGroup::new_with_nodes`（C6）

要么删掉，要么让它复用调用方传入的 relay/transport 配置。当前无人调用，倾向直接删除。

---

## 3. 落地顺序

1. **F1 + F3 + F5 + F11a/F11b**（服务端与三处解析逻辑统一 + 取消一切隐式回落，一天）— 已完成。
2. **F7**（文案）— 已完成一半（两端 `disabled` 的说法）。
3. **原 F2 + F11c** — 已证明在 iroh 1.0.1 下做不到，改为"移除开关 + 文档写明边界"。
4. **F8**（token）— 已完成（服务端 + Android + 桌面，见 §8）。
5. **F9 / F10** — 已完成（见 §8）。
6. **F12**（自建 pkarr）— 单独立项。`force_relay` 开关已删除。

## 4. 验证清单

- 服务端：`relay_mode` 四种值 × {有 URL / 无 URL} 全组合，检查 `ep.addr().relay_urls()` 与启动日志。
- 客户端：`pinned` / `default` / `disabled` / `custom` × {空 URL / 合法 URL}；`custom` + 错误 URL 必须启动失败（当前桌面会 `?` 返回错误，Android 是 `expect` 会 panic —— 顺手改成返回错误）。
- 跨 relay 场景：客户端 `pinned`(aps1-1) + 服务端 `custom`(自建 relay)，确认仍能建连且 `link_kinds()` 能给出正确读数。
- `disabled` 组合矩阵：客户端 disabled × 服务端 enabled（应连不上，仅直连可行）、服务端 disabled × 客户端 enabled（按 S6 的说明给明确报错，而不是 `No addressing information available` 这种黑箱）。
- ~~`force_relay = true` 后 `link_kinds()` 必须恒为 `relay`。~~ **已作废**：开关已删除，iroh
  1.0.1 做不到（见 F2 / §0.6）。
- **独占性（§0.5）**：`relay_mode = "custom"` 配好 URL 后，抓包或看连接目标确认**没有任何
  `*.relay.n0.iroh.link` 的流量**——home relay 与 net_report 探测两处。
  （对端广播的 relay 拦不住，iroh 1.0.1 没有可用的开关，见 §0.6，不要把它写进验收条件。）
- **`custom` + 空 URL / 未知 mode**：必须报错退出，不得在任何一端回落到 `pinned` 或 N0 默认。
- 回归：`cargo test --workspace`；`cargo ndk -t arm64-v8a check -p nexapipe-client --features jni,tun-proxy`；桌面 `npm run build` + `lint:i18n`；Android `gradlew :app:compileDebugKotlin`。

## 5. 风险

- **改动 endpoint 构建路径 = 改动所有流量的入口**，F1 必须整批验证，不要拆成多次半拉子提交。
- 服务端默认值若改成 `pinned`（F6），对所有已有部署是行为变更，需要写进 release notes。
- 客户端配置是全局的（C3），改 relay 会影响所有节点；在把它 per-node 化之前，UI 上的提示不能省。
- **取消隐式回落（F3/F11b）会让原本"配错了也能用"的部署直接起不来**。这是有意为之（否则无法
  判断有没有脱离官方 relay），但需要在 release notes 里作为破坏性变更写明。
- **V3 是架构性的，且 iroh 1.0.1 关不掉**：见 §0.6。只要对端还广播 N0 relay，客户端就有能力
  连过去，而且连接建立后 iroh 还会用握手里交换的地址打洞升级，这跟地址发现无关，任何过滤器
  都拦不住。只能写进文档，不能假装解决了。
- **F12 之前，"自定义 relay"不等于"脱离 n0"**：地址发现仍然访问 `dns.iroh.link`。这个边界
  必须写进文档，否则容易被误认为已经完全自建。
- **删除 `force_relay` 是破坏性的**：IPC 协议里少了一个字段。新旧版本的 UI 与 service 二进制
  混用时，旧的 UI 会多传一个字段——serde 默认忽略未知字段，所以方向是安全的；反过来（新 UI +
  旧 service）旧 service 只是缺这个字段，它本来也没用。升级时不必强求两者同版本。

---

## 6. 落地状态（2026-09-22 第一批）

已落地：

- 新增 `crates/nexapipe-client/src/relay.rs`（`RelayModeSpec` + 11 项单测），服务端、Android
  JNI、桌面 `ProxyManager` 三处改为共用它。**F1 / F3 / F11a / F11b / F11d 完成**，
  `pinned` 常量只剩一份。
- 服务端顺带加上 `[iroh] relay_auth_token`（F8 的服务端半边，客户端 UI 还没有入口）。
- `--generate-invite` 的 relay 参数改为读解析后的 spec，不再是裸字符串比较。
- README 的 `[iroh]` 表格与 `config.toml` 注释已补上 `pinned`、`relay_auth_token`
  和"custom 独占 / disabled 是彻底没有 relay"的说明。
- 两端 UI 的 `Disabled (direct only)` 改成 `Disabled (no relay at all)`（F7 的一半）。

**一处对计划的偏离**：`relay_mode` 与 `relay_url` 冲突（`pinned` 却带着 URL）**没有做成启动
失败，而是忽略 + WARN**。原因是这个组合几乎总是"用户改过模式、URL 字段遗留下来"，直接报错会让
已存在的部署起不来。真正会让人连不上的三种情况（custom 缺 URL、未知 mode、custom 指向 n0 官方
relay）仍然是硬错误。为此加了 `RelayModeSpec::uses_url()`，三处调用方各自打 WARN。

仍未做：**F8 客户端侧 token**、**F9**、**F10**、**F12**。

## 7. 落地状态（2026-09-22 第二批）

- **F2 结论改为"做不到"并移除开关**。核对 iroh 1.0.1 后确认四条路都不通（见 F2 表格），其中
  最关键的一条是 §0.6：`addr_filter` 是**发布侧**过滤器，跟拨号无关。
- 删除范围：桌面前端 5 个文件 + 后端 5 个文件（含 `service/ipc.rs` 的 IPC 字段）、Android 3 个
  文件。**F11c 同样作废**，降级为"文档写明边界"。
- 校验：`ui-desktop/src-tauri` `cargo check --all-targets` 通过；`npm run build` exit 0；
  `gradlew :app:compileDebugKotlin` BUILD SUCCESSFUL（仅一个既有的 deprecation warning）。

## 8. 落地状态（2026-09-22 第三批）

- **F8 客户端侧 token 补齐**，服务端字段（第一批）现在有了入口：
  - Android：`nativeSetRelayConfig(mode, url, token)` 变三参；`SettingsManager` 新增
    `KEY_RELAY_AUTH_TOKEN`；`VpnViewModel.relayAuthToken` + `updateRelayConfig(mode, url, token)`；
    `VpnControlScreen` 在 `custom` 下多一个 `PasswordVisualTransformation` 输入框，且非 custom
    模式下 token 与 URL 一起清空。
  - 桌面：`ProxyManager.relay_auth_token` → `RelayModeSpec::parse`，经 `lib.rs` / `service/ipc.rs`
    （新字段带 `#[serde(default)]`）/ `ipc_client.rs` / `runner.rs` 打通；`SettingsPage` 在
    `custom` 下多一个 `type=password` 输入框。`types`/`stores/config`/`useConfigStore`/`proxy.ts`
    都带上 `relayAuthToken` 并做了旧配置迁移。
  - 两端文案都写明：需要鉴权的 relay 必须**两端**都配 token，只配一端没有用。
- **F9 完成（桌面）**：`InviteImportDialog` 现在把"是否采用邀请里的 relay"做成一个默认**不勾**
  的复选框（`invite.applyRelay`），`applyInvite(invite, { applyRelay })` 只有显式勾选才写
  `relayMode`/`relayUrl`。邀请的 relay 只是"那个端点怎么可达"的提示，不是改本机配置的请求。
  Android 侧原本就由 `inviteConflicts` 把"the relay settings"列进确认对话框，不会静默覆盖，
  只更新了那段过时的注释（旧注释写的是"邀请里的 relay 是路由请求"）。
- **F10 完成**：`EndpointGroup::new_with_nodes` 删除；留下的 `new_with_domain_mappings` 加了
  注释说明它没有复用调用方的 relay/transport 配置、当前无人调用。
- 顺手清掉两处 README 里还写着 "force relay" 的功能介绍（Android / desktop），以及本计划里
  已作废的 `force_relay` 验收项。

校验：`cargo test --workspace` 全绿（含 `relay::tests` 13 项）；`cargo clippy --workspace
--all-targets` 无告警；`cargo ndk -t arm64-v8a check -p nexapipe-client --features jni,tun-proxy`
通过；桌面 `npm run build`（vue-tsc + vite）exit 0、`lint:i18n` 143 keys 同步；
`gradlew :app:compileDebugKotlin` BUILD SUCCESSFUL。

仍未做：**F12**（自建 pkarr / 关掉 `dns.iroh.link`），单独立项。
