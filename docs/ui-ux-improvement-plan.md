# UI 改进计划：邀请制入网 / TUN 开关 / Android 视觉现代化 / 连接页直连·中继展示

> 面向开发者的内部文档。若要并入仓库公开文档（README / docs），需按仓库约定改写成英文。
> 基于 2026-09-22 的代码核对。四项需求全部落在 UI 层，`crates/` 与 `src-tauri` 的 Rust 侧不需要改动。
> `ui-desktop` / `ui-android` 是 submodule，改动必须在这两个仓库内部提交。

---

## 0. 总览

| # | 需求 | 平台 | 主要涉及文件 | 改 Rust？ |
| --- | --- | --- | --- | --- |
| 1 | 移除"添加 node"，只能扫码 / 填邀请链接 | 桌面 + Android | `ConfigPage.vue`、`VpnControlScreen.kt` | 否 |
| 2 | Proxy Mode 改为 TUN 虚拟网卡开关，放进连接页；去掉 Refresh Status，改动态更新 | 桌面 | `DashboardPage.vue`、`ProxyStatusControl.vue`、`SettingsPage.vue`、`stores/proxy.ts` | 否（`use_tun` 已就绪） |
| 3 | Android 按钮样式与布局现代化 | Android | `ui/theme/*`、新增 `ui/components/*`、`VpnControlScreen.kt` | 否 |
| 4 | 连接页展示已连接 endpoint 的 relay / direct | 桌面 | `DashboardPage.vue` + proxy store | 否（`get_endpoint_links` 已就绪） |

### 三个先说清楚的前提

1. **后端已经就绪。** `start_proxy` 已接受 `use_tun: Option<bool>` 并透传服务 IPC
   （`src-tauri/src/lib.rs:61-115`、`service/runner.rs:252-338`、`service/ipc.rs:63`），
   `proxy.tun_unavailable` 错误码已存在（`error.rs:46`），`get_endpoint_links` 已返回
   `{ connection, endpoint_id, link }`（`status.rs:81-96`）。需求 2 和需求 4 都是**纯前端接线**，
   不存在"后端不支持"的阻塞。
2. **桌面端有一个阻塞性前置：双 store 并存**（§1）。不先解决，需求 2 和 4 会建在错误的 store 上，
   点 Start 会发出一份空的节点列表。
3. 需求 2 与 `ui-desktop/docs/ui-refactor-plan.md` 有重叠也有冲突：§5.12 / Phase 3.1 已经规划了
   TUN 开关（一致），但 §3.1 线框图把 `Refresh` 放进页面头部（与"去掉 Refresh"冲突）。
   **本计划在这两点上优先**，建议同步回写该文档。

---

## 0.1 执行进度（2026-09-22 当晚）

| 步骤 | 状态 | 说明 |
| --- | --- | --- |
| P0 store 收敛 | ✅ | `stores/config.ts` 收下 `applyInvite` / per-node 2FA / `name` 迁移；`stores/proxy.ts` 收下链接状态与轮询；`composables/useConfigStore.ts` 已删除，`dropLegacyKey()` 改 `true` |
| D1 移除添加节点（桌面） | ✅ | Add Node 按钮与 `updateConnectionString` 一并移除；连接串改为脱敏展示 + reveal/copy；`Load Example` 不再造节点 |
| D3 轮询（桌面） | ✅ | `stores/proxy.ts` 内 `setTimeout` 链：running 3s / starting 1s / stopped 5s，连续 3 次失败退避 10s 并置 `stale`；`visibilitychange` 立即重读 |
| D2 TUN 开关（桌面） | ✅ | 连接页 `AppToggle`，服务门控 + 内联安装 + 运行中切换走 confirm 重启；Settings 的 Proxy Mode 卡片解散，`useService` 并入 Service 面板 |
| D4 已连接 endpoint（桌面） | ✅ | 新增 Connected endpoints 卡片（含 `N direct · M relay` 汇总），Node List 去掉只镜像全局状态的绿点与行内徽标 |
| A1/A2 移除添加节点（Android） | ✅ | `AddNodeDialog` 删除；抽出 `handleInviteText()`，扫码与粘贴共用；新增 InviteLinkDialog |
| A4 主题层（Android） | ✅ | `Color.kt` 换品牌蓝（对齐桌面 `--accent`）、新增 `Shape.kt` / `Dimens.kt`、补齐 `Type.kt`、`dynamicColor` 默认关闭 |
| A5 按钮组件层（Android） | ✅ | 新增 `ui/components/NexaButtons.kt`；主界面按钮与两个对话框已换用 |
| A6 布局改造（Android） | ⏳ | 折叠面板整行可点、去掉 80dp FAB 让位、端点行改 ListItem、`EndpointDetailScreen` / `QrScannerDialog` / `PermissionGuideScreen` 换按钮组件 —— 下一步 |
| A3 `nexapipe://` intent-filter | ⏳ | 待定（Q5） |

验证：桌面 `npm run build`（vue-tsc + vite）通过、`lint:i18n` 168 keys 双语同步、`lint:tokens` 无新增违规；
Android `gradlew :app:compileDebugKotlin` BUILD SUCCESSFUL。

---

## 1. 前置 P0：桌面端 store 收敛（阻塞需求 2 与 4）

### 现状

同名的 `useConfigStore` 有两份实现，各自持有一份独立的响应式配置：

| | 文件 | localStorage key | 谁在用 |
| --- | --- | --- | --- |
| 旧 | `src/composables/useConfigStore.ts` | `nexa-config` | ConfigPage、DashboardPage、SettingsPage、ProxyStatusControl |
| 新 | `src/stores/config.ts` | `nexapipe.config`（v1，带迁移） | `stores/proxy.ts`、`main.ts`、`SideBarFooter.vue` |

`stores/proxy.ts` 的 `start()` 读的是**新** store 的 `config.nodes`（`stores/proxy.ts:119`），
而页面写的是**旧** store。今天这条链路没人走通（页面仍用 `ProxyStatusControl` 自己拼参数），
所以问题被掩盖了；一旦把 TUN 开关接到 `stores/proxy.ts` 上而连接页仍读旧 store，
就会出现"开关在新 store、节点在旧 store" → Start 发出 0 个节点。

另外新 store 缺旧 store 已有的能力，不能直接删旧的：`applyInvite`、`setNodeTwoFactor`、
`clearNodeTwoFactor`、`hasTwoFactor`、`proxyStatus`、`endpointLinks`、`linkKindFor`、
`setProxyStatus`、`setEndpointLinks`。

### 方案 A（推荐）：完成 store 切换

1. 把上述缺失能力搬到 `stores/config.ts` / `stores/proxy.ts`（invite 与 2FA 归 config，
   链接状态归 proxy）。
2. 四个页面 + `ProxyStatusControl` 全部改用 `stores/*`；删除 `src/composables/useConfigStore.ts`。
3. `stores/config.ts:39` 的 `dropLegacyKey()` 改为 `return true`，与删除旧 loader 是**同一个 commit**
   （早删会静默清空配置页，见该文件注释与 R3）。
4. `ProxyStatusControl.vue` 里的 `startProxy` / `stopProxy`（`:170-240`）整段删除——
   `stores/proxy.ts` 已有等价且更完整的实现（带超时轮询、模式校验、`startupError`）。
   组件退化为纯展示。

成本：约等于 refactor plan 的 Phase 3.1+3.2+3.3 中"换 store"那部分（不含视觉重做）。
收益：需求 2 与 4 直接落在正确的状态层，且 `ProxyStatusControl` 的 D12（状态所有权分裂）一并解决。

### 方案 B（最小改动）：全部留在旧 store

TUN 开关直接改旧 store 的 `config.useTun`，`ProxyStatusControl` 补上 `use_tun` 参数。
改动小、风险低，但 `stores/proxy.ts`（已写好 `setUseTun` / `serviceRunning` / `initProxyState`）
继续闲置，D12 继续存在，等于把欠账推到 Phase 3。

> 建议 **A**。需求 1 要动 ConfigPage、需求 2/4 要动 Connect 页，两个页面本来就要改，
> 顺手换 store 的边际成本最低。

---

## 2. 需求 1：移除手动添加节点，只保留扫码 / 邀请链接

### 2.1 桌面端现状

- `ConfigPage.vue:176-182` —— 头部 `Add Node` 按钮，调 `addNode()`（`composables/useConfigStore.ts:182`）。
- `ConfigPage.vue:226-239` —— 节点卡片里的**自由文本连接串输入框**，
  `updateConnectionString()` 会把任意字符串当 ticket / endpoint ID 存下来。
- `ConfigPage.vue:151-160` —— `Load Example` 在节点为空时也会 `addNode()`。
- 已有邀请链路：`InviteImportDialog.vue` + `api/invite.ts`（`isInviteLink` / `parseInvite`），
  解析在 Rust 侧（`parse_invite`），落到 `applyInvite()`（`useConfigStore.ts:244`）。
- `ConfigPage.vue:64-78` —— 往输入框里粘贴 `nexapipe://` 会被拦下来转给邀请对话框
  （因为 `detectConnectionType` 会把整个 URI 当成 ticket）。

### 2.2 桌面端目标形态

1. 删除 `Add Node` 按钮与 `addNode()` 在 UI 上的全部调用（含 `loadExampleConfig` 里的那次；
   示例配置只填网络字段，不再造节点）。`addNode()` 本身保留在 store 里——邀请导入仍要用它。
2. 节点卡片的连接串输入框改为**只读**：显示脱敏后的 ticket / endpoint ID（默认打码，
   带 reveal + copy），`updateConnectionString` / `updateConnectionString` 的写路径从页面移除。
   理由：节点只能来自邀请，但用户仍需要知道"这个节点连的是谁"。
3. 保留可编辑的部分：域名列表、per-node 2FA（都已经在同一个卡片里）。**已确认（2026-09-22）**：
   已有节点保持可编辑，限制只针对"新增节点"和"改连接目标"。
4. `Import Invite` 按钮从卡片头部挪到**页面头部主操作位**（现在它只是一个次要按钮，
   改成唯一入口后它就是主 CTA）。
5. 空状态：节点列表为空时的文案改为引导导入邀请，并给出 `nexapipe://…` 的示例形态。
6. 连接页（Dashboard）空状态里的 "Go to the Config page to add nodes"
   （`DashboardPage.vue:136`）同步改文案，且 CTA 直接指向导入对话框而不是 Config 页。

### 2.3 Android 现状

- `VpnControlScreen.kt:695-703` —— `FilledTonalButton` "Add endpoint" → `showAddNodeDialog`
  → `AddNodeDialog`（`:824-873`）→ `viewModel.addNode()`（`VpnViewModel.kt:808`）。
- `VpnControlScreen.kt:704-712` —— `FilledTonalButton` "Scan invite" → `QrScannerDialog`，
  结果在 `:580` 用 `EndpointInviteCodec.parse()` 解析。
- **没有粘贴邀请链接的入口**：`EndpointInviteCodec.parse` 全仓库只有 `:580` 一处调用。
- `AndroidManifest.xml` **没有** `nexapipe://` 的 intent-filter，`MainActivity` 也不读 `intent.data`
  —— 在手机浏览器里点邀请链接不会唤起 App。
- `EmptyNodesHint`（`:799-822`）文案是 "Add an endpoint ID or scan an invite…"。

### 2.4 Android 目标形态

1. 删除 `AddNodeDialog` 与 `showAddNodeDialog` 状态、"Add endpoint" 按钮。
   `VpnViewModel.addNode()` 保留（`applyInviteImport` 内部在用，`:124`）。
2. 新增 **"粘贴邀请链接"** 入口：一个带 `OutlinedTextField` 的对话框（或 bottom sheet），
   复用 `EndpointInviteCodec.parse()`。
3. **关键重构**：把 `:576-598` 里"扫码结果 → 解析 → 冲突确认 → 应用"这段逻辑抽成
   一个共享函数，例如 `handleInviteText(text: String): String?`，扫码与粘贴两个入口都调它。
   否则粘贴路径会漏掉 `inviteConflicts()`（:169）这道确认——而邀请会覆盖全局 relay 和
   该 endpoint 的 2FA，静默覆盖是不能接受的。
4. 文案同步：`EmptyNodesHint` 改为只提扫码 / 粘贴链接。
5. （可选，建议）`AndroidManifest.xml` 给 `MainActivity` 加 `nexapipe://` 的
   `<intent-filter>`（VIEW + BROWSABLE），`MainActivity.onCreate` 读 `intent?.data`，
   交给同一个 `handleInviteText`。这是 Android 上"点链接即加入"的完整体验，
   不加的话用户只能靠复制粘贴。

### 2.5 已决定：桌面端不做扫码

**决定（2026-09-22）**：桌面端不接摄像头，加入节点只走**粘贴 `nexapipe://` 邀请链接**
（对话框已存在，见 2.2 第 4 点）。系统级 URL scheme 注册（`nexapipe://` 直接唤起 App）**暂不做**，
需要时再单开一项。理由：摄像头要新依赖 + 三平台权限适配，代价与收益不成比例。

---

## 3. 需求 2：TUN 虚拟网卡开关 + 连接页动态更新

### 3.1 现状与要改掉的三个问题

**(a) "Proxy Mode" 名不副实。** `SettingsPage.vue:50-96` 的 Proxy Mode 卡片
（Normal Mode / Service Mode）实际选的是**执行后端**（进程内 / 系统服务，即 `useService`），
跟转发方式无关。真正的转发模式（TUN vs 本地代理）在 UI 上**根本没有开关**：
`ProxyStatusControl.vue:189-202` 的 `startProxy` 连 `use_tun` 参数都没传，
后端于是走隐式探测，可能静默开 TUN 或静默降级（refactor plan 的 D16）。

**(b) 状态不会自己更新。** `get_proxy_status` 只在挂载、`start`、`stop` 和
手动点 `Refresh Status`（`ProxyStatusControl.vue:344-355`）时被调用一次；
只有链路类型（link kind）有 5 秒轮询（`:150-160`）。服务死了、代理崩了、
TUN 掉回本地代理，界面都不会变——所以才需要那个 Refresh 按钮。

**(c) 开关该在哪。** TUN 开关与 Start 放在一起（clash-verge 的做法，也是 §5.12 rule 5），
Settings 里只留 TUN 设备名（`SettingsPage.vue:98-129`）。

### 3.2 目标形态（连接页 `/`，即 `DashboardPage.vue`）

```text
┌─ Connect ────────────────────────────────────────────────────────┐
│  ● Running · TUN                                     [ Stop ]     │
│  node 8f2c…9ab  [copy]                                            │
│                                                                   │
│  虚拟网卡模式 (TUN)   [ ●━━━ ]   需要已安装的系统服务             │
│                                                                   │
│  ── 已连接 ────────────────────────────────────  2 直连 · 1 中继 ─│
│  ▸ home.example.com       ● Direct                                │
│  ▸ 8f2c…9ab               ● Relay                                 │
│  ▸ Ticket ****c1d2        ● Direct                                │
└───────────────────────────────────────────────────────────────────┘
```

- **TUN 开关**：用已有的 `components/base/AppToggle.vue`，状态绑 `config.useTun`。
  - 服务未安装 → 开关 disabled + 提示文案；点击时走"内联安装"（confirm → `install_service`，
    UAC / sudo / polkit 提权流程已有 `service.elevation_*` 错误码）。
  - 代理运行中切换 → confirm 后重启（§5.12 rule 5 的后半句）。
  - 服务消失（卸载/崩溃）→ `refreshServiceRunning()` 已实现把开关弹回 off 并 toast
    （`stores/proxy.ts:201-216`），直接复用。
  - i18n key 已备好：`connect.tunToggle` / `connect.tunRequiresService` /
    `connect.tunUnavailableServiceGone` / `connect.modeMismatch`（`i18n/locales/en.json:62-65`）。
- **Stat 行**的 "Proxy Mode" 磁贴（`DashboardPage.vue:74-87`）改为展示**实际**模式
  （它已经是读 `proxyStatus.mode` 了，保留），并在与请求模式不符时给出警示样式
  ——`stores/proxy.ts:164-171` 已经会 toast `modeMismatch`。
- **SettingsPage**：删掉 Proxy Mode 卡片，把 `useService` 开关并进 Service 面板
  （与 §6.3 rule 2/3 一致）；TUN 分组只留设备名。

### 3.3 去掉 Refresh，改成动态更新

把轮询收敛到 `stores/proxy.ts`（模块级单例，不要放进组件）：

| 项 | 取值 |
| --- | --- |
| 轮询间隔 | 运行中 3s；`starting` 期间 1s（起速更快）；停止态 5s |
| 一次轮询做什么 | `get_proxy_status`；若 running，再取 `get_node_id` + `get_endpoint_links` |
| 额外触发 | `start()` / `stop()` 结束、窗口 focus（`visibilitychange`）、服务安装/卸载之后 |
| 并发保护 | in-flight 标记，上一轮没回来就跳过这一轮（避免慢后端堆积） |
| 失败处理 | 连续 3 次失败后退避到 10s，并在面板上标一个"状态可能过期"的提示；**不 toast**（后台轮询 toast 是噪音，见 `stores/proxy.ts:58-62` 现有约定） |

`ProxyStatusControl.vue` 里现有的 `LINK_POLL_INTERVAL_MS`（`:26`）和 `onMounted/onUnmounted`
定时器（`:150-168`）随之删除；组件只渲染 store 的状态。

> 与 refactor plan 的冲突：§3.1 线框图里页面头部是 `[Refresh] [Start Proxy]`。
> 本计划下头部改为 `[Start/Stop]`，不设 Refresh。需要回写该文档。

### 3.4 验收

- 无服务时：TUN 开关禁用 + 提示；点 Start 起本地代理，模式显示 Local Proxy。
- 装服务后：开关解锁；开 TUN → Start → 状态显示 TUN（`mode: "tun"`）。
- 手动 kill 服务进程：≤3s 内连接页自己变回 Stopped，不需要点任何按钮。
- TUN 已开时卸载服务：开关自动弹回 off + toast（已有实现）。
- 请求 TUN 但无权限：报 `proxy.tun_unavailable`，**不**静默降级。

---

## 4. 需求 3：Android 按钮样式与布局现代化

### 4.1 现状：主题层还是 M3 脚手架

| 文件 | 问题 |
| --- | --- |
| `ui/theme/Color.kt` | 就是新建项目模板的紫色三件套（`Purple40 #6650a4` / `Purple80 #D0BCFF`），与品牌无关 |
| `ui/theme/Theme.kt` | `dynamicColor = true` 默认开启 → Android 12+ 全盘取壁纸色，换壁纸就换主色；Android 8–11（minSdk 26）回落到紫色，两端观感完全不一致 |
| `ui/theme/Type.kt` | 只定义了 `bodyLarge`，其余样式全是 M3 默认；`Typography()` 未覆盖的层级没有区分度（标题/标签看起来一样） |
| 圆角 | 无统一 shape 定义，代码里手写 `RoundedCornerShape(8.dp)`、`50`、`24.dp`（`VpnControlScreen.kt:678/698/708/523`） |

### 4.2 按钮与布局的具体缺陷

| 位置 | 问题 |
| --- | --- |
| `VpnControlScreen.kt:695-712` | 两个 `FilledTonalButton` 并排 `weight(1f)`，圆角 8dp（比 M3 默认的 full-shape 更方）；"Scan invite" 用 `Icons.Default.Search`（放大镜），语义是"搜索"不是"扫码" |
| `VpnControlScreen.kt:229-261` | FAB 同时承担连接/断开，`containerColor = error` 表示"断开"，图标在 `CheckCircle` / `Close` 之间切——`CheckCircle` 读作"已完成"，`Close` 读作"关窗口"；无文字，全靠颜色猜 |
| 全屏 | 主操作只有这一个 FAB，卡片内部没有任何按钮；对照桌面端和 clash-verge，Start/Stop 是显式按钮 |
| `:616/628`、`EndpointDetailScreen.kt:587/601/641/737/797` | 对话框一律 `TextButton`，确认与"删除"同权重，无主次之分 |
| `:406/:444` | 折叠开关只有 `IconButton` 可点，标题不可点 → 触摸目标小 |
| `:517` | `Spacer(Modifier.height(80.dp))` 硬编码给 FAB 让位 |
| `:264-270` | 整页 `Column + verticalScroll` 平铺；`showSettings = true` 与 `showRelaySettings = false` 初值不一致，首屏高度每次进入都在跳 |

**图标集约束（硬限制）**：`app/build.gradle.kts` 的 release 未开 R8（`isMinifyEnabled = false`），
**不能引 `material-icons-extended`**（会把几十 MB 图标全打进 APK）。只能用 `Icons.Default.*` core 集，
需要的新图标要么从 core 里挑近似的，要么自绘 24dp 矢量。
另外 `composeBom = 2024.09.00`（Material3 1.3.x），**升级到 M3 Expressive（1.4+）不在本计划内**——
会牵动 Kotlin / AGP 版本，风险与收益不匹配。

### 4.3 改造方案

**Step 1 — 主题层（`ui/theme/`）**

1. `Color.kt`：定义品牌色板（建议沿用桌面 token 的主色，两端一致），补齐 M3 语义槽
   （`primary/onPrimary/primaryContainer/surface/surfaceContainerLow|High|Highest/error/…`）。
2. `Theme.kt`：`dynamicColor` 默认改 `false`（或做成 Settings 里的显式开关），保证品牌一致；
   提供完整 light / dark 两套 `ColorScheme`；挂上 `Shapes` 与 `Typography`。
3. 新增 `Shape.kt`：`xs 4 / sm 8 / md 12 / lg 16 / xl 28 / full`，按钮统一 `md 12`。
4. `Type.kt`：补齐 `displaySmall / titleLarge / titleMedium / titleSmall / bodyMedium /
   labelLarge / labelMedium / labelSmall`，`lineHeight` 给 CJK 留余量（不小于 1.4×fontSize）。
5. 新增 `Dimens.kt`：`space 4/8/12/16/20/24`、`minTouchTarget 48.dp`、`cardRadius 16.dp`。

**Step 2 — 按钮组件层（新增 `ui/components/NexaButton.kt`）**

| 组件 | 用途 | 规格 |
| --- | --- | --- |
| `NexaPrimaryButton` | 主操作（Connect / Import） | filled，`RoundedCornerShape(12.dp)`，`heightIn(min = 48.dp)`，icon 18dp + 8dp gap |
| `NexaTonalButton` | 次操作（Scan / Paste link） | tonal，`surfaceContainerHighest` 底 |
| `NexaTextButton` | 对话框次要操作 | 保持 text，但带形状与 48dp 触摸区 |
| `NexaDangerButton` | 删除 / Disconnect | `errorContainer` 底或 error 描边，与确认按钮明确区分 |
| `NexaIconButton` | 工具条图标 | 48dp 触摸区，统一 `contentDescription` 必填 |

全 App 的按钮替换为这五个组件；散落的 `RoundedCornerShape(8.dp)` / `50` 收敛到 shape token。

**Step 3 — 布局与信息层级**

1. **主操作显式化**：状态卡里放一个整宽的 `NexaPrimaryButton`（`Connect` / `Disconnect`，
   带 `CircularProgressIndicator` 的 loading 态），取代 FAB 承担主操作。
   FAB 降级为"添加 endpoint"入口（`Icons.Default.Add`，弹出"扫码 / 粘贴链接"二选一）。
2. **状态卡**：标题 + 状态点 + 副标题保持"恒定高度"（现有注释里已经为这个吃过亏，别破坏它）；
   已连接 endpoint 列表（见需求 4 的 Android 对照）留在卡片内。
3. **折叠面板**：整行可点（标题 + chevron 一起），`IconButton` 只作视觉指示；
   `showSettings` / `showRelaySettings` 初值统一为 `false`，首屏稳定。
4. **去掉 80dp spacer**（`:517`）：改用 `Scaffold` 的 `contentWindowInsets` 或列表底部
   `Spacer(Modifier.navigationBarsPadding())`。
5. **端点行**：改为 `ListItem` 风格（高度 ≥ 56dp，leading monogram、标题、副标题域名数、
   trailing chevron，2FA 锁标），整行单一触摸目标。
6. **顶栏**：补一个设置/关于入口位（现阶段可以是预留，不新增功能）。

### 4.4 验收

- `.\gradlew.bat :app:compileDebugKotlin --console=plain` 通过（PowerShell 里跑，`bash` 里没有 `sed` 之类工具）。
- 亮/暗两套主题、Android 12+ 与 Android 11 各截一次图对比（dynamic color 关掉后两端应一致）。
- 所有按钮触摸区 ≥ 48dp；所有 `contentDescription` 非空。
- APK 体积增量 ≈ 0（不引新依赖）。

---

## 5. 需求 4：连接页展示已连接 endpoint 的 relay / direct

### 5.1 现状

数据链路其实已经打通了：

- `get_endpoint_links`（`lib.rs:319`）→ `ProxyManager::endpoint_links()`（`manager.rs:513`）
  → 按 `connection`（ticket 或 endpoint ID 原样）返回 `{ connection, endpoint_id, link }`。
- 前端 `ProxyStatusControl.vue:105-116` 每 5s 拉一次，写进 `endpointLinks`；
  `linkKindFor(node)`（`useConfigStore.ts:340`）按 connection 匹配节点。
- 但**展示**有两处缺陷：
  1. `DashboardPage.vue:139-173` 的"Node List"把已配置和未配置的节点混在一起列，
     relay/direct 徽标（`:155-163`）夹在类型徽标和域名数之间，很容易看不见；
     行尾那个绿点（`:169-171`）只是全局 running 的镜像，不提供节点级信息。
  2. 状态面板里只有一个**聚合**胶囊（Direct / Relay / Mixed，`ProxyStatusControl.vue:82-96`），
     看不出是**哪个** endpoint 走的 relay。

Android 那边已经有一块 "Connected endpoints"（`VpnControlScreen.kt:327-356`），
只列真正连上的、每行带 `LinkKindBadge`——桌面端照这个语义对齐即可。

### 5.2 目标形态

1. 连接页新增 **"Connected endpoints" 卡片**，位置在状态面板正下方：
   - 只列**有实时链路**的 endpoint（link 条目存在且不是 unknown），没有就整卡不渲染
     （沿用现有约定：没连上就什么都不画，比画一个过期的 direct 更诚实）。
   - 每行：节点名（无 name 时用脱敏的 ticket / 短 endpoint ID）+ `Direct` / `Relay` 徽标，
     复用 `AppIcon` 的 `link-direct` / `link-relay` / `link-unknown`。
   - 卡片标题右侧给一行汇总：`2 direct · 1 relay`。
2. **Node List** 里去掉那个只镜像全局 running 的绿点（`:169-171`）和行内 link 徽标，
   让它纯粹是"配置清单"；实时链路信息只出现在新卡片里，避免两处说法打架。
3. 状态面板的聚合胶囊保留（一眼看全局），但它与新卡片读的是同一份 `endpointLinks`。
4. 轮询统一由 §3.3 的 store 定时器驱动，`link` 会在 iroh 打洞成功后自己从 relay 翻成 direct
   ——这点必须在实现里保留：**不要**用配置里的 relay mode 去推断，那是另一个问题
   （见 `status.rs:81-85` 的注释）。

### 5.3 验收

- 代理未启动：卡片不出现，Node List 干净。
- 启动后 ≤3s：卡片出现，每个连上的 endpoint 一行。
- 手动让某个 endpoint 只能走 relay（关掉对应直连路径）：该行徽标从 Direct 变 Relay，不需要点刷新。
- 停止代理：卡片消失，`endpointLinks` 清空（不要留下过期的徽标）。

---

## 6. 执行顺序与提交切分

两个 submodule 的改动互不依赖，可以并行；桌面端内部有依赖顺序。

```text
ui-desktop
  D1  删除 Add Node（ConfigPage）+ 连接串只读 + 邀请入口提到页头        [需求 1]
  D2  store 收敛：补齐 stores/* → 页面换 store → 删旧 composable
      → dropLegacyKey() 改 true                                        [前置 P0]
  D3  ProxyStatusControl 退化为纯展示；轮询搬进 stores/proxy.ts         [需求 2 的一半]
  D4  连接页加 TUN 开关 + 已连接 endpoint 卡片；Settings 解散 Proxy Mode [需求 2 + 4]

ui-android
  A1  删除 AddNodeDialog 与 Add endpoint 按钮                          [需求 1]
  A2  抽出 handleInviteText()；新增粘贴邀请链接入口                     [需求 1]
  A3  （可选）nexapipe:// intent-filter + MainActivity 读 intent.data    [需求 1]
  A4  主题层：Color / Theme(dynamicColor) / Shape / Type / Dimens        [需求 3]
  A5  NexaButton 组件层 + 全量替换                                      [需求 3]
  A6  布局：主操作显式化、折叠面板整行可点、去 80dp spacer、端点行 ListItem [需求 3]
```

D2 会大改文件，单独一个 commit，方便 review 和回滚。

---

## 7. 验收清单

**桌面端（`ui-desktop`）**

- [ ] `npm run build`（`vue-tsc --noEmit`）通过；`npm run lint:i18n`、`npm run lint:tokens` 无新增违规。
- [ ] Config 页没有"添加节点"入口；节点只能从邀请产生；已有节点的连接串不可编辑但可查看/复制。
- [ ] 粘贴 `nexapipe://…` 到任何输入框都会走邀请导入，不会被当成 ticket 存下。
- [ ] 连接页有 TUN 开关，服务未安装时禁用并提示；装服务后可用。
- [ ] 连接页没有 Refresh 按钮；kill 服务后 ≤3s 状态自己变化。
- [ ] 已连接 endpoint 卡片按实际路径显示 Direct / Relay，且会自己更新。
- [ ] Settings 页不再有 "Proxy Mode" 卡片；`useService` 归到 Service 面板。
- [ ] 旧 `nexa-config` 用户的配置迁移后不丢（nodes / 域名 / 2FA / relay）。
- [ ] `cargo check` 不需要跑（本计划不改 Rust）；若 src-tauri 有任何改动再补。

**Android（`ui-android`）**

- [ ] `.\gradlew.bat :app:compileDebugKotlin` 通过；`assembleDebug` 通过。
- [ ] 没有手动添加 endpoint 的入口；扫码与粘贴链接都能走完整的
      `inviteConflicts()` → 确认 → 应用 流程（粘贴路径不能绕过确认）。
- [ ] 邀请覆盖 relay / 2FA 时仍然弹确认。
- [ ] 亮/暗主题 + Android 12+ / Android 11 截图对比；按钮触摸区 ≥ 48dp。
- [ ] APK 体积无明显增加（未引 `material-icons-extended`）。

---

## 8. 未决问题（需要拍板）

### 已决定（2026-09-22）

| # | 问题 | 决定 |
| --- | --- | --- |
| Q1 | 桌面端要不要真的做"扫码"？ | **不做**。桌面端只走粘贴邀请链接；系统级 `nexapipe://` scheme 注册暂不做 |
| Q2 | Config 页已有节点，域名和 2FA 是否仍然可编辑？ | **可编辑**。限制只针对"新增节点"和"改连接目标"（连接串转为只读） |
| Q3 | 桌面端 store 收敛走方案 A（完整切换）还是 B（留在旧 store）？ | **A —— 完整切换** |

### 仍待定

| # | 问题 | 建议 |
| --- | --- | --- |
| Q4 | Android 主题是否保留 dynamic color？ | 默认关闭，保证品牌一致；若希望跟随壁纸，做成 Settings 里的显式开关 |
| Q5 | Android 是否加 `nexapipe://` intent-filter？ | 建议加，成本很低（manifest + `onCreate` 读 `intent.data`），体验完整 |
| Q6 | M3 版本是否升级（2024.09.00 → 2025.x，拿到 Expressive 组件）？ | 不在本计划内。会牵动 Kotlin/AGP，单独评估 |
