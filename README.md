# NodeKit

Linux VPS 节点管理工具：Bash 安装入口、Go 中文向导和独立 mihomo 内核。

## 功能

- VLESS REALITY Vision、SS2022、TUIC V5、Hysteria2、AnyTLS。
- 中文菜单和非交互命令；节点配置与订阅由同一份配置生成。
- HTTPS 完整配置订阅和纯节点 provider，面向 FlClash 等 mihomo 客户端。
- 可选 Cloudflare 橙云 HTTPS 订阅，五协议节点使用公网 IP 直连并保持 TLS 身份校验。
- 每台 VPS 独立统计本项目节点上传/下载，订阅展示总额度及到期日期。
- 北京时间每月指定日、小时清零，也可以手动清零。
- Cloudflare DNS-01 申请/续期证书；独立端口和 systemd 单元。
- 托管本节点 Cloudflare DNS，分阶段彻底卸载，失败可重试。
- 国旗＋主机名＋协议名称、逐协议自定义名称、可编辑 REALITY SNI。
- 输入中 Ctrl+C 取消并返回主菜单；主菜单 Ctrl+C 退出。

**总额度和到期时间仅展示，不停用节点。** 订阅显示随客户端刷新更新。

## 运行环境

目标：Debian 12/13、Ubuntu 22.04/24.04，systemd，AMD64/ARM64。安装需要 root、Bash、curl、tar、gzip 和 sha256sum。

管理器为无 CGO 的 Go 二进制，目标机无需 Go/Python。锁定内核 `v1.19.33`；以已验证组合为单位升级，不盲目跟随 Alpha。

## 构建

```bash
bash scripts/build.sh test ./...
bash scripts/package.sh v0.4.0
```

构建缓存和发布包默认存于源码目录的上一级，分别为 `cache/`、`modules/`、`tmp/`、`dist/`。可以设置 `NODEKIT_BUILD_ROOT`。本项目开发优先在 VPS 的专用临时目录进行构建。

发布包包含管理器、匹配架构的 mihomo 和发行元信息。原创代码采用 MIT；第三方许可证及对应源码见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 和同一 Release 的附属资产。

## 安装与初始化

```bash
# 官方发布仓库。
repo=ffhmfd/nodekit
curl -fLsS --proto '=https' --proto-redir '=https' "https://github.com/$repo/releases/latest/download/install.sh" -o install.sh
sudo bash install.sh --repo "$repo"
# 可用 --version v0.4.0 固定版本。
# 离线安装仍支持：
sudo bash install.sh --file nodekit-v0.4.0-linux-amd64.tar.gz --sha256 <可信的SHA256>
sudo nodekit setup
```

安装器自动识别 AMD64/ARM64，从同一固定 Release 取得包和 SHA256SUMS。校验用于下载完整性，信任来源是所选仓库和 HTTPS，并非独立数字签名。交互安装后进入向导，已有安装进入管理菜单；非终端运行时显式添加 `--non-interactive`，仅部署程序，随后执行 `nodekit setup` 或带完整参数的 `nodekit init`。初始化前准备：

1. 一个 Cloudflare 区域内的专用子域名。向导创建或显式接管 A/AAAA；`direct` 使用灰云，默认 `cloudflare` 使用橙云。
2. 该区域的 **Zone Read、DNS Edit** API Token。向导直接输入或粘贴 Token，输入时不回显，无需准备文件路径；确认提交后自动保存标准副本 `/root/nodekit-cloudflare.token`（root/600）和续期副本 `/etc/nodekit/cloudflare.token`（root/服务组640）。普通卸载保留，彻底卸载删除这两个文件，不撤销 Cloudflare API Token。非交互初始化仍使用 `--token-file` 读取受限文件。
3. ACME 注册邮箱、节点使用端口、流量额度和日期。节点 TLS 直连仍需要公网受信任证书，不能用 Cloudflare Origin Certificate 替代。

无交互示例（全为占位值）：

```bash
sudo nodekit init --managed-dns --subscription-mode cloudflare \
  --domain node.example.com --address '<VPS公网IP>' \
  --email admin@example.com --token-file /root/nodekit-cloudflare.token \
  --firewall auto --name my-vps --country JP --reality-sni addons.mozilla.org
```

`--firewall auto` 使用已识别的 UFW/iptables 管理方式，只维护项目规则。`manual` 模式由用户放行。OCI 安全列表/NSG 也必须允许相应端口。

默认候选端口：VLESS 24441/TCP，SS2022 24442/TCP+UDP，TUIC 24443/UDP，HY2 24444/UDP，AnyTLS 24445/TCP，HTTPS 订阅 24446/TCP。冲突时拒绝占用，使用私有配置文件修改端口后初始化。

可以先生成私有配置并编辑，再安装：

```bash
sudo nodekit init --domain node.example.com --address '<VPS公网IP>' --dry-run
# 编辑 /etc/nodekit/bootstrap.json，包括每个协议 enabled/port、额度和日期。
sudo nodekit init --config /etc/nodekit/bootstrap.json \
  --email admin@example.com --token-file /root/nodekit-cloudflare.token --firewall auto
```

首次 ACME 测试可使用 `--staging`，其证书不被普通客户端信任；正式部署使用生产 CA。也可用 `--certificate` 和 `--key` 导入已有匹配域名的证书，未配置 DNS 凭据时需自行续期。

### 橙云订阅 + IP 直连（v0.1.1）

1. 将订阅子域名的 A 记录设为橙云，内容填对应 VPS IP。检查同名 A/AAAA，避免遗漏灰云源站记录。
2. 订阅回源使用 **Full (strict)**；调整前检查区域中其他网站的设置。不要将订阅路径套入登录页或交互式验证码，不要重定向到源站 IP，也不要覆盖 `Cache-Control: no-store` 或 `Subscription-Userinfo`。
3. 放行源站订阅端口 **8443/TCP** 和各协议端口。OCI 安全列表/NSG 同样需要放行。
4. 使用自己的真实公网 IP 初始化（`<VPS公网IP>` 为占位符，文档保留地址和私网地址会被拒绝）：

```bash
sudo nodekit init --subscription-mode cloudflare \
  --domain node.example.com --address '<VPS公网IP>' \
  --email admin@example.com --token-file /root/nodekit-cloudflare.token \
  --firewall auto
```

新建橙云配置默认 8443，也可通过 `--subscription-port` 选择 2053、2083、2087、2096、8443。IPv6 地址需要 `--ipv6`，或在导入配置中设置 `ipv6: true`。使用 `--config` 时保留文件中的显式端口；不兼容时应编辑文件或传入合法端口。

订阅形如 `https://node.example.com:8443/s/<token>/config.yaml`。只有 HTTPS 订阅经过 Cloudflare；全部节点 `server` 为 VPS IP，TUIC/HY2/AnyTLS 的 SNI 为证书域名，REALITY 使用自己的 SNI。节点不依赖域名解析，TLS 校验保持启用。DNS-01 签证书不要求公开 DNS 指向源站。

**已有配置迁移：先升级至 v0.1.1，再设置真实公网 IP 和模式，最后开启橙云并刷新客户端订阅。**

```bash
sudo nodekit config set address '<VPS公网IP>'
sudo nodekit config set subscription-mode cloudflare
sudo nodekit subscription
```

模式切换会保留兼容端口，否则选择 8443；端口冲突则拒绝并保持原配置。也可先设置其他兼容订阅端口。缺少 `subscription_mode` 的旧 JSON 始终按 `direct` 处理，旧节点地址/端口不会自动迁移。

公开 DNS 查询返回 Cloudflare 边缘地址后，不再直接返回 VPS IP；这不会删除历史 DNS 记录，也不隐藏订阅中的节点 IP。上线验收应检查公开 DNS、边缘与源站两段 TLS、两种订阅 YAML、userinfo 用量更新和 FlClash 实际连接。

## 日常使用

```bash
sudo nodekit                            # 中文菜单
sudo nodekit status
sudo nodekit subscription               # 显示包含访问凭据的订阅链接
sudo nodekit subscription rotate        # 更换订阅 token，节点凭据不变
sudo nodekit protocol disable tuic
sudo nodekit protocol enable tuic
sudo nodekit protocol port hy2 25444
sudo nodekit protocol rotate ss2022
sudo nodekit config set quota 500GB
sudo nodekit config set expiry '2026-12-31 18:00'
sudo nodekit config set reset '15@8'     # 每月15日北京时间08:00
sudo nodekit usage reset
sudo nodekit cert renew
sudo nodekit logs
sudo nodekit config set subscription-port 8443
sudo nodekit capabilities              # 只读查看程序支持的订阅模式
sudo nodekit config set name my-vps
sudo nodekit config set country JP
sudo nodekit config set name-style flag-host
sudo nodekit protocol name vless '我的 REALITY'
sudo nodekit protocol name vless auto  # 恢复自动名称
sudo nodekit config set reality-sni addons.mozilla.org
sudo nodekit config set reality-target addons.mozilla.org:443
sudo nodekit dns status
sudo nodekit dns adopt                 # 为旧安装登记匹配DNS，purge将删除它
sudo nodekit dns recover
sudo nodekit setup --resume
```

`GB/TB` 为十进制，`GiB/TiB` 为二进制。`expiry none` 移除到期显示。`config export` 导出包含节点凭据的私有 JSON，`config apply <文件>` 替换完整配置，不作局部合并；修订过期会拒绝覆盖。

新配置默认 REALITY SNI 为 `addons.mozilla.org`；旧配置升级保留原值。修改 SNI 会同步握手目标443并探测 TLS 1.3/h2，目标网站日后变化仍可能影响连接。国旗检测失败使用🌐；显示名只影响订阅，不重置节点凭据或用量。

完整订阅：`https://域名:端口/s/token/config.yaml`。FlClash 中添加为远程配置。

纯节点：`https://域名:端口/s/token/proxies.yaml`，适用于 `proxy-providers`。provider 仍只含 `proxies`，节点、凭据及用量展示与完整订阅一致，不覆盖使用者自己的分流、DNS 或嗅探；元信息的 UI 显示由客户端决定。

### 完整订阅分流、DNS 与嗅探

`config.yaml` 采用以下客户端策略（服务端仍为 `MATCH,DIRECT`）：

- 保留“节点选择”“自动选择”“故障切换”。YouTube、Telegram 的“电报信息”和最终兜底“漏网之鱼”默认跟随“节点选择”；“节点选择”和“漏网之鱼”可手动选择 `DIRECT`。
- “ChatGPT”组用于 OpenAI、Gemini/Bard，排除已知 `CountryCode=HK` 或名称含香港标记的节点。没有合格候选时使用 `REJECT`，不回退香港节点或直连；未知国家不代表支持 AI 解锁。全部协议关闭时，代理候选同样使用 `REJECT`，直连规则仍然有效。
- YouTube、AI 专项规则优先，其后为应用/面板及私有域名直连、广告拦截、境外域名代理、国内域名与局域网/国内 IP 直连、Telegram IP 专项和最终兜底。“全球拦截”默认 `REJECT`，可手动改为 `DIRECT`。**Apple/iCloud 默认走“节点选择”（代理），不是直连。** IPv4/IPv6 私网保护保留，未启用 QUIC 拦截。
- 新业务组与自定义节点重名时，仅策略组追加无冲突后缀，节点名称和凭据不变。
- DNS 使用 `fake-ip` 模式、`198.18.0.1/16`、国内 bootstrap 和 DoT 上游；保留过滤列表 `["*", "+.lan", "+.local"]`。锁定内核 `v1.19.33` 实测中，`*` 匹配单标签名称，不是所有域名：普通多标签域名仍返回 fake-IP，`.lan`/`.local` 及其子域名返回真实解析结果。不能据此宣称消除了 DNS 污染或泄漏。
- 开启 DNS 映射、纯 IP 嗅探和目标覆盖；HTTP 嗅探 80、8080–8880，TLS/QUIC 嗅探 443、8443。不额外开放 LAN、控制 API、客户端端口或 TUN。顶层及 DNS 的 IPv6 继续由原 IPv6 开关或已启用的 IPv6 节点决定，原 IPv4 节点的解析约束保留。

完整模板依赖 Loyalsoldier 的 11 个远程 rule-provider（每日更新），以及 mihomo 的 GEOSITE（YouTube/OpenAI）和 GEOIP（LAN/CN）支持。客户端首次启动可能下载规则及缺失的 Geo 数据，后续也需要更新；资源不可达或下载失败会影响加载与分流。模板并非离线规则包，也不保证目标网站或节点实际可达。

**应用新版策略：先将 VPS 管理器升级到包含此改造的版本，再在客户端刷新原 `config.yaml` 地址。** URL/Token、节点身份与用量/到期展示不变，无需新建订阅地址；仅修改本地源码不会更新已部署 VPS 的响应。只需要节点、不想更换现有客户端策略时，继续使用原 `proxies.yaml`。

## 安装后添加 IPv6 节点

先完成原有 IPv4 初始化，再打开管理菜单的 **24 IPv6节点管理**。初始向导不会自动启用 IPv6，也不会默认复制 IPv4 的协议选择。菜单可查看状态、配置/选择协议、重新启用已保存的选择或关闭 IPv6。

```bash
sudo nodekit ipv6 status
sudo nodekit ipv6 configure --address '<本机已分配的公网IPv6>' --protocols vless,hy2
sudo nodekit ipv6 disable
sudo nodekit ipv6 enable             # 使用已保存的 IPv6 地址和协议选择
```

IPv6 可独立选择 VLESS、SS2022、TUIC、Hysteria2、AnyTLS，包括 IPv4 没有启用的协议。修改某一地址族的协议启停不改变另一组；同协议的端口、密码/UUID、REALITY 参数及证书共用，因此修改这些共用参数会同时作用于两类入口。

IPv4 节点名称、订阅 URL 和 Token 保持不变；新增节点名称追加 ` · IPv6`，完整配置和纯节点 provider 都通过原订阅提供。两类入口共用原有用量、额度、到期及每月清零，不重复计算。使用 IPv6 节点的客户端网络必须具备 IPv6 连接能力；provider 使用者也应检查自己的客户端 IPv6 设置。

必须使用网卡上已分配且有效的公网 IPv6，不能填写链路本地、ULA、回环、文档地址或未分配的地址。程序不会修改网卡、路由、sysctl 或云安全组；使用自动防火墙时只维护项目规则，云端 IPv6 入站规则仍需自行放行。节点是 **IPv6 连接入口**，不是强制网站流量走 IPv6 出口，不需要为订阅域名新增 AAAA。

首次启用会将核心的通配监听转换为明确 IPv4/IPv6 地址监听，避免未选择协议被另一地址族意外开放；过程中可能出现短暂连接重建。IPv4 公网地址经 NAT 映射时，使用本机实际 IPv4 地址监听。关闭 IPv6 会移除新增入口和订阅条目，但保留选择及明确 IPv4 监听；不会重置 IPv4 节点、凭据、证书或用量。

若 VPS 的网卡地址发生变化，请重新配置并选择当前已分配的地址。为避免启用客户端 IPv6 后原域名节点通过 AAAA 改走 IPv6，配置此功能后的原节点锁定 IPv4 解析；新增 IPv6 节点仍使用明确的 IPv6 地址。

旧配置不会自动迁移或启用此功能。原来已使用旧 `--ipv6` 监听方式的安装保持旧行为，不直接叠加新的菜单配置。保存过新 IPv6 设置的安装需要支持 `ipv6-nodes-v1` 的程序处理升级、回滚和保留数据重装，即使暂时关闭 IPv6 也不能用旧程序悄悄丢弃设置。

## 流量与时间语义

- 所有业务日期使用 `Asia/Shanghai`；保留 VPS 自己的系统时区。
- 每月指定日不存在时，取当月最后一天同一小时。修改安排从未来第一个边界生效，手动清零不改变定时安排。
- 读取专用 mihomo 进程的累计计数，不依赖仅存活连接的列表；SSH、其他代理、网站和订阅 HTTP 服务不计入。
- 是内核报告的代理转发量，可能包含 REALITY 回落等协议相关转发，不等于 HTTP 正文字节，也不等于云厂商账单。
- 默认 5 秒采集落盘。正常管理器重启补齐同一内核累计差值；异常核心退出/掉电可能丢失最后未采集窗口。采集服务中断时窗口可能更大。
- 管理器离线跨月、内核持续运行时，无法准确拆分跨月流量，恢复时建立当前基线并显示缺口，而不把整段历史算入新月。

## 服务与数据

| 路径/服务 | 用途 |
|---|---|
| `/opt/nodekit/releases` | 版本化程序与内核 |
| `/etc/nodekit` | 管理设置、受限 DNS 凭据 |
| `/var/lib/nodekit/state.db` | 配置、累计计量、操作恢复状态 |
| `/var/lib/nodekit/certs` | 不可变证书版本 |
| `/run/nodekit` | 私有 Unix 控制接口 |
| `nodekit-core.service` | 专用代理进程 |
| `nodekit-manager.service` | 订阅、用量及证书管理 |

## 升级、恢复与卸载

```bash
sudo nodekit upgrade --file <新版本包> --sha256 <可信的SHA256>
sudo nodekit rollback
sudo nodekit recover                   # 恢复未完成的升级
sudo nodekit uninstall                 # 保留配置与统计
sudo nodekit uninstall --purge         # 删除本节点DNS、项目数据和标准Token文件
# 保留数据重装程序之后：
sudo nodekit resume
```

先验证新配置和二进制，再切换版本；新服务健康检查失败回退。更改协议凭据、监听或证书可能使该协议的连接重建。现有 Caddy、sing-box、Docker 等不作为本项目操作对象。

橙云模式下，升级/回滚在停服务前检查目标程序能力，不支持该模式的 v0.1.0 会被拒绝。确需降级时先显式切回 `direct`，并恢复灰云解析与客户端订阅；这会重新公开域名到源站 IP 的对应关系。不要绕过新版入口手工替换 current 或使用旧程序发起降级。

启用新名称或托管DNS后，不兼容的旧版本会被拒绝。恢复工具也必须支持当前功能；使用同版本或兼容新版管理器执行 `recover`。升级快照和日志保存在 root 独占的 `/etc/nodekit/lifecycle`，后台账户无权替换。

彻底卸载先删除精确登记的DNS，再清理服务和本地数据，最后删除凭据；**不会撤销 Cloudflare API Token**。标准Token路径如果变成符号链接，只删除链接；自选外部输入文件保留。DNS删除失败或记录被外部修改时保留重试状态。中断后使用 `/opt/nodekit/current/nodekit uninstall --purge` 继续，已删除的DNS不会因Ctrl+C恢复。普通卸载保留DNS、Token、证书和用量。手工DNS/导入证书且无Cloudflare凭据的direct安装仅清理本地资源。

手动 `cert renew` 实际由后台服务身份签发和保存，不会将证书/账户文件改成 root 专用。`status` 显示 TLS 证书期限、续期模式和失败重试信息。更换域名可以使用 `nodekit cert renew --domain <新域名>`，新证书成功后才提交配置。

## 测试

```bash
NODEKIT_CORE_BIN=/path/to/mihomo bash scripts/build.sh test ./...
# 并发检测需要独立 C 编译器（发布仍然 CGO_ENABLED=0）
CGO_ENABLED=1 CC='zig cc' bash scripts/build.sh test -race ./...
```

没有设置 `NODEKIT_CORE_BIN` 时真实内核集成测试显式跳过。测试时钟可注入，避免改变宿主时钟；跨 VPS 测试只临时放行对端 IP 所需的精确规则，测试结束回收。

公开源码导出：`python3 scripts/export-public.py /path/to/new-public-directory`。仅导出已跟踪的白名单源码和发布文件，不包含 Git 历史、本地运维记录或运行配置。在干净公开仓库推送版本tag后，GitHub Actions 构建并发布双架构资产。`scripts/cross-test.ps1` 通过显式参数接收两台测试VPS及密钥路径；系统生命周期测试只能在空白测试机运行。
