> 历史版本 v0.1.0；新安装推荐 [最新版本](https://github.com/ffhmfd/nodekit/releases/latest)。

# NodeKit

个人 Linux VPS 节点管理工具：Bash 安装入口、Go 管理器和独立 mihomo 内核。

## 功能

- VLESS REALITY Vision、SS2022、TUIC V5、Hysteria2、AnyTLS。
- 中文菜单和非交互命令；节点配置与订阅由同一份配置生成。
- HTTPS 完整配置订阅和纯节点 provider，面向 FlClash 等 mihomo 客户端。
- 每台 VPS 独立统计本项目节点上传/下载，订阅展示总额度及到期日期。
- 北京时间每月指定日、小时清零，也可以手动清零。
- Cloudflare DNS-01 申请/续期证书；独立端口和 systemd 单元。

**总额度和到期时间仅展示，不停用节点。** 订阅显示随客户端刷新更新。

## 运行环境

目标：Debian 12/13、Ubuntu 22.04/24.04，systemd，AMD64/ARM64。已测试的系统、协议及尚待验收的项目见 验收记录（见该版本 Release 说明）。

管理器为无 CGO 的 Go 二进制，目标机无需 Go/Python。锁定内核 `v1.19.33`；以已验证组合为单位升级，不盲目跟随 Alpha。

## 构建

```bash
bash scripts/build.sh test ./...
bash scripts/package.sh v0.1.0
```

构建缓存和发布包默认存于源码目录的上一级，分别为 `cache/`、`modules/`、`tmp/`、`dist/`。可以设置 `NODEKIT_BUILD_ROOT`。本项目开发优先在 VPS 的专用临时目录进行构建。

发布包包含管理器、匹配架构的 mihomo 和发行元信息。正式公开仓库/发布地址尚未设置，以下使用本地包，不提供虚构的一键下载 URL。

## 安装与初始化

```bash
sudo bash install.sh --file nodekit-v0.1.0-linux-amd64.tar.gz --sha256 <可信的SHA256>
sudo nodekit init
```

ARM64 使用对应包。安装器校验下载包、拒绝路径穿越及未知同名资源。安装程序与初始化节点分开，初始化前准备：

1. 一个专用子域名，其 A 记录指向本机公网 IPv4，Cloudflare 设置 **DNS only / 灰云**。
2. 对该 zone 有 DNS 编辑和必要读取权限的 API Token，放在服务器受限文件（例如 `/root/nodekit-cloudflare.token`，权限 `600`）。不要把 Token 填到命令参数或订阅中。
3. ACME 注册邮箱、节点使用端口、流量额度和日期。Cloudflare Origin Certificate 不能替代灰云连接需要的公网受信任证书。

无交互示例（全为占位值）：

```bash
sudo nodekit init \
  --domain node.example.com --address 203.0.113.10 \
  --email admin@example.com --token-file /root/nodekit-cloudflare.token \
  --firewall auto
```

`--firewall auto` 使用已识别的 UFW/iptables 管理方式，只维护项目规则。`manual` 模式由用户放行。OCI 安全列表/NSG 也必须允许相应端口。

默认候选端口：VLESS 24441/TCP，SS2022 24442/TCP+UDP，TUIC 24443/UDP，HY2 24444/UDP，AnyTLS 24445/TCP，HTTPS 订阅 24446/TCP。冲突时拒绝占用，使用私有配置文件修改端口后初始化。

可以先生成私有配置并编辑，再安装：

```bash
sudo nodekit init --domain node.example.com --address 203.0.113.10 --dry-run
# 编辑 /etc/nodekit/bootstrap.json，包括每个协议 enabled/port、额度和日期。
sudo nodekit init --config /etc/nodekit/bootstrap.json \
  --email admin@example.com --token-file /root/nodekit-cloudflare.token --firewall auto
```

首次 ACME 测试可使用 `--staging`，其证书不被普通客户端信任；正式部署使用生产 CA。也可用 `--certificate` 和 `--key` 导入已有匹配域名的证书，未配置 DNS 凭据时需自行续期。

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
```

`GB/TB` 为十进制，`GiB/TiB` 为二进制。`expiry none` 移除到期显示。`config export` 导出包含节点凭据的私有 JSON，`config apply <文件>` 应用编辑后的配置；修订过期会拒绝覆盖。

完整订阅：`https://域名:端口/s/token/config.yaml`。FlClash 中添加为远程配置。

纯节点：`https://域名:端口/s/token/proxies.yaml`，适用于 `proxy-providers`。provider 元信息的 UI 显示由客户端决定。完整模板含手动选择、自动选择、故障切换，基础分流为局域网直连、其他走代理。

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
sudo nodekit uninstall --purge         # 删除本项目数据
# 保留数据重装程序之后：
sudo nodekit resume
```

先验证新配置和二进制，再切换版本；新服务健康检查失败回退。更改协议凭据、监听或证书可能使该协议的连接重建。现有 Caddy、sing-box、Docker 等不作为本项目操作对象。

若 current 版本本身不能执行，可使用 `/opt/nodekit/previous/nodekit recover`。升级快照和日志保存在 root 独占的 `/etc/nodekit/lifecycle`，后台账户无权替换；内核启动前也会检查未完成的升级。

手动 `cert renew` 实际由后台服务身份签发和保存，不会将证书/账户文件改成 root 专用。`status` 显示 TLS 证书期限、续期模式和失败重试信息。更换域名可以使用 `nodekit cert renew --domain <新域名>`，新证书成功后才提交配置。

## 测试

```bash
NODEKIT_CORE_BIN=/path/to/mihomo bash scripts/build.sh test ./...
# 并发检测需要独立 C 编译器（发布仍然 CGO_ENABLED=0）
CGO_ENABLED=1 CC='zig cc' bash scripts/build.sh test -race ./...
```

没有设置 `NODEKIT_CORE_BIN` 时真实内核集成测试显式跳过。测试时钟可注入，避免改变宿主时钟；跨 VPS 测试只临时放行对端 IP 所需的精确规则，测试结束回收。
