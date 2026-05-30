# 防火墙自动管理脚本 (auto-firewall.sh)

适用于 **Ubuntu / Debian** 云端 VPS 的一键防火墙自动化脚本，集成 **UFW + Fail2ban + Docker** 三重防线。

## 功能概览

| 功能 | 说明 |
|------|------|
| UFW 自动初始化 | 默认拒绝入站、放行出站，自动扫描监听端口生成白名单 |
| 端口动态管理 | Cron 每 5 分钟扫描端口变化，自动放行新端口/回收失效端口 |
| Docker 兼容修复 | 自动修补 Docker 绕过 UFW 的安全漏洞（iptables DOCKER-USER 链） |
| Fail2ban 联动封禁 | 自动安装配置 Fail2ban，检测恶意 IP 并通过 UFW 封禁，支持 IP 白名单 |
| 系统自动清理 | 每小时清理 APT 缓存、旧内核、systemd 日志，内存不足时释放缓存 |
| IP 白名单保护 | 支持 Fail2ban ignoreip + UFW 双重白名单，防止误封 |

## 快速开始

### 安装

```bash
# 赋予执行权限
chmod +x auto-firewall.sh

# 一键安装（自动初始化 UFW、Fail2ban、Cron）
sudo bash auto-firewall.sh install
```

安装过程自动完成：
1. 检测系统环境（Debian/Ubuntu）
2. 安装并初始化 UFW（默认 deny incoming / allow outgoing）
3. 扫描当前监听端口，生成端口白名单
4. 检测 Docker 并修复 UFW 绕过问题
5. 安装配置 Fail2ban（sshd jail + UFW 联动封禁）
6. 部署 Cron 定时任务

### 查看状态

```bash
sudo bash auto-firewall.sh status
```

### 手动触发

```bash
sudo bash auto-firewall.sh port-check      # 扫描端口并自动放行/回收
sudo bash auto-firewall.sh fail2ban-check  # 检测 Fail2ban 状态、同步 IP 白名单
sudo bash auto-firewall.sh cleanup         # 系统清理 + 日志轮转
```

### 帮助

```bash
sudo bash auto-firewall.sh help
```

## 配置文件

| 文件 | 说明 |
|------|------|
| `/opt/auto-firewall/port-whitelist.conf` | 端口白名单（格式：`端口/协议 # 服务名`） |
| `/opt/auto-firewall/ip-whitelist.conf` | IP 白名单（格式：`IP/CIDR # 说明`） |
| `/opt/auto-firewall/ports.state` | 动态追踪端口状态 |
| `/opt/auto-firewall/logs/` | 日志目录 |

### 端口白名单示例

```
22/tcp       # SSH
443/tcp      # HTTPS
8080/tcp     # Web 服务
```

### IP 白名单示例

```
1.2.3.4      # 公司出口IP
10.0.0.0/8   # 内网段
```

白名单中的 IP 不会被 Fail2ban 自动封禁，也会同步写入 UFW allow 规则。

## Cron 定时任务

| 周期 | 任务 | 说明 |
|------|------|------|
| 每 5 分钟 | `port-check` | 检测端口变化，自动放行/回收 |
| 每 15 分钟 | `fail2ban-check` | 检测 Fail2ban 状态，同步 IP 白名单 |
| 每 1 小时 | `cleanup` | APT 缓存、旧内核、日志清理 |

## 技术栈

- **系统**: Debian 12 (bookworm) / Ubuntu 22.04+
- **防火墙**: UFW (Uncomplicated Firewall)
- **入侵防御**: Fail2ban (sshd jail + UFW action)
- **兼容**: Docker (iptables DOCKER-USER 链修复)
- **Web 服务**: Nginx（Fail2ban nginx-http-auth jail）

## 三重防线架构

```
互联网流量
    │
    ▼
┌─────────────────┐
│  UFW 防火墙      │  ← 第一道：端口级访问控制
│  (deny incoming) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Fail2ban       │  ← 第二道：入侵检测与自动封禁
│  (暴力破解防御)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Docker UFW修复  │  ← 第三道：防止容器绕过防火墙
│  (iptables规则)  │
└─────────────────┘
```

## 兼容性

- Debian GNU/Linux 12 (bookworm) ✅
- Ubuntu 22.04 LTS ✅
- Ubuntu 24.04 LTS ✅
- 其他 Debian 系发行版需 `/etc/debian_version` 存在

## 安全建议

1. 安装后立即将你的公网 IP 加入 `/opt/auto-firewall/ip-whitelist.conf`，防止 Fail2ban 误封
2. 定期执行 `sudo bash auto-firewall.sh status` 检查防火墙状态
3. 新增服务后，手动编辑 `/opt/auto-firewall/port-whitelist.conf` 添加端口白名单
4. 建议配合 SSH 密钥认证使用，禁用密码登录更安全

## License

MIT
