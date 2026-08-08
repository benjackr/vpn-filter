# VPN Filter 部署指南

## 项目结构

```
vpn-filter/                  # GitHub 仓库（存储测试脚本和结果）
├── .github/workflows/
│   └── filter.yml          # GitHub Actions 定时任务
├── scripts/
│   └── filter.js           # Node.js 测试脚本
├── configs/
│   └── filtered/
│       ├── working.txt     # 生成的订阅（自动更新）
│       └── stats.json      # 统计数据

vpn-filter-worker/           # CF Worker（订阅代理）
├── src/
│   └── index.js            # Worker 代码
└── wrangler.toml           # 配置文件
```

---

## 部署步骤

### 第1步：创建 GitHub 仓库

```bash
# 1. 在 GitHub 创建新仓库
# 仓库名: vpn-filter
# 可见性: Public 或 Private

# 2. 初始化本地仓库
cd E:\Users\YY\Desktop\vpn-filter
git init
git add .
git commit -m "Initial commit"

# 3. 推送到 GitHub
git remote add origin https://github.com/benjackr/vpn-filter.git
git push -u origin main
```

### 第2步：部署 CF Worker

```bash
# 1. 进入 Worker 目录
cd E:\Users\YY\Desktop\vpn-filter-worker

# 2. 登录 CF（如果还没登录）
wrangler login

# 3. 部署 Worker
wrangler deploy
```

### 第3步：绑定域名

**方法 A: 使用 Workers 路由**

在 `wrangler.toml` 中添加：
```toml
routes = [
  { pattern = "vpn.guton.indevs.in/*", zone_name = "guton.indevs.in" }
]
```

**方法 B: 手动配置 CF Dashboard**

1. 登录 https://dash.cloudflare.com
2. 进入 Workers → 找到 `vpn-filter-worker`
3. 点击 "Triggers" → "Add Route"
4. 域名: `guton.indevs.in`
5. 路径: `vpn/*`
6. 保存

### 第4步：测试订阅

```bash
# 测试 CF Worker
curl https://vpn.guton.indevs.in

# 应该返回 VPN 订阅内容
```

---

## 使用说明

### 导入到客户端

**v2rayNG:**
1. 打开 v2rayNG
2. 点击订阅 → 添加订阅
3. 粘贴 URL: `https://vpn.guton.indevs.in`
4. 保存

**NekoBox:**
1. 设置 → 订阅管理
2. 添加 → 粘贴 URL

**Hiddify:**
1. 配置 → 添加订阅
2. 粘贴 URL

### 更新频率

- GitHub Actions 每 6 小时自动运行
- 手动触发: GitHub → Actions → Filter VPN Nodes → Run workflow

---

## 技术说明

### 安全性筛选

| 等级 | 协议 | 评分 |
|------|------|------|
| 🟢 HIGH | VLESS-Reality | 3分 |
| 🟡 MEDIUM | VLESS-TLS | 2分 |
| 🔴 LOW | 无加密 | 1分 |

### 测试结果

每次运行会测试前 50 个高安全节点，输出：
- `working.txt`: 可用节点订阅
- `stats.json`: 统计数据

---

## 故障排查

### GitHub Actions 失败

```bash
# 检查日志
# GitHub → Repositories → vpn-filter → Actions → Filter VPN Nodes

# 常见错误:
# 1. Node.js 版本问题 → 修改 workflow 中的 node-version
# 2. 网络超时 → 增加 timeout
# 3. 权限问题 → 检查 token
```

### CF Worker 404

```bash
# 检查路由配置
# CF Dashboard → Workers → vpn-filter-worker → Triggers

# 检查域名是否绑定
# CF Dashboard → Routers → 确认路由存在
```

### 订阅内容为空

```bash
# 检查 GitHub Actions 是否运行成功
# GitHub → Actions → 确认有成功的 workflow run

# 检查 GitHub Raw 是否可访问
curl https://raw.githubusercontent.com/benjackr/vpn-filter/main/configs/filtered/working.txt
```

---

## 安全提醒

⚠️ **使用免费 VPN 有风险：**
- 运营者可能监控流量
- 不要登录敏感账户
- 不要传输银行卡/密码
- 定期更换节点

✅ **建议：**
- 只用于访问被封网站
- 使用 Reality 协议节点
- 不要长期连同一个节点
