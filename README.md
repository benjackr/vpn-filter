# VPN Filter

自动筛选高质量 VPN 节点的 GitHub Action。

## 功能

1. 从 12 个上游配置源获取节点
2. 解析 VLESS/Trojan 协议
3. TCP 连通性测试
4. 按安全性 + 延迟排序
5. 生成可用节点订阅

## 安全等级

- 🟢 HIGH: VLESS-Reality (DPI 检测率 <1%)
- 🟡 MEDIUM: VLESS-TLS
- 🔴 LOW: 无加密

## 输出

- `configs/filtered/working.txt` - 可用节点订阅
- `configs/filtered/stats.json` - 统计数据

## 运行频率

- 每 6 小时自动运行
- 支持手动触发
