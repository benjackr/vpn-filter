# GitHub Actions - VPN Node Filter

This workflow filters VPN nodes from multiple sources and generates a working subscription.

## Schedule

- Runs every 6 hours
- Can be manually triggered

## Output

- `configs/filtered/working.txt` - Working nodes subscription
- `configs/filtered/stats.json` - Statistics

## How It Works

1. Fetch configs from 12 upstream sources
2. Parse VLESS/Trojan nodes
3. Test TCP connectivity (top 50 nodes)
4. Sort by security level + latency
5. Generate subscription file
