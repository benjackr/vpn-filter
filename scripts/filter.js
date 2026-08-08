/**
 * VPN Node Filter Script v3
 * 测试内容: 安全性 | 地域 | 速度 | 稳定性 | 解锁情况
 */

const https = require('https');
const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');

// 上游配置源
const SOURCE_URLS = [
  'https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/1.1.txt',
  'https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/2.1.txt',
  'https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/3.1.txt',
  'https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/10.1.txt',
  'https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/13.1.txt',
  'https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/17.1.txt',
  'https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/19.1.txt',
  'https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/20.1.txt',
  'https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/26.1.txt',
  'https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/27.txt',
  'https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/28.1.txt',
  'https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/29.txt',
];

// 解锁测试 URL
const UNLOCK_TESTS = {
  X: 'https://www.x.com',
  Reddit: 'https://www.reddit.com',
  HF: 'https://huggingface.co'
};

// 解析 VLESS 节点
function parseVLESS(line) {
  try {
    const rest = line.slice(8);
    let query = {};
    let urlPart = rest;
    
    if (rest.includes('?')) {
      const parts = rest.split('?');
      urlPart = parts[0];
      query = Object.fromEntries(new URLSearchParams(parts[1]));
    }
    
    let host, port = 443;
    if (urlPart.includes('@')) {
      const afterAt = urlPart.split('@')[1];
      const lastColon = afterAt.lastIndexOf(':');
      host = afterAt.slice(0, lastColon);
      port = parseInt(afterAt.slice(lastColon + 1)) || 443;
    } else {
      host = urlPart.split(':')[0];
    }
    
    return {
      protocol: 'VLESS',
      host,
      port,
      security: query['security'] || '',
      sni: query['sni'] || query['peer'] || '',
      fp: query['fp'] || '',
      flow: query['flow'] || '',
      raw: line
    };
  } catch (e) {
    return null;
  }
}

// 解析 Trojan 节点
function parseTrojan(line) {
  try {
    const rest = line.slice(9);
    let query = {};
    let urlPart = rest;
    
    if (rest.includes('?')) {
      const parts = rest.split('?');
      urlPart = parts[0];
      query = Object.fromEntries(new URLSearchParams(parts[1]));
    }
    
    let host, port = 443;
    if (urlPart.includes('@')) {
      const afterAt = urlPart.split('@')[1];
      const lastColon = afterAt.lastIndexOf(':');
      host = afterAt.slice(0, lastColon);
      port = parseInt(afterAt.slice(lastColon + 1)) || 443;
    } else {
      host = urlPart.split(':')[0];
    }
    
    return {
      protocol: 'Trojan',
      host,
      port,
      security: 'tls',
      sni: query['sni'] || '',
      fp: query['fp'] || '',
      flow: '',
      raw: line
    };
  } catch (e) {
    return null;
  }
}

// TCP 连通性测试（测速度）
function testConnect(host, port, timeout = 5000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const start = Date.now();
    
    socket.connect(port, host, () => {
      const latency = Date.now() - start;
      socket.destroy();
      resolve({ success: true, latency });
    });
    
    socket.setTimeout(timeout, () => {
      socket.destroy();
      resolve({ success: false, error: 'timeout' });
    });
    
    socket.on('error', (err) => {
      resolve({ success: false, error: err.message });
    });
  });
}

// HTTP 请求（用于解锁测试）
function httpGet(url, timeout = 5000) {
  return new Promise((resolve) => {
    const urlObj = new URL(url);
    const client = urlObj.protocol === 'https:' ? https : http;
    const start = Date.now();
    
    const req = client.get(url, { timeout }, (res) => {
      resolve({ 
        success: res.statusCode >= 200 && res.statusCode < 400,
        status: res.statusCode,
        latency: Date.now() - start
      });
    });
    
    req.on('error', (err) => {
      resolve({ success: false, error: err.message, latency: Date.now() - start });
    });
    
    req.setTimeout(timeout, () => {
      req.destroy();
      resolve({ success: false, error: 'timeout', latency: Date.now() - start });
    });
  });
}

// IP 地理信息获取
async function getGeoInfo(host) {
  try {
    const url = `https://ipinfo.io/${host}/json`;
    const data = await new Promise((resolve, reject) => {
      https.get(url, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            resolve(null);
          }
        });
      }).on('error', reject);
    });
    
    if (data && data.country) {
      const countryNames = {
        'US': '美国', 'JP': '日本', 'DE': '德国', 'GB': '英国',
        'FR': '法国', 'CA': '加拿大', 'HK': '香港', 'TW': '台湾',
        'SG': '新加坡', 'KR': '韩国', 'AU': '澳大利亚', 'NL': '荷兰',
        'SE': '瑞典', 'NO': '挪威', 'FI': '芬兰', 'DK': '丹麦',
        'CH': '瑞士', 'AT': '奥地利', 'BE': '比利时', 'IE': '爱尔兰',
        'IT': '意大利', 'ES': '西班牙', 'PT': '葡萄牙', 'PL': '波兰',
        'CZ': '捷克', 'HU': '匈牙利', 'RO': '罗马尼亚', 'BG': '保加利亚',
        'HR': '克罗地亚', 'SI': '斯洛文尼亚', 'SK': '斯洛伐克', 'LT': '立陶宛',
        'LV': '拉脱维亚', 'EE': '爱沙尼亚', 'MT': '马耳他', 'CY': '塞浦路斯',
        'BR': '巴西', 'MX': '墨西哥', 'AR': '阿根廷', 'CL': '智利',
        'IN': '印度', 'ID': '印度尼西亚', 'TH': '泰国', 'VN': '越南',
        'PH': '菲律宾', 'MY': '马来西亚', 'AZ': '阿塞拜疆', 'GE': '格鲁吉亚',
        'RU': '俄罗斯', 'TR': '土耳其', 'UA': '乌克兰', 'KZ': '哈萨克斯坦'
      };
      
      return {
        country: data.country,
        countryName: countryNames[data.country] || data.country,
        city: data.city || '',
        org: data.org || ''
      };
    }
  } catch (e) {}
  return null;
}

// 稳定性测试（连续3次连接）
async function testStability(host, port, attempts = 3) {
  const results = [];
  for (let i = 0; i < attempts; i++) {
    const result = await testConnect(host, port);
    results.push(result);
    if (i < attempts - 1) await new Promise(r => setTimeout(r, 100));
  }
  
  const successCount = results.filter(r => r.success).length;
  const avgLatency = results.reduce((sum, r) => sum + (r.latency || 0), 0) / attempts;
  
  return {
    success: successCount === attempts,
    successRate: `${successCount}/${attempts}`,
    avgLatency: Math.round(avgLatency),
    details: results
  };
}

// 解锁测试
async function testUnlocks(node) {
  const results = {};
  
  for (const [name, url] of Object.entries(UNLOCK_TESTS)) {
    const result = await httpGet(url);
    results[name] = result.success;
  }
  
  return results;
}

// 生成节点注释
function generateComment(node, geoInfo, stability, unlocks) {
  const flag = getCountryFlag(geoInfo?.country || 'Unknown');
  const region = geoInfo?.countryName || '未知';
  const avgLatency = stability?.avgLatency || 0;
  const security = node.security?.toUpperCase() || 'UNKNOWN';
  
  // 速度评级
  let speedRating = '慢';
  if (avgLatency < 50) speedRating = '快';
  else if (avgLatency < 150) speedRating = '中';
  else if (avgLatency > 300) speedRating = '极慢';
  
  // 稳定性评级
  let stabilityRating = '中';
  if (stability?.successRate === '3/3') stabilityRating = '稳';
  else if (stability?.successRate === '2/3') stabilityRating = '中';
  else stabilityRating = '差';
  
  // 解锁状态
  const xStatus = unlocks?.X ? '✅' : '❌';
  const redditStatus = unlocks?.Reddit ? '✅' : '❌';
  const hfStatus = unlocks?.HF ? '✅' : '❌';
  
  return `${flag} ${region} | ${avgLatency}ms | ${speedRating} | ${stabilityRating} | ${security} | X:${xStatus} Reddit:${redditStatus} HF:${hfStatus}`;
}

// 国家代码转旗帜
function getCountryFlag(countryCode) {
  const flags = {
    'US': '🇺🇸', 'JP': '🇯🇵', 'DE': '🇩🇪', 'GB': '🇬🇧',
    'FR': '🇫🇷', 'CA': '🇨🇦', 'HK': '🇭🇰', 'TW': '🇹🇼',
    'SG': '🇸🇬', 'KR': '🇰🇷', 'AU': '🇦🇺', 'NL': '🇳🇱',
    'SE': '🇸🇪', 'NO': '🇳🇴', 'FI': '🇫🇮', 'DK': '🇩🇰',
    'CH': '🇨🇭', 'AT': '🇦🇹', 'BE': '🇧🇪', 'IE': '🇮🇪',
    'IT': '🇮🇹', 'ES': '🇪🇸', 'PT': '🇵🇹', 'PL': '🇵🇱',
    'CZ': '🇨🇿', 'HU': '🇭🇺', 'RO': '🇷🇴', 'BG': '🇧🇬',
    'HR': '🇭🇷', 'SI': '🇸🇮', 'SK': '🇸🇰', 'LT': '🇱🇹',
    'LV': '🇱🇻', 'EE': '🇪🇪', 'MT': '🇲🇹', 'CY': '🇨🇾',
    'BR': '🇧🇷', 'MX': '🇲🇽', 'AR': '🇦🇷', 'CL': '🇨🇱',
    'IN': '🇮🇳', 'ID': '🇮🇩', 'TH': '🇹🇭', 'VN': '🇻🇳',
    'PH': '🇵🇭', 'MY': '🇲🇾', 'AZ': '🇦🇿', 'GE': '🇬🇪',
    'RU': '🇷🇺', 'TR': '🇹🇷', 'UA': '🇺🇦', 'KZ': '🇰🇿'
  };
  return flags[countryCode] || '🏳️';
}

// 获取配置
async function fetchConfigs() {
  const allLines = [];
  
  for (const url of SOURCE_URLS) {
    try {
      const text = await new Promise((resolve, reject) => {
        https.get(url, { timeout: 10000 }, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => resolve(data));
        }).on('error', reject);
      });
      
      for (const line of text.split('\n')) {
        const trimmed = line.trim();
        if (trimmed && (trimmed.startsWith('vless://') || trimmed.startsWith('trojan://'))) {
          allLines.push(trimmed);
        }
      }
    } catch (e) {
      console.error(`Failed to fetch ${url}: ${e.message}`);
    }
  }
  
  return allLines;
}

// 安全性评分
function getSecurityScore(node) {
  const security = (node.security || '').toLowerCase();
  if (security === 'reality') return 3;
  if (security === 'tls') return 2;
  return 1;
}

// 主函数
async function main() {
  console.log('=== VPN Node Filter v3 ===');
  console.log('测试: 安全性 | 地域 | 速度 | 稳定性 | 解锁情况\n');
  
  // 1. 获取配置
  console.log('1. Fetching configs...');
  const allLines = await fetchConfigs();
  console.log(`   Got ${allLines.length} lines\n`);
  
  // 2. 解析节点
  console.log('2. Parsing nodes...');
  const nodes = [];
  for (const line of allLines) {
    let node = null;
    if (line.startsWith('vless://')) {
      node = parseVLESS(line);
    } else if (line.startsWith('trojan://')) {
      node = parseTrojan(line);
    }
    if (node) {
      nodes.push(node);
    }
  }
  console.log(`   Parsed ${nodes.length} valid nodes\n`);
  
  // 3. 去重
  const uniqueNodes = [];
  const seen = new Set();
  for (const node of nodes) {
    const key = `${node.host}:${node.port}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueNodes.push(node);
    }
  }
  console.log(`   Unique: ${uniqueNodes.length}\n`);
  
  // 4. 按安全性排序，取前 50 个深度测试
  uniqueNodes.sort((a, b) => getSecurityScore(b) - getSecurityScore(a));
  const toTest = uniqueNodes.slice(0, 50);
  
  // 5. 深度测试
  console.log('3. Running deep tests (security + geo + speed + stability + unlocks)...');
  const tested = [];
  
  for (let i = 0; i < toTest.length; i++) {
    const node = toTest[i];
    process.stdout.write(`   [${i+1}/${toTest.length}] Testing ${node.host}:${node.port}... `);
    
    try {
      // 并行测试：连接 + 地域 + 解锁
      const [connectivity, geo, unlocks] = await Promise.all([
        testStability(node.host, node.port),
        getGeoInfo(node.host),
        testUnlocks(node)
      ]);
      
      tested.push({
        ...node,
        stability: connectivity,
        geo: geo || { country: 'Unknown', countryName: '未知' },
        unlocks
      });
      
      const status = connectivity.success ? '✅' : '❌';
      console.log(`${status} ${connectivity.avgLatency}ms ${geo?.countryName || '未知'}`);
    } catch (e) {
      console.log(`❌ Error: ${e.message}`);
    }
  }
  
  const working = tested.filter(n => n.stability.success);
  console.log(`\n=== Results ===`);
  console.log(`Total tested: ${tested.length}`);
  console.log(`Working: ${working.length}`);
  console.log(`Reality: ${working.filter(n => n.security === 'reality').length}`);
  console.log(`Countries: ${new Set(working.map(n => n.geo?.country)).size}`);
  console.log(`X unlocked: ${working.filter(n => n.unlocks?.X).length}`);
  console.log(`Reddit unlocked: ${working.filter(n => n.unlocks?.Reddit).length}`);
  console.log(`HF unlocked: ${working.filter(n => n.unlocks?.HF).length}`);
  
  // 6. 按稳定性 + 解锁状态排序
  working.sort((a, b) => {
    // 优先解锁的
    const aUnlock = (a.unlocks?.X ? 1 : 0) + (a.unlocks?.Reddit ? 1 : 0) + (a.unlocks?.HF ? 1 : 0);
    const bUnlock = (b.unlocks?.X ? 1 : 0) + (b.unlocks?.Reddit ? 1 : 0) + (b.unlocks?.HF ? 1 : 0);
    if (bUnlock !== aUnlock) return bUnlock - aUnlock;
    // 然后按延迟
    return a.stability.avgLatency - b.stability.avgLatency;
  });
  
  // 7. 生成订阅
  const subscription = working.map(n => {
    const comment = generateComment(n, n.geo, n.stability, n.unlocks);
    const hashIndex = n.raw.indexOf('#');
    if (hashIndex >= 0) {
      return n.raw.slice(0, hashIndex + 1) + comment;
    }
    return n.raw + '#' + comment;
  }).join('\n');
  
  // 8. 保存
  const outputDir = path.join(__dirname, '..', 'configs', 'filtered');
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  
  fs.writeFileSync(
    path.join(outputDir, 'working.txt'),
    `# VPN Filtered Nodes - ${new Date().toISOString()}\n` +
    `# Working: ${working.length} | Reality: ${working.filter(n => n.security === 'reality').length}\n` +
    `# Test: GitHub Actions (US) | ${tested.length} tested | ${working.length} working\n\n${subscription}`
  );
  
  // 统计
  const stats = {
    timestamp: new Date().toISOString(),
    total: uniqueNodes.length,
    tested: tested.length,
    working: working.length,
    reality: working.filter(n => n.security === 'reality').length,
    byCountry: working.reduce((acc, n) => {
      const c = n.geo?.country || 'Unknown';
      acc[c] = (acc[c] || 0) + 1;
      return acc;
    }, {}),
    unlocked: {
      X: working.filter(n => n.unlocks?.X).length,
      Reddit: working.filter(n => n.unlocks?.Reddit).length,
      HF: working.filter(n => n.unlocks?.HF).length
    }
  };
  
  fs.writeFileSync(
    path.join(outputDir, 'stats.json'),
    JSON.stringify(stats, null, 2)
  );
  
  console.log(`\nOutput: configs/filtered/working.txt`);
}

main().catch(console.error);
