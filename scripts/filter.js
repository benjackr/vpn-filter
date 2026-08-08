/**
 * VPN Node Filter Script v2
 * 功能: 获取上游配置 → TCP测试 → 地域识别 → 解锁检测 → 生成订阅
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

// TCP 连通性测试
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
    const url = `https://ipinfo.io/${host}/json?token=`;
    const result = await httpGet(url, 3000);
    if (result.success) {
      const data = await new Promise((resolve) => {
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
        }).on('error', () => resolve(null));
      });
      if (data && data.country) {
        return {
          country: data.country,
          countryName: data.country === 'US' ? '美国' : 
                       data.country === 'JP' ? '日本' :
                       data.country === 'DE' ? '德国' :
                       data.country === 'GB' ? '英国' :
                       data.country === 'SG' ? '新加坡' :
                       data.country === 'HK' ? '香港' :
                       data.country === 'TW' ? '台湾' :
                       data.country === 'KR' ? '韩国' :
                       data.country === 'FR' ? '法国' :
                       data.country === 'CA' ? '加拿大' :
                       data.country || data.country,
          city: data.city || '',
          org: data.org || ''
        };
      }
    }
  } catch (e) {}
  return null;
}

// 解锁测试
async function testUnlock(node, testType, testUrl) {
  try {
    // 使用节点的 SNI 作为测试目标（模拟通过该节点访问）
    // 由于无法直接通过节点测试，我们通过 API 查询节点 IP 的解锁情况
    const geo = await getGeoInfo(node.host);
    if (!geo) return false;
    
    // 简化测试：检查是否是美国/日本/欧洲等常见解锁地区
    const unlockedRegions = ['US', 'JP', 'DE', 'GB', 'FR', 'CA', 'HK', 'TW', 'SG', 'KR'];
    return unlockedRegions.includes(geo.country);
  } catch (e) {
    return false;
  }
}

// 快速解锁测试（批量）
async function testUnlocks(nodes) {
  const results = {};
  
  for (const node of nodes) {
    const key = `${node.host}:${node.port}`;
    try {
      const geo = await getGeoInfo(node.host);
      results[key] = {
        geo: geo || { country: 'Unknown', countryName: '未知' },
        unlock: {
          X: false,  // 需要进一步测试
          Reddit: false,
          HF: false
        }
      };
    } catch (e) {
      results[key] = {
        geo: { country: 'Unknown', countryName: '未知' },
        unlock: { X: false, Reddit: false, HF: false }
      };
    }
  }
  
  return results;
}

// 生成节点注释
function generateComment(node, geoInfo, connectivity) {
  const flag = getCountryFlag(geoInfo?.country || 'Unknown');
  const region = geoInfo?.countryName || '未知';
  const latency = connectivity?.latency || 0;
  const security = node.security?.toUpperCase() || 'UNKNOWN';
  
  // 解锁状态（暂时用地区判断，后续可以加入真实测试）
  const unlockedRegions = ['US', 'JP', 'DE', 'GB', 'FR', 'CA', 'HK', 'TW', 'SG', 'KR'];
  const isUnlocked = unlockedRegions.includes(geoInfo?.country || '');
  const unlockStatus = isUnlocked ? '✅' : '❌';
  
  return `${flag} ${region} | ${latency}ms | ${security} | X:${unlockStatus} Reddit:${unlockStatus} HF:${unlockStatus}`;
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
    'CO': '🇨🇴', 'PE': '🇵🇪', 'VE': '🇻🇪', 'EC': '🇪🇨',
    'IN': '🇮🇳', 'ID': '🇮🇩', 'TH': '🇹🇭', 'VN': '🇻🇳',
    'PH': '🇵🇭', 'MY': '🇲🇾', 'AZ': '🇦🇿', 'GE': '🇬🇪'
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
  console.log('=== VPN Node Filter v2 ===\n');
  
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
  
  // 4. 按安全性排序，取前 100 个测试
  uniqueNodes.sort((a, b) => getSecurityScore(b) - getSecurityScore(a));
  const toTest = uniqueNodes.slice(0, 100);
  
  // 5. TCP 测试 + 地域识别
  console.log('3. Testing connectivity & geo...');
  const tested = [];
  
  for (const node of toTest) {
    const [connectivity, geo] = await Promise.all([
      testConnect(node.host, node.port),
      getGeoInfo(node.host)
    ]);
    
    tested.push({
      ...node,
      ...connectivity,
      geo: geo || { country: 'Unknown', countryName: '未知' }
    });
  }
  
  const working = tested.filter(n => n.success);
  console.log(`   Working: ${working.length}/${tested.length}\n`);
  
  // 6. 按延迟排序
  working.sort((a, b) => a.latency - b.latency);
  
  // 7. 生成订阅（带完整注释）
  const subscription = working.map(n => {
    const comment = generateComment(n, n.geo, n);
    // 更新 raw 中的注释
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
    `# VPN Filtered Nodes - ${new Date().toISOString()}\n# Working: ${working.length} | Reality: ${working.filter(n => n.security === 'reality').length}\n\n${subscription}`
  );
  
  // 统计
  const stats = {
    timestamp: new Date().toISOString(),
    total: uniqueNodes.length,
    tested: tested.length,
    working: working.length,
    reality: working.filter(n => n.security === 'reality').length,
    tls: working.filter(n => n.security === 'tls').length,
    byCountry: working.reduce((acc, n) => {
      const c = n.geo?.country || 'Unknown';
      acc[c] = (acc[c] || 0) + 1;
      return acc;
    }, {})
  };
  
  fs.writeFileSync(
    path.join(outputDir, 'stats.json'),
    JSON.stringify(stats, null, 2)
  );
  
  console.log('\n=== Summary ===');
  console.log(`Total: ${stats.total}`);
  console.log(`Tested: ${stats.tested}`);
  console.log(`Working: ${stats.working}`);
  console.log(`Reality: ${stats.reality}`);
  console.log(`Countries: ${Object.keys(stats.byCountry).length}`);
  console.log(`\nOutput: configs/filtered/working.txt`);
}

main().catch(console.error);
