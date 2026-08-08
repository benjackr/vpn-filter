/**
 * VPN Node Filter Script
 * 功能: 获取上游配置 → TCP测试 → 排序去重 → 生成订阅
 */

const https = require('https');
const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');

// 上游配置源（精简版，12个文件）
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

// 解析 VLESS 节点
function parseVLESS(line) {
  try {
    const rest = line.slice(8); // 去掉 vless://
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
    const rest = line.slice(9); // 去掉 trojan://
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
function testConnect(host, port, timeout = 3000) {
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
  console.log('=== VPN Node Filter ===\n');
  
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
  
  // 3. 按安全性排序
  nodes.sort((a, b) => getSecurityScore(b) - getSecurityScore(a));
  
  // 4. 去重
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
  
  // 5. 测试前50个高安全节点
  console.log('3. Testing connectivity (top 50)...');
  const toTest = uniqueNodes.slice(0, 50);
  const tested = [];
  
  for (const node of toTest) {
    const result = await testConnect(node.host, node.port);
    tested.push({ ...node, ...result });
  }
  
  const working = tested.filter(n => n.success);
  console.log(`   Working: ${working.length}/${tested.length}\n`);
  
  // 6. 按延迟排序
  working.sort((a, b) => a.latency - b.latency);
  
  // 7. 生成订阅
  const subscription = working.map(n => n.raw).join('\n');
  
  // 8. 保存
  const outputDir = path.join(__dirname, '..', 'configs', 'filtered');
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  
  fs.writeFileSync(
    path.join(outputDir, 'working.txt'),
    `# VPN Filtered Nodes - ${new Date().toISOString()}\n# Working: ${working.length}\n# Total: ${uniqueNodes.length}\n\n${subscription}`
  );
  
  // 统计
  const stats = {
    timestamp: new Date().toISOString(),
    total: uniqueNodes.length,
    tested: tested.length,
    working: working.length,
    reality: working.filter(n => n.security === 'reality').length,
    tls: working.filter(n => n.security === 'tls').length
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
  console.log(`TLS: ${stats.tls}`);
  console.log(`\nOutput: configs/filtered/working.txt`);
}

main().catch(console.error);
