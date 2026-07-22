const http = require('http');
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const { ProxyAgent } = require('undici');

const PORT = process.env.PORT || 8080;
const PUBLIC_DIR = path.join(__dirname, 'public');
const DEFAULT_LIBRARY_PROXY = 'http://127.0.0.1:10808';

function normalizeProxyUrl(value) {
  if (!value) return null;
  try {
    return new URL(value).toString();
  } catch {
    if (/^[\w.-]+:\d+$/.test(value)) {
      return `http://${value}`;
    }
    return null;
  }
}

const LIBRARY_PROXY = normalizeProxyUrl(process.env.LIBRARY_PROXY || process.env.HTTPS_PROXY || process.env.HTTP_PROXY || DEFAULT_LIBRARY_PROXY);
const LIBRARY_PROXY_AGENT = LIBRARY_PROXY ? new ProxyAgent(LIBRARY_PROXY) : null;

const LIB_CACHE_DIR = path.join(__dirname, 'libs');
try { fs.mkdirSync(LIB_CACHE_DIR, { recursive: true }); } catch (e) { /* ignore */ }

const CF_IPV4_URL = 'https://www.cloudflare.com/ips-v4';
const CF_IPV6_URL = 'https://www.cloudflare.com/ips-v6';
const DEFAULT_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
const DEFAULT_TIMEOUT = 3000;

// colo 三字代码 → 国家/城市
const COLO_MAP = {
  LAX: { country: 'US', name: 'Los Angeles' },
  SFO: { country: 'US', name: 'San Francisco' },
  SJC: { country: 'US', name: 'San Jose' },
  SEA: { country: 'US', name: 'Seattle' },
  DEN: { country: 'US', name: 'Denver' },
  DFW: { country: 'US', name: 'Dallas' },
  ORD: { country: 'US', name: 'Chicago' },
  IAD: { country: 'US', name: 'Ashburn' },
  ATL: { country: 'US', name: 'Atlanta' },
  MIA: { country: 'US', name: 'Miami' },
  EWR: { country: 'US', name: 'Newark' },
  BOS: { country: 'US', name: 'Boston' },
  AMS: { country: 'NL', name: 'Amsterdam' },
  LHR: { country: 'GB', name: 'London' },
  FRA: { country: 'DE', name: 'Frankfurt' },
  CDG: { country: 'FR', name: 'Paris' },
  SIN: { country: 'SG', name: 'Singapore' },
  NRT: { country: 'JP', name: 'Tokyo' },
  KIX: { country: 'JP', name: 'Osaka' },
  HKG: { country: 'HK', name: 'Hong Kong' },
  TPE: { country: 'TW', name: 'Taipei' },
  ICN: { country: 'KR', name: 'Seoul' },
  BOM: { country: 'IN', name: 'Mumbai' },
  MAA: { country: 'IN', name: 'Chennai' },
  SYD: { country: 'AU', name: 'Sydney' },
  MEL: { country: 'AU', name: 'Melbourne' },
  GRU: { country: 'BR', name: 'Sao Paulo' },
  MAD: { country: 'ES', name: 'Madrid' },
  MXP: { country: 'IT', name: 'Milan' },
  ARN: { country: 'SE', name: 'Stockholm' },
  WAW: { country: 'PL', name: 'Warsaw' },
  DME: { country: 'RU', name: 'Moscow' },
  JNB: { country: 'ZA', name: 'Johannesburg' },
  DXB: { country: 'AE', name: 'Dubai' },
  MCT: { country: 'OM', name: 'Muscat' },
  DEL: { country: 'IN', name: 'Delhi' },
  BLR: { country: 'IN', name: 'Bangalore' },
};

const COUNTRY_MAP = {
  US: '美国', NL: '荷兰', GB: '英国', DE: '德国', FR: '法国',
  SG: '新加坡', JP: '日本', HK: '香港', TW: '台湾', KR: '韩国',
  IN: '印度', AU: '澳大利亚', BR: '巴西', ES: '西班牙', IT: '意大利',
  SE: '瑞典', PL: '波兰', RU: '俄罗斯', ZA: '南非', AE: '阿联酋', OM: '阿曼',
};

function coloInfo(colo) {
  const c = COLO_MAP[colo?.toUpperCase()];
  return c ? { countryCode: c.country, country: COUNTRY_MAP[c.country] || c.country, city: c.name } : null;
}

const LIBRARY_SOURCES = {
  cf_official: { name: 'CF 官方列表 v4', url: CF_IPV4_URL },
  cm_preferred: { name: 'CM优选库v4', url: 'https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt' },
  as13335: { name: 'AS13335优选库v4', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/13335/ipv4-aggregated.txt' },
  as209242: { name: 'AS209242优选库v4', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/209242/ipv4-aggregated.txt' }
};

// ======================== 代理协议检测功能 (仿 _worker.js admin/check) ========================

function parseProxyAddress(address, defaultPort = 1080) {
  if (!address) throw new Error('empty address');
  let addr = String(address).trim();
  addr = addr.replace(/^(socks5|http|https|turn|sstp):\/\//i, '');
  addr = addr.split('#')[0].trim();

  const atIndex = addr.lastIndexOf('@');
  let authPart = '';
  let hostPart = addr;
  if (atIndex !== -1) {
    authPart = addr.slice(0, atIndex);
    hostPart = addr.slice(atIndex + 1);
  }

  let username = null;
  let password = null;
  if (authPart && !authPart.includes(':')) {
    try {
      const decoded = Buffer.from(authPart, 'base64').toString('utf8');
      if (decoded.includes(':')) {
        const [u, p] = decoded.split(':');
        username = u || null;
        password = p || null;
      }
    } catch (_) { }
  }
  if (!username && authPart) {
    const [u, ...rest] = authPart.split(':');
    username = u || null;
    password = rest.join(':') || null;
  }

  let hostname = hostPart;
  let port = defaultPort;
  if (hostPart.includes(']:')) {
    const match = hostPart.match(/^\[(.+)\]:(\d+)$/);
    if (match) {
      hostname = `[${match[1]}]`;
      port = parseInt(match[2], 10);
    }
  } else if (hostPart.startsWith('[')) {
    hostname = hostPart;
  } else {
    const colonIdx = hostPart.lastIndexOf(':');
    if (colonIdx > -1) {
      const maybePort = parseInt(hostPart.slice(colonIdx + 1), 10);
      if (!isNaN(maybePort) && maybePort > 0 && maybePort <= 65535) {
        hostname = hostPart.slice(0, colonIdx);
        port = maybePort;
      }
    }
  }
  if (isNaN(port) || port < 1 || port > 65535) throw new Error('invalid port');
  return { username, password, hostname, port };
}

const PROXY_DEFAULT_PORTS = {
  socks5: 1080,
  http: 80,
  https: 443,
  turn: 3478,
  sstp: 443,
};

function socks5Handshake(host, port, proxy) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let handled = false;

    const finish = (err, s) => {
      if (handled) return;
      handled = true;
      if (err) {
        try { socket.destroy(); } catch (_) { }
        reject(err);
      } else {
        resolve(s);
      }
    };

    socket.setTimeout(10000, () => finish(new Error('socks5_timeout')));
    socket.once('error', (err) => finish(err));

    socket.connect(proxy.port, proxy.hostname, () => {
      const hasAuth = !!(proxy.username && proxy.password);
      const authMethods = hasAuth
        ? Buffer.from([0x05, 0x02, 0x00, 0x02])
        : Buffer.from([0x05, 0x01, 0x00]);
      socket.write(authMethods);

      socket.once('data', (data) => {
        if (data[0] !== 0x05) return finish(new Error('socks5_invalid_version'));
        const selectedMethod = data[1];

        if (selectedMethod === 0x02) {
          if (!hasAuth) return finish(new Error('socks5_auth_required'));
          const uname = Buffer.from(proxy.username, 'utf8');
          const pwd = Buffer.from(proxy.password, 'utf8');
          const authPacket = Buffer.alloc(3 + uname.length + pwd.length);
          authPacket[0] = 0x01;
          authPacket[1] = uname.length;
          uname.copy(authPacket, 2);
          authPacket[2 + uname.length] = pwd.length;
          pwd.copy(authPacket, 3 + uname.length);

          socket.write(authPacket);
          socket.once('data', (authResp) => {
            if (authResp[0] !== 0x01 || authResp[1] !== 0x00) {
              return finish(new Error('socks5_auth_failed'));
            }
            sendConnectRequest();
          });
        } else if (selectedMethod === 0x00) {
          sendConnectRequest();
        } else {
          finish(new Error(`socks5_unsupported_method:0x${selectedMethod.toString(16)}`));
        }

        function sendConnectRequest() {
          let req;
          const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
          if (ipv4Regex.test(host)) {
            const ipParts = host.split('.').map(n => parseInt(n, 10));
            req = Buffer.concat([
              Buffer.from([0x05, 0x01, 0x00, 0x01]),
              Buffer.from(ipParts),
              Buffer.from([(port >> 8) & 0xff, port & 0xff])
            ]);
          } else {
            const domainBuf = Buffer.from(host, 'utf8');
            req = Buffer.concat([
              Buffer.from([0x05, 0x01, 0x00, 0x03]),
              Buffer.from([domainBuf.length]),
              domainBuf,
              Buffer.from([(port >> 8) & 0xff, port & 0xff])
            ]);
          }
          socket.write(req);

          socket.once('data', (resp) => {
            if (resp[0] !== 0x05) return finish(new Error('socks5_invalid_response'));
            if (resp[1] !== 0x00) {
              const errors = {
                0x01: 'general_failure', 0x02: 'connection_not_allowed',
                0x03: 'network_unreachable', 0x04: 'host_unreachable',
                0x05: 'connection_refused', 0x06: 'ttl_expired',
                0x07: 'command_not_supported', 0x08: 'address_not_supported'
              };
              return finish(new Error(`socks5_${errors[resp[1]] || `error_0x${resp[1].toString(16)}`}`));
            }
            return finish(null, socket);
          });
        }
      });
    });
  });
}

function httpProxyConnect(host, port, proxy) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let handled = false;

    const finish = (err, s) => {
      if (handled) return;
      handled = true;
      if (err) {
        try { socket.destroy(); } catch (_) { }
        reject(err);
      } else {
        resolve(s);
      }
    };

    socket.setTimeout(10000, () => finish(new Error('http_proxy_timeout')));
    socket.once('error', (err) => finish(err));

    socket.connect(proxy.port, proxy.hostname, () => {
      const authHeader = (proxy.username && proxy.password)
        ? `Proxy-Authorization: Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString('base64')}\r\n`
        : '';

      const connectReq = [
        `CONNECT ${host}:${port} HTTP/1.1`,
        `Host: ${host}:${port}`,
        authHeader.replace(/\r\n$/, ''),
        'Connection: keep-alive',
        '',
        ''
      ].join('\r\n');
      socket.write(connectReq);

      let buffer = '';
      socket.on('data', (data) => {
        buffer += data.toString();
        const headerEnd = buffer.indexOf('\r\n\r\n');
        if (headerEnd === -1) {
          if (buffer.length > 16384) finish(new Error('http_proxy_response_too_large'));
          return;
        }
        const header = buffer.substring(0, headerEnd);
        const statusMatch = header.match(/^HTTP\/\S+\s+(\d+)/);
        if (!statusMatch) return finish(new Error('http_proxy_invalid_response'));
        const statusCode = parseInt(statusMatch[1], 10);
        if (statusCode !== 200) return finish(new Error(`http_proxy_status_${statusCode}`));
        socket.removeAllListeners('data');
        finish(null, socket);
      });
    });
  });
}

function proxyCheck(proxyType, proxyStr, timeout = 10000) {
  return new Promise(async (resolve) => {
    const start = Date.now();
    let tlsSocket = null;
    try {
      const defaultPort = PROXY_DEFAULT_PORTS[proxyType] || 1080;
      const parsed = parseProxyAddress(proxyStr, defaultPort);

      const checkHost = 'cloudflare.com';
      const checkPort = 443;
      let rawSocket;

      if (proxyType === 'socks5') {
        rawSocket = await socks5Handshake(checkHost, checkPort, parsed);
      } else if (proxyType === 'http' || proxyType === 'https') {
        rawSocket = await httpProxyConnect(checkHost, checkPort, parsed);
      } else {
        return resolve({
          ok: false,
          error: `unsupported_proxy_type:${proxyType}`,
          proxy: `${proxyType}://${proxyStr}`
        });
      }

      tlsSocket = tls.connect({
        socket: rawSocket,
        servername: checkHost,
        rejectUnauthorized: false,
        timeout,
      });

      await new Promise((res, rej) => {
        const onErr = (e) => rej(e);
        const onTimeout = () => rej(new Error('tls_timeout'));
        tlsSocket.once('error', onErr);
        tlsSocket.once('secureConnect', () => {
          tlsSocket.removeListener('error', onErr);
          tlsSocket.removeListener('timeout', onTimeout);
          res();
        });
        tlsSocket.setTimeout(timeout, onTimeout);
      });

      const traceResult = await new Promise((res, rej) => {
        let responseData = '';
        let resolved = false;
        const onData = (chunk) => {
          responseData += chunk.toString();
          if (responseData.length > 65536) {
            if (!resolved) { resolved = true; rej(new Error('trace_too_large')); }
            return;
          }
          if (responseData.includes('ip=') && responseData.includes('loc=')) {
            if (!resolved) { resolved = true; res(responseData); }
          }
        };
        const onEnd = () => {
          if (!resolved) {
            resolved = true;
            rej(new Error('trace_invalid: missing ip= or loc='));
          }
        };
        const onErr = (e) => {
          if (!resolved) { resolved = true; rej(e); }
        };
        tlsSocket.on('data', onData);
        tlsSocket.once('end', onEnd);
        tlsSocket.once('error', onErr);

        tlsSocket.write(
          `GET /cdn-cgi/trace HTTP/1.1\r\nHost: ${checkHost}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`
        );
      });

      const ipMatch = traceResult.match(/(?:^|\n)ip=(.*)/);
      const locMatch = traceResult.match(/(?:^|\n)loc=(.*)/);
      const ip = ipMatch ? ipMatch[1].trim() : null;
      const loc = locMatch ? locMatch[1].trim() : null;

      const latency = Date.now() - start;
      try { tlsSocket.destroy(); } catch (_) { }

      if (!ip || !loc) {
        return resolve({
          ok: false,
          error: 'trace_no_ip_or_loc',
          proxy: `${proxyType}://${proxyStr}`,
          latency
        });
      }

      return resolve({
        ok: true,
        proxy: `${proxyType}://${proxyStr}`,
        ip,
        loc,
        latency
      });
    } catch (err) {
      const latency = Date.now() - start;
      try { tlsSocket?.destroy(); } catch (_) { }
      resolve({
        ok: false,
        error: err.message,
        proxy: `${proxyType}://${proxyStr}`,
        latency
      });
    }
  });
}

// ======================== 代理协议检测功能结束 ========================

async function fetchLibraryText(libId) {
  const config = LIBRARY_SOURCES[libId];
  if (!config) throw new Error('未知的 IP 库');
  const cacheFile = path.join(LIB_CACHE_DIR, `${libId}.txt`);
  try {
    if (fs.existsSync(cacheFile)) {
      const cached = fs.readFileSync(cacheFile, 'utf8');
      if (cached && cached.trim()) {
        console.log(`loadLibraryFromCache ${libId}`);
        return cached;
      }
    }
  } catch (e) {
    console.warn('cache read error', e.message);
  }

  const urlObj = new URL(config.url);
  urlObj.searchParams.set('_t', String(Date.now()));

  let fetchedText = '';
  if (LIBRARY_PROXY_AGENT) {
    try {
      console.log(`fetchLibraryText using proxy ${LIBRARY_PROXY} for ${urlObj.toString()}`);
      const response = await fetch(urlObj.toString(), { dispatcher: LIBRARY_PROXY_AGENT });
      if (response.ok) fetchedText = await response.text();
      else console.warn(`代理获取 ${config.name} 返回状态 ${response.status}`);
    } catch (err) {
      console.warn(`通过代理获取 ${config.name} 失败，回退到直连：`, err.message);
    }
  }

  if (!fetchedText) {
    try {
      console.log(`fetchLibraryText direct fetch for ${urlObj.toString()}`);
      const directResponse = await fetch(urlObj.toString());
      if (directResponse.ok) fetchedText = await directResponse.text();
      else throw new Error(`直接获取 ${config.name} 失败，状态：${directResponse.status}`);
    } catch (err) {
      console.error('fetchLibraryText direct fetch error', err.message);
      throw new Error(`无法加载 ${config.name}`);
    }
  }

  try {
    fs.writeFileSync(cacheFile, fetchedText, 'utf8');
    console.log(`cached library ${libId} -> ${cacheFile}`);
  } catch (e) {
    console.warn('cache write error', e.message);
  }
  return fetchedText;
}

function sendJson(res, data, status = 200) {
  const body = JSON.stringify(data, null, 2);
  res.writeHead(status, {
    'Content-Type': 'application/json;charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

function sendHtml(res, html) {
  res.writeHead(200, { 'Content-Type': 'text/html;charset=utf-8' });
  res.end(html);
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function normalizeLine(line) {
  return line.trim().replace(/\r|\n/g, '');
}

function parseIpPort(item, defaultPort = 443) {
  const trimmed = normalizeLine(item);
  if (!trimmed) return null;
  if (/^[0-9.]+(:\d+)?$/.test(trimmed)) {
    const [ip, port] = trimmed.split(':');
    return { host: ip, port: port ? Number(port) : defaultPort, explicitPort: !!port };
  }
  if (/^[0-9.]+\/[0-9]+$/.test(trimmed)) {
    return { cidr: trimmed };
  }
  return null;
}

function cidrToRange(cidr) {
  const [ip, prefix] = cidr.split('/');
  const parts = ip.split('.').map(Number);
  const ipInt = parts.reduce((acc, part) => (acc << 8) + part, 0) >>> 0;
  const mask = prefix === '0' ? 0 : (0xffffffff << (32 - Number(prefix))) >>> 0;
  const start = ipInt & mask;
  const size = 2 ** (32 - Number(prefix));
  return { start, size };
}

function intToIp(value) {
  return [
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff
  ].join('.');
}

function randomIpFromRange(range) {
  const offset = Math.floor(Math.random() * Math.max(range.size - 2, 1));
  return intToIp(range.start + offset + 1);
}

function expandCidr(cidr, count = 16) {
  const range = cidrToRange(cidr);
  const result = new Set();
  for (let i = 0; i < count; i += 1) {
    result.add(randomIpFromRange(range));
  }
  return Array.from(result);
}

function pickRandomPort(ports) {
  return ports[Math.floor(Math.random() * ports.length)];
}

function parseTargetText(text, defaultPort = 443) {
  const items = text.split(/\r?\n/).map(normalizeLine).filter(Boolean);
  const parsed = [];
  for (const item of items) {
    const target = parseIpPort(item, defaultPort);
    if (!target) continue;
    if (target.cidr) {
      parsed.push(target);
    } else {
      parsed.push({ host: target.host, port: target.port, explicitPort: target.explicitPort === true });
    }
  }
  return parsed;
}

async function fetchWithProxyFallback(url) {
  try {
    const directResponse = await fetch(url);
    if (directResponse.ok) return await directResponse.text();
    console.warn(`直接获取 ${url} 失败，状态 ${directResponse.status}，尝试代理`);
  } catch (err) {
    console.warn(`直接获取 ${url} 失败，准备使用代理：`, err.message);
  }

  if (!LIBRARY_PROXY_AGENT) {
    console.error('没有可用的库下载代理');
    throw new Error('代理不可用');
  }

  const proxyResponse = await fetch(url, { dispatcher: LIBRARY_PROXY_AGENT });
  if (!proxyResponse.ok) throw new Error(`代理获取 ${url} 失败：${proxyResponse.status}`);
  return await proxyResponse.text();
}

async function fetchCidrs(isp = 'cf') {
  const source = CF_IPV4_URL;
  try {
    const text = await fetchWithProxyFallback(source);
    const lines = text.split(/\r?\n/).map(normalizeLine).filter(Boolean);
    return lines.filter(line => /^[0-9.]+\/[0-9]+$/.test(line));
  } catch (err) {
    console.error('fetchCidrs error', err);
    return [];
  }
}

async function buildTargets(options) {
  const { source = 'custom', input = '', ports = [443], sampleSize = 64, perCidrCount = 1, isp = 'cf', randomPorts = false } = options;
  const targets = [];
  const scanPorts = ports.length ? ports : DEFAULT_PORTS;
  const shouldRandomize = randomPorts || ports.length === 0;
  const portMultiplier = shouldRandomize ? 1 : scanPorts.length;
  const SAFETY_MAX = 50000;

  let numCidrs = 0;
  let cfCidrs = [];
  if (source === 'cf') {
    cfCidrs = await fetchCidrs(isp);
    numCidrs += cfCidrs.length;
  }
  if (input) {
    const preParsed = parseTargetText(input, scanPorts[0]);
    numCidrs += preParsed.filter(item => item.cidr).length;
  }
  const autoLimit = numCidrs * perCidrCount * portMultiplier;
  const effectiveLimit = Math.min(Math.max(sampleSize, autoLimit || sampleSize), SAFETY_MAX);

  if (source === 'cf') {
    for (const cidr of cfCidrs) {
      if (targets.length >= effectiveLimit) break;
      const remaining = effectiveLimit - targets.length;
      const count = Math.min(perCidrCount, remaining);
      if (count <= 0) break;
      const ips = expandCidr(cidr, Math.max(1, Math.min(count, 4096)));
      for (const host of ips) {
        if (targets.length >= effectiveLimit) break;
        if (shouldRandomize) {
          targets.push({ host, port: Number(pickRandomPort(scanPorts)) });
        } else {
          for (const p of scanPorts) {
            if (targets.length >= effectiveLimit) break;
            targets.push({ host, port: Number(p) });
          }
        }
      }
    }
  }
  if (input) {
    const parsedItems = parseTargetText(input, scanPorts[0]);
    for (const item of parsedItems) {
      if (targets.length >= effectiveLimit) break;
      if (item.cidr) {
        const remaining = effectiveLimit - targets.length;
        const count = Math.min(perCidrCount, remaining);
        if (count <= 0) break;
        const ips = expandCidr(item.cidr, Math.max(1, Math.min(count, 4096)));
        for (const host of ips) {
          if (targets.length >= effectiveLimit) break;
          if (shouldRandomize) {
            targets.push({ host, port: Number(pickRandomPort(scanPorts)) });
          } else {
            for (const p of scanPorts) {
              if (targets.length >= effectiveLimit) break;
              targets.push({ host, port: Number(p) });
            }
          }
        }
      } else {
        if (item.explicitPort) {
          targets.push({ host: item.host, port: item.port });
        } else if (shouldRandomize) {
          targets.push({ host: item.host, port: Number(pickRandomPort(scanPorts)) });
        } else {
          for (const p of scanPorts) {
            if (targets.length >= effectiveLimit) break;
            targets.push({ host: item.host, port: Number(p) });
          }
        }
      }
    }
  }
  return targets.slice(0, effectiveLimit);
}

function connectTcp(host, port, timeout) {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = new net.Socket();
    let handled = false;

    const onResult = (ok, error, socketObj) => {
      if (handled) return;
      handled = true;
      const latency = Date.now() - start;
      if (socketObj) socketObj.destroy();
      resolve({ ok, error, latency });
    };

    socket.setTimeout(timeout, () => onResult(false, 'connect_timeout', socket));
    socket.once('error', (err) => onResult(false, err.message, socket));
    socket.once('connect', () => onResult(true, null, socket));
    socket.connect(port, host);
  });
}

async function checkTarget(target, options) {
  const { tls: useTls, timeout } = options;
  const result = { host: target.host, port: target.port, ok: false, latency: null, tls: !!useTls, note: null, httpInfo: null };

  if (useTls) {
    // 单连接：TLS 握手 + trace 验证 colo= 确认为 CF 边缘
    return new Promise((resolve) => {
      const start = Date.now();
      const socket = tls.connect({ host: target.host, port: target.port, servername: 'cloudflare.com', rejectUnauthorized: false, timeout });
      let handled = false;
      let responseData = '';

      const finish = () => {
        if (handled) return;
        handled = true;
        result.latency = Date.now() - start;
        try { socket.destroy(); } catch (_) { }

        if (responseData) {
          result.httpInfo = responseData;
          const lower = responseData.toLowerCase();
          const coloMatch = responseData.match(/(?:^|\n)colo=(\S+)/);
          // 必须有 ip= 和 colo= 才是真正的 CF 边缘节点
          if (lower.includes('ip=') && lower.includes('colo=')) {
            result.ok = true;
            result.loc = coloMatch ? coloMatch[1].trim() : null;
            result.note = 'cf edge ok';
          } else {
            result.ok = false;
            result.note = 'no cf trace';
          }
        } else {
          result.ok = false;
          result.note = 'no trace response';
        }
        resolve(result);
      };

      socket.once('error', (err) => {
        result.ok = false;
        result.note = err.message;
        result.latency = Date.now() - start;
        handled = true;
        try { socket.destroy(); } catch (_) { }
        resolve(result);
      });

      socket.once('secureConnect', () => {
        socket.setEncoding('utf8');
        socket.write('GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: close\r\nUser-Agent: node-cf-scanner\r\n\r\n');

        socket.on('data', (chunk) => {
          responseData += chunk;
          if (responseData.length > 16384) finish();
          if (responseData.toLowerCase().includes('colo=')) finish();
        });
        socket.once('end', finish);

        const traceTimer = setTimeout(() => { if (!handled) finish(); }, Math.min(timeout, 4000));
        socket.once('close', () => clearTimeout(traceTimer));
      });

      socket.setTimeout(timeout, () => {
        if (!handled) {
          result.note = result.note || 'tls_timeout';
          result.latency = Date.now() - start;
          handled = true;
          try { socket.destroy(); } catch (_) { }
          resolve(result);
        }
      });
    });
  } else {
    try {
      const tcpRes = await connectTcp(target.host, target.port, timeout);
      result.ok = tcpRes.ok;
      result.latency = tcpRes.latency;
      result.note = tcpRes.error || 'tcp connected';
    } catch (err) {
      result.ok = false;
      result.note = err.message;
    }
  }
  return result;
}

function serveStatic(req, res) {
  const filePath = req.url === '/' ? path.join(PUBLIC_DIR, 'index.html') : path.join(PUBLIC_DIR, req.url);
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      return res.end('Not Found');
    }
    const ext = path.extname(filePath).toLowerCase();
    const types = {
      '.html': 'text/html;charset=utf-8',
      '.js': 'application/javascript;charset=utf-8',
      '.css': 'text/css;charset=utf-8'
    };
    res.writeHead(200, { 'Content-Type': types[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const { method } = req;
    const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
    const pathname = parsedUrl.pathname;
    console.log('REQ', method, pathname);

    if (method === 'GET' && (pathname === '/' || pathname.startsWith('/public') || pathname.endsWith('.js') || pathname.endsWith('.css'))) {
      return serveStatic(req, res);
    }
    if (method === 'GET' && pathname === '/libraries') {
      return sendJson(res, Object.entries(LIBRARY_SOURCES).map(([id, lib]) => ({ id, name: lib.name })));
    }
    if (method === 'GET' && pathname === '/library') {
      const libId = parsedUrl.searchParams.get('lib');
      if (!libId || !LIBRARY_SOURCES[libId]) return sendJson(res, { error: '未知的 IP 库' }, 400);
      const content = await fetchLibraryText(libId);
      return sendJson(res, { id: libId, name: LIBRARY_SOURCES[libId].name, content });
    }
    if (method === 'POST' && pathname === '/scan') {
      const body = await parseBody(req);
      const parsePorts = (v) => {
        if (v === undefined || v === null) return [];
        if (Array.isArray(v)) return v.map(x => Number(x)).filter(n => Number.isInteger(n) && n > 0 && n <= 65535);
        if (typeof v === 'number') return Number.isInteger(v) && v > 0 && v <= 65535 ? [v] : [];
        if (typeof v === 'string') {
          const trimmed = v.trim();
          if (!trimmed) return [];
          return trimmed.split(',').map(s => Number(s.trim())).filter(n => Number.isInteger(n) && n > 0 && n <= 65535);
        }
        return [];
      };

      const requestPorts = parsePorts(body.ports || body.defaultPort || '');
      let input = body.targets || '';
      const library = body.library || '';

      if (!input.trim() && library) {
        input = await fetchLibraryText(library);
      }
      const source = (!input.trim() && !library) ? 'cf' : 'custom';

      const options = {
        source,
        input,
        ports: requestPorts.length ? requestPorts : DEFAULT_PORTS,
        randomPorts: requestPorts.length === 0,
        sampleSize: Math.max(1, Math.min(Number(body.sampleSize || 64), 50000)),
        perCidrCount: Math.max(1, Math.min(Number(body.perCidrCount || 1), 128)),
        isp: 'cf',
        library,
        concurrency: Math.max(1, Math.min(Number(body.concurrency || 50), 500)),
        timeout: Math.max(500, Math.min(Number(body.timeout || DEFAULT_TIMEOUT), 15000)),
        tls: body.tls !== false,
        httpCheck: body.httpCheck === true
      };
      const targets = await buildTargets(options);
      if (!targets.length) return sendJson(res, { error: '没有可扫描的目标' }, 400);

      // SSE 流式扫描响应
      res.writeHead(200, {
        'Content-Type': 'text/event-stream;charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Accel-Buffering': 'no',
        'Connection': 'keep-alive'
      });

      const sendSSE = (data) => {
        res.write(`data: ${JSON.stringify(data)}\n\n`);
      };

      sendSSE({ type: 'start', totalTargets: targets.length });

      const { concurrency, timeout, tls } = options;
      const results = new Array(targets.length);
      let completed = 0;
      let index = 0;

      const worker = async () => {
        while (index < targets.length) {
          const current = index;
          index += 1;
          const target = targets[current];
          const result = await checkTarget(target, { tls, timeout });
          results[current] = result;
          completed += 1;
          sendSSE({ type: 'progress', current: completed, total: targets.length, index: current, result });
        }
      };

      const workers = Array.from({ length: Math.min(concurrency, targets.length) }, worker);
      await Promise.all(workers);

      const successes = results.filter(r => r && r.ok);
      const rankedResults = results.slice().sort((a, b) => {
        if (!a || !b) return 0;
        if (a.ok !== b.ok) return a.ok ? -1 : 1;
        return (a.latency || 9999) - (b.latency || 9999);
      });

      sendSSE({
        type: 'done',
        summary: {
          count: successes.length,
          totalScanned: results.length,
          totalTargets: targets.length,
          requestedTargets: Number(options.sampleSize || targets.length),
          successCount: successes.length,
          failureCount: results.length - successes.length,
        },
        results: rankedResults
      });
      res.end();
      return;
    }
    if (method === 'POST' && pathname === '/proxy-check') {
      const body = await parseBody(req);
      const proxyType = (body.proxyType || body.type || '').toLowerCase();
      const proxyStr = body.proxyStr || body.proxy || body.address || '';
      const timeout = Math.max(500, Math.min(Number(body.timeout || 10000), 30000));

      if (!proxyType || !proxyStr) {
        return sendJson(res, { error: '缺少 proxyType 或 proxyStr/address 参数' }, 400);
      }
      if (!['socks5', 'http', 'https'].includes(proxyType)) {
        return sendJson(res, { error: `不支持的代理类型: ${proxyType}，支持: socks5, http, https` }, 400);
      }

      const result = await proxyCheck(proxyType, proxyStr, timeout);
      return sendJson(res, result);
    }
    if (method === 'GET' && pathname === '/health') {
      return sendJson(res, { status: 'ok' });
    }
    if (method === 'POST' && pathname === '/speedtest') {
      const body = await parseBody(req);
      const host = body.host;
      if (!host) return sendJson(res, { error: '缺少 host' }, 400);
      // speed.cloudflare.com 只监听 443，测速统一用 443
      const ST_PORT = 443;
      const start = Date.now();
      let downloaded = 0;
      try {
        const socket = tls.connect({ host, port: ST_PORT, servername: 'speed.cloudflare.com', rejectUnauthorized: false, timeout: 15000 });
        await new Promise((resolve, reject) => {
          socket.once('error', reject);
          socket.once('secureConnect', () => {
            socket.write('GET /__down?bytes=10000000 HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\nUser-Agent: node-cf-scanner\r\n\r\n');
            socket.once('data', (chunk) => {
              const s = chunk.toString();
              const idx = s.indexOf('\\r\\n\\r\\n');
              if (idx >= 0) downloaded += s.length - idx - 4;
            });
            socket.on('data', (chunk) => {
              downloaded += chunk.length;
              if (downloaded >= 5000000 || Date.now() - start > 12000) {
                try { socket.destroy(); } catch (_) { }
              }
            });
            socket.once('end', resolve);
            socket.once('close', resolve);
            setTimeout(() => { try { socket.destroy(); } catch (_) { } resolve(); }, 15000);
          });
        });
        const elapsed = (Date.now() - start) / 1000;
        const mbps = downloaded > 0 ? (downloaded * 8 / elapsed / 1e6).toFixed(1) : '0';
        sendJson(res, { ok: true, host, speed: Number(mbps), downloaded });
      } catch (err) {
        sendJson(res, { ok: false, host, error: err.message });
      }
      return;
    }
    res.writeHead(404);
    res.end('Not Found');
  } catch (err) {
    console.error(err);
    sendJson(res, { error: err.message }, 500);
  }
});

server.listen(PORT, () => {
  console.log(`CF 优选节点扫描服务已启动: http://localhost:${PORT}`);
  console.log(`API 端点:`);
  console.log(`  POST /scan          - CF 节点批量扫描`);
  console.log(`  POST /proxy-check   - 代理协议检测 (socks5/http/https)`);
  console.log(`  GET  /health        - 健康检查`);
});