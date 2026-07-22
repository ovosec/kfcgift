# kfcgift 项目分析文档

## 一、项目概述

### 1.1 kfcgift 项目

这是一个基于 **Cloudflare Workers** 的代理/隧道系统，主入口文件为 `_worker.js`（约 6113 行）。该项目实现了完整的代理服务功能：

- **多协议代理**：支持 VLESS、Trojan、Shadowsocks 协议的代理转发
- **多传输层**：支持 WebSocket、gRPC、XHTTP（SplitHTTP）三种传输方式
- **管理面板**：提供 Web 管理界面，支持配置保存、日志查看、优选 IP 管理
- **订阅生成**：支持 Clash、Sing-box、Surge、Quantumult X、Loon 等客户端订阅格式
- **节点检测**：内建代理节点连通性检测功能（`admin/check` 端点）

### 1.2 scanner-js 子项目

`scanner-js` 是一个独立的 Node.js 扫描工具（`index.js`，约 532 行），其目的是**仿写 _worker.js 中的节点扫描功能**，在本地环境中快速检测 CF（Cloudflare）优选节点的连通性。

> **核心目标**：将 _worker.js 中嵌入在代理系统内的节点检测逻辑，抽取为独立的、可本地运行的扫描服务。

---

## 二、_worker.js 节点扫描功能分析

### 2.1 扫描入口：`admin/check` 端点

位于 _worker.js 第 137-204 行。当请求路径为 `admin/check` 时触发，需要管理员认证通过（Cookie 验证）。

### 2.2 支持的代理协议类型

代码中使用以下协议类型进行检测：

| 协议 | 说明 |
|------|------|
| `socks5` | SOCKS5 代理连接 |
| `http` | HTTP 代理连接 |
| `https` | HTTPS 代理连接（对 IP 主机名特殊处理） |
| `turn` | TURN 中继连接 |
| `sstp` | SSTP 协议连接 |

### 2.3 扫描三步流程

_worker.js 中的节点检测（`admin/check`）按以下三步执行：

#### 第一步：建立底层 TCP 连接

```javascript
// 第 152-160 行（核心逻辑提取）
tcpSocket = 代理协议 === 'socks5'
    ? await socks5Connect(检测主机, 检测端口, new Uint8Array(0), TCP连接, checkParsed)
    : 代理协议 === 'turn'
        ? await turnConnect(checkParsed, 检测主机, 检测端口, TCP连接)
        : 代理协议 === 'sstp'
            ? await sstpConnect(checkParsed, 检测主机, 检测端口, TCP连接)
            : (代理协议 === 'https' && isIPHostname(hostname)
                ? await httpsConnect(检测主机, 检测端口, new Uint8Array(0), TCP连接, checkParsed)
                : await httpConnect(检测主机, 检测端口, new Uint8Array(0), 代理协议 === 'https', TCP连接, checkParsed));
```

TCP 连接器由函数 `创建请求TCP连接器(request)` 生成，底层使用 Cloudflare Workers 的 `connect()` API。

#### 第二步：TLS 握手

```javascript
// 第 162 行
tlsSocket = new TlsClient(tcpSocket, { serverName: 检测主机, insecure: true });
await tlsSocket.handshake();
```

使用 Cloudflare Workers 的 `TlsClient` 进行 TLS 握手，`insecure: true` 表示跳过证书验证。

#### 第三步：HTTP Trace 验证

```javascript
// 第 164 行
await tlsSocket.write(encoder.encode(
    `GET /cdn-cgi/trace HTTP/1.1\r\nHost: ${检测主机}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`
));
```

发送 HTTP 请求到 Cloudflare 的 `/cdn-cgi/trace` 端点，然后解析响应中的关键字段：

```javascript
// 第 190-193 行（响应解析）
const ip = response.match(/(?:^|\n)ip=(.*)/)?.[1];
const loc = response.match(/(?:^|\n)loc=(.*)/)?.[1];
if (!ip || !loc) throw new Error('代理检测响应无效');
```

验证逻辑：
1. 检查 HTTP 状态码 200-299
2. 响应体包含 `ip=` 字段（表示 Cloudflare 出口 IP）
3. 响应体包含 `loc=` 字段（表示数据中心位置代码，如 `NRT`、`LAX`）

### 2.4 检测主机固定值

```javascript
const 检测主机 = 'cloudflare.com', 检测端口 = 443;
```

所有代理检测都连接到 `cloudflare.com:443`，通过不同的代理协议建立隧道后，再访问 `/cdn-cgi/trace` 验证代理是否正常工作。

### 2.5 IP 优选相关功能

_worker.js 中包含大量 IP 优选逻辑（订阅生成部分）：

- **`生成随机IP()`**：从 CIDR 段随机生成 IP 地址
- **`请求优选API()`**：调用外部优选 API 获取可用 IP 列表
- **CIDR 处理**：支持 `ip/prefix` 格式的网段解析和随机采样
- **自定义优选 IP**：支持通过 `admin/ADD.txt` 端点管理自定义 IP 列表

---

## 三、scanner-js/index.js 节点扫描功能分析

### 3.1 整体架构

scanner-js 是一个 Node.js HTTP 服务器，监听 `PORT=8080`（默认），提供 REST API 和静态前端界面。

### 3.2 核心 API 端点

| 端点 | 方法 | 功能 |
|------|------|------|
| `/` | GET | 返回静态前端页面 |
| `/scan` | POST | 核心扫描接口 |
| `/libraries` | GET | 列出可用 IP 库 |
| `/library?lib=xxx` | GET | 获取指定 IP 库内容 |
| `/health` | GET | 健康检查 |

### 3.3 扫描三步流程

scanner-js 精确仿写了 _worker.js 三步检测流程：

#### 第一步：TCP 连接探测（`connectTcp`）

```javascript
// index.js 第 288-311 行
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
```

- 使用 Node.js 内置 `net` 模块
- 记录连接延迟（`Date.now() - start`）
- 超时处理和错误捕获

#### 第二步：TLS 握手探测（`connectTls`）

```javascript
// index.js 第 313-331 行
function connectTls(host, port, timeout) {
    return new Promise((resolve) => {
        const start = Date.now();
        const socket = tls.connect({
            host, port, servername: host,
            rejectUnauthorized: false,  // ← 对应 _worker.js 的 insecure: true
            timeout
        });
        // ...
        socket.once('secureConnect', () => onResult(true, null, socket));
    });
}
```

- 使用 Node.js 内置 `tls` 模块
- `rejectUnauthorized: false` 对应 Worker 的 `insecure: true`
- `servername: host` 对应 Worker 的 `serverName: 检测主机`

#### 第三步：HTTP Trace 验证（`httpCheckTls`）

```javascript
// index.js 第 333-372 行
function httpCheckTls(host, port, timeout) {
    return new Promise((resolve) => {
        // ...
        socket.once('secureConnect', () => {
            socket.write(
                'GET /cdn-cgi/trace HTTP/1.1\r\n' +
                'Host: cloudflare.com\r\n' +
                'Connection: close\r\n' +
                'User-Agent: node-cf-scanner\r\n\r\n'
            );
        });
        socket.on('data', (chunk) => {
            responseData += chunk;
            const lower = responseData.toLowerCase();
            // 检测 ip= 和 loc= 字段
            if (lower.includes('ip=') && lower.includes('loc=')) {
                finish(true, null, responseData);
            }
        });
    });
}
```

- **完全一致的请求**：都是 `GET /cdn-cgi/trace`，Host 为 `cloudflare.com`
- **完全一致的验证逻辑**：检测 `ip=` 和 `loc=` 字段
- 增加了响应大小限制（16KB）防止异常数据

### 3.4 目标构建系统

scanner-js 提供三种扫描来源模式：

| 来源 | 说明 |
|------|------|
| `custom` | 手动输入 IP 列表 / CIDR |
| `cf` | 从 Cloudflare 官方 IP 段随机生成 |
| `library` | 从预置 IP 库加载（CF 官方、CM 优选、AS13335、AS209242） |

CIDR 展开逻辑：
```javascript
// index.js 第 168-175 行
function expandCidr(cidr, count = 16) {
    const range = cidrToRange(cidr);
    const result = new Set();
    for (let i = 0; i < count; i += 1) {
        result.add(randomIpFromRange(range));
    }
    return Array.from(result);
}
```

### 3.5 并发控制与结果处理

```javascript
// index.js 第 403-421 行
async function runTasks(targets, options) {
    const { concurrency } = options;
    const results = [];
    let index = 0;
    const next = async () => {
        while (index < targets.length) {
            const current = index;
            index += 1;
            const target = targets[current];
            const result = await checkTarget(target, options);
            results[current] = result;
        }
    };
    const workers = Array.from(
        { length: Math.min(concurrency, targets.length) }, next
    );
    await Promise.all(workers);
    return results;
}
```

- 使用 worker pool 模式控制并发数（默认 50，最大 500）
- 结果按延迟排序，可用节点排在前面

### 3.6 扫描结果结构

```json
{
    "count": 64,
    "totalScanned": 100,
    "successCount": 55,
    "failureCount": 45,
    "results": [
        {
            "host": "104.16.0.1",
            "port": 443,
            "ok": true,
            "latency": 150,
            "tls": true,
            "note": "trace ok",
            "httpInfo": "fl=...\nip=...\nloc=NRT\n..."
        }
    ]
}
```

---

## 四、两者对比分析

### 4.1 运行环境

| 维度 | _worker.js | scanner-js/index.js |
|------|-----------|---------------------|
| 运行平台 | Cloudflare Workers | Node.js (≥18) |
| 网络 API | `connect()` (CF 专用) | `net` / `tls` 模块 |
| TLS 实现 | `TlsClient` (CF 专用) | `tls.connect()` (Node.js) |
| HTTP 客户端 | 自写 TCP + TLS 组合 | 自写 TCP + TLS 组合 |
| 文件系统 | 无（KV 存储） | `fs` 模块 |
| 静态服务 | 无（Pages 部署） | 内置 HTTP 服务器 |

### 4.2 扫描目标

| 维度 | _worker.js | scanner-js/index.js |
|------|-----------|---------------------|
| 扫描复杂度 | 单节点代理检测 | 批量 IP:Port 连通性扫描 |
| 检测主机 | 固定 `cloudflare.com:443` | 用户指定的 IP 和端口 |
| 代理协议 | 5 种（socks5/http/https/turn/sstp） | 无（直连检测） |
| IP 来源 | 固定代理地址 | 多种 IP 库 + 自定义输入 |

### 4.3 核心检测流程对比

```
_worker.js admin/check:
  代理参数解析 → SOCKS5/HTTP/HTTPS/TURN/SSTP 连接 → TLS 握手 → /cdn-cgi/trace 验证

scanner-js /scan:
  目标构建（CIDR展开/随机IP）→ TCP 连接 → TLS 握手 → /cdn-cgi/trace 验证（可选HTTP Check）
```

### 4.4 三步检测映射表

| 步骤 | _worker.js | scanner-js | 一致性 |
|------|-----------|------------|--------|
| TCP 连接 | `socks5Connect/httpConnect/...` + `connect()` | `connectTcp()` (net.Socket) | ✅ 逻辑一致，API 不同 |
| TLS 握手 | `new TlsClient()` | `tls.connect()` | ✅ `insecure` = `rejectUnauthorized: false` |
| HTTP Trace | `GET /cdn-cgi/trace` 检测 `ip=`/`loc=` | `GET /cdn-cgi/trace` 检测 `ip=`/`loc=` | ✅ 完全一致 |

### 4.5 功能差异

| 功能 | _worker.js | scanner-js |
|------|-----------|------------|
| 代理协议检测 | ✅ 全部支持 | ❌ 未实现（直连扫描） |
| SOCKS5 认证 | ✅ 用户名/密码 | ❌ 不需要 |
| 批量 IP 扫描 | ❌ 需要外部优选 API | ✅ 内置并发扫描 |
| CIDR 展开 | ✅ 订阅生成中使用 | ✅ 扫描目标构建 |
| IP 库缓存 | ❌ 无本地文件系统 | ✅ `libs/` 目录缓存 |
| Web 管理界面 | ✅ Cloudflare Pages | ✅ 静态 HTML 前端 |
| 结果导出 | ✅ 订阅链接 | ✅ 文本文件下载 |
| gRPC/WS/XHTTP 传输 | ✅ 完整实现 | ❌ 不涉及 |

### 4.6 代码量对比

| 文件 | 行数 | 功能密度 |
|------|------|---------|
| _worker.js | 6113 行 | 完整代理系统 + 管理面板 + 订阅系统 |
| scanner-js/index.js | 532 行 | 纯扫描服务 |
| scanner-js/public/index.html | 348 行 | 扫描前端界面 |

---

## 五、scanner-js 对 _worker.js 扫描功能的仿写映射

### 5.1 仿写策略

scanner-js 采用了**核心逻辑提取 + 环境适配**的仿写策略：

1. **提取核心三步检测流程**：TCP → TLS → HTTP Trace
2. **适配运行环境**：将 CF Workers 专用 API 替换为 Node.js 等价实现
3. **简化代理层面**：去除代理协议检测（SOCKS5 等），专注于直连 IP:Port 节点检测
4. **增强批量能力**：添加 CIDR 展开、并发控制、IP 库管理等 _worker.js 中未完整实现的功能

### 5.2 关键映射关系

```
_worker.js                          →  scanner-js
──────────────────────────────────────────────────────────
connect()                           →  net.Socket.connect()
TlsClient(socket, {insecure:true})  →  tls.connect({rejectUnauthorized:false})
/cdn-cgi/trace 验证 (ip= & loc=)   →  /cdn-cgi/trace 验证 (ip= & loc=)
admin/check 单节点检测              →  POST /scan 批量检测
生成随机IP()                        →  expandCidr() + randomIpFromRange()
请求优选API()                       →  fetchLibraryText() (IP库下载)
```

### 5.3 已验证的一致性项

- [x] `/cdn-cgi/trace` 路径完全一致
- [x] Host 头均为 `cloudflare.com`
- [x] 验证字段均为 `ip=` 和 `loc=`
- [x] TLS 跳过证书验证（`insecure: true` ↔ `rejectUnauthorized: false`）
- [x] 连接超时机制
- [x] 延迟记录（`Date.now() - start`）

### 5.4 差异项

| 差异 | _worker.js | scanner-js | 影响 |
|------|-----------|------------|------|
| 代理协议 | 5 种代理协议支持 | 无代理，直连 TCP | scanner-js 定位为 CF 节点扫描，不需要代理 |
| TlsClient vs tls | CF 专用 `TlsClient` | Node.js `tls` 模块 | 功能等价，API 不同 |
| HTTP 响应解析 | 正则提取 `ip=`/`loc=` | `includes('ip=') && includes('loc=')` | scanner-js 更宽松但不影响结果 |
| 响应大小限制 | 64KB | 16KB | scanner-js 更保守 |
| `servername` | `cloudflare.com` | `host`（目标 IP） | 注意：这可能导致 TLS SNI 不匹配警告 |

### 5.5 已知问题

从 `scanner.err` 日志可以看到一个已知警告：

```
DEP0123: Setting the TLS ServerName to an IP address is not permitted by RFC 6066.
```

这是因为 scanner-js 在 TLS 连接时使用 IP 地址作为 `servername`，而 _worker.js 使用域名 `cloudflare.com`。这在实际使用中不会影响扫描结果（因为 `rejectUnauthorized: false`），但不符合 RFC 规范。

---

## 六、总结

### 6.1 仿写完成度

scanner-js 成功仿写了 _worker.js 的核心节点扫描逻辑：

1. ✅ **TCP 连通性检测** — 等价实现
2. ✅ **TLS 握手验证** — 等价实现（`insecure` 模式）
3. ✅ **HTTP Trace 验证** — 完全一致的请求和验证逻辑
4. ✅ **延迟记录** — 相同的计时方式
5. ✅ **超时机制** — 相同的超时处理

### 6.2 简化项

scanner-js 有意省略了以下功能，因为它们属于代理系统范畴而非节点扫描范畴：

- ❌ SOCKS5/HTTP/HTTPS/TURN/SSTP 代理连接
- ❌ gRPC/WebSocket/XHTTP 多路复用传输
- ❌ VLESS/Trojan/Shadowsocks 协议解析
- ❌ 用户认证和会话管理
- ❌ KV 存储和配置持久化

### 6.3 架构优势

scanner-js 相比 _worker.js 的扫描功能有以下增强：

1. **批量并发扫描**：支持最多 500 并发的高效批量检测
2. **多 IP 库支持**：内置 CF 官方、CM 优选、AS13335、AS209242 等 IP 库
3. **CIDR 展开**：支持从网段随机采样 IP
4. **结果排序**：按延迟排序，可用节点优先展示
5. **Web 前端**：提供直观的扫描配置和结果展示界面
6. **结果导出**：支持导出可用节点列表为文本文件
7. **本地缓存**：IP 库本地缓存避免重复下载