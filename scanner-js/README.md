# CF 优选节点扫描服务

这是一个纯 JavaScript 实现的 CF 优选节点扫描服务，基于 Node.js 内置 `net` 和 `tls` 模块。

## 功能

- 支持导入自定义 IP / CIDR 列表
- 支持从 CF IP 段生成随机节点候选
- 支持并发扫描、超时配置、TLS 探测
- 支持简单的 HTTP `/scan` API
- 提供静态前端界面用于输入、扫描和查看结果

## 启动

```bash
cd scanner-js
npm install
npm start
```

访问 `http://localhost:8080` 进入扫描界面。

## API

### POST /scan

请求体示例：

```json
{
  "source": "cf",
  "isp": "cmcc",
  "targets": "104.16.0.0/20\n104.17.0.0/20",
  "defaultPort": 443,
  "sampleSize": 64,
  "concurrency": 80,
  "timeout": 3000,
  "tls": true,
  "httpCheck": false
}
```

返回结果：

```json
{
  "count": 64,
  "results": [
    { "host": "104.16.0.1", "port": 443, "ok": true, "latency": 150, "tls": true, "note": "tls connected" }
  ]
}
```

### GET /health

返回服务健康状态。
