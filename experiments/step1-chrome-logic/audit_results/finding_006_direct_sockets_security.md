# Finding 006: Direct Sockets API — TCPServerSocket 缺少 Private Network Access 检查 + Worker PP 缺失

## 严重性: Medium

## 摘要

Direct Sockets API（仅限 Isolated Web Apps / 桌面端）存在两个权限检查不一致问题：

1. **`OpenTCPServerSocket` 缺少 Private Network Access 检查**: 其兄弟方法 `OpenBoundUDPSocket`、
   `OpenTCPSocket`、`OpenConnectedUDPSocket` 都调用 `RequestPrivateNetworkAccessAndCreateSocket`，
   但 `OpenTCPServerSocket` 完全跳过此检查，直接在 network context 上创建 socket。

2. **SharedWorker / ServiceWorker 跳过多项 Permissions Policy 检查**:
   `kDirectSockets`、`kDirectSocketsPrivate`、`kMulticastInDirectSockets` PP 检查在
   Worker 创建路径中被 TODO 注释标记为"尚未实现"。

## 受影响组件

- `content/browser/direct_sockets/direct_sockets_service_impl.cc`
- Mojo 接口: `blink::mojom::DirectSocketsService`

## 漏洞详情

### Issue 1: OpenTCPServerSocket 缺少 Private Network Access 检查

**文件**: `direct_sockets_service_impl.cc:616-657`

| 方法 | Private Network Access 检查 | 状态 |
|------|---------------------------|------|
| `OpenBoundUDPSocket` (line 593) | `RequestPrivateNetworkAccessAndCreateSocket` ✓ | 安全 |
| `OpenTCPSocket` → `OnResolveCompleteForTCPSocket` (line 734) | `RequestPrivateNetworkAccessAndCreateSocket` ✓ | 安全 |
| `OpenConnectedUDPSocket` → `OnResolveCompleteForUDPSocket` (line 818) | `RequestPrivateNetworkAccessAndCreateSocket` ✓ | 安全 |
| **`OpenTCPServerSocket`** (line 616) | **无** ❌ | **缺失** |

TCP Server Socket **必然**绑定到本地地址（它是监听器），因此每次使用都是 private/loopback
网络访问。但代码跳过了 `kDirectSocketsPrivate` PP 和 `LOCAL_NETWORK`/`LOOPBACK_NETWORK`
权限检查。

```cpp
// line 616-657 (简化)
void DirectSocketsServiceImpl::OpenTCPServerSocket(
    blink::mojom::DirectTCPServerSocketOptionsPtr options,
    OpenTCPServerSocketCallback callback) {
  // ... 参数验证 ...
  if (!ValidateRequest(url::SchemeHostPort(url::kHttpScheme, ...), ...)) {
    return;  // 只检查 embedder delegate
  }
  // ← 没有 RequestPrivateNetworkAccessAndCreateSocket!
  // 直接创建 socket:
  auto tcp_server_socket = std::make_unique<network::TCPServerSocket>(...);
  // ...
}
```

对比 `OpenBoundUDPSocket`:
```cpp
// line 593
void DirectSocketsServiceImpl::OpenBoundUDPSocket(...) {
  // ...
  RequestPrivateNetworkAccessAndCreateSocket(
      {PermissionType::LOCAL_NETWORK, PermissionType::LOOPBACK_NETWORK},
      std::move(callback));  // ← 总是检查两种权限
}
```

### Issue 2: SharedWorker / ServiceWorker PP 检查缺失

**创建路径对比**:

| 创建方法 | `kDirectSockets` PP | `kDirectSocketsPrivate` PP | `kMulticast` PP |
|----------|--------------------|--------------------------|----|
| `CreateForFrame` (line 411) | ✓ | ✓ (line 251) | ✓ (line 167) |
| `CreateForDedicatedWorker` → `CreateForFrame` | ✓ (继承) | ✓ (继承) | ✓ (继承) |
| **`CreateForSharedWorker`** (line 452) | **❌ TODO** | **❌** | **❌ TODO (always true)** |
| **`CreateForServiceWorker`** (line 484) | **❌ TODO** | **❌** | **❌ TODO (always true)** |

`CreateForSharedWorker` (line 452-456):
```cpp
// TODO(crbug.com/393539884): Figure out appropriate checks wrt permissions.
```

`IsMulticastAllowed` (line 159-186) 对 SharedWorker/ServiceWorker 无条件返回 `true`:
```cpp
// TODO(crbug.com/393539884): Enforce permissions policy for workers.
return true;  // ← 对 worker 跳过所有 multicast PP 检查
```

## 攻击场景

### 场景 1: IWA TCP Server Socket 绕过 Private Network 权限

1. 一个 Isolated Web App 在 manifest 中没有声明 `direct-sockets-private` 权限
2. IWA 调用 `new TCPServerSocket({localAddress: "127.0.0.1", localPort: 8080})`
3. 由于缺少 Private Network Access 检查，socket 成功创建
4. IWA 监听本地端口，可以接受来自 localhost 的连接
5. 相同的 IWA 如果尝试 `new UDPSocket({localAddress: "127.0.0.1"})` 会被 `RequestPrivateNetworkAccessAndCreateSocket` 阻止

### 场景 2: Service Worker 绕过 PP 使用 Multicast

1. IWA Service Worker 使用 multicast 相关的 UDP socket 选项
2. 即使 IWA manifest 未声明 `direct-sockets-multicast` 权限
3. `IsMulticastAllowed` 对 Service Worker 返回 true
4. 攻击者控制的 IWA 可以加入 multicast 组、监听局域网流量

## 前提和限制

1. **仅限 IWA (Isolated Web Apps)**: Direct Sockets API 不可用于普通网页
2. **仅限桌面平台**: `!BUILDFLAG(IS_ANDROID)` 排除 Android
3. **IWA 分发受限**: IWA 需要通过 Chrome Web Store 或企业策略安装，攻击者难以分发恶意 IWA
4. **Chromium 团队已知**: 多处 TODO 注释引用 crbug.com/393539884

## VRP 可报告性分析

- **Issue 1 (TCP Server Socket)**: 可能是真正的遗漏（没有 TODO 注释），VRP 价值 Low-Medium
- **Issue 2 (Worker PP)**: 有 TODO 注释，团队已知，VRP 价值低
- **IWA 限制**: 攻击者需要先让受害者安装恶意 IWA，这大大降低了实际可利用性
- **预期评级**: Low（因为 IWA 的攻击门槛高）

## 建议修复

### TCP Server Socket

```cpp
void DirectSocketsServiceImpl::OpenTCPServerSocket(...) {
  // ... 现有验证 ...
  // 添加: 与 OpenBoundUDPSocket 一致的 Private Network Access 检查
  RequestPrivateNetworkAccessAndCreateSocket(
      {PermissionType::LOCAL_NETWORK, PermissionType::LOOPBACK_NETWORK},
      std::move(callback));
}
```

### Worker PP 检查

在 `CreateForSharedWorker` 和 `CreateForServiceWorker` 中添加
`kDirectSockets` PP 检查（需要解决 Worker 上下文中如何获取 PP 的问题）。

## 发现方法

通过系统性审计 Direct Sockets API 所有方法的权限检查一致性发现。
TCP Server Socket 的缺失是 Pattern 2（新 API 方法缺少已有权限检查）的又一实例。
