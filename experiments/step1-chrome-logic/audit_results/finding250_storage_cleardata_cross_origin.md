# Finding 250: Storage.clearDataForOrigin — 跨域存储删除无信任检查

## 日期: 2026-05-01

## 漏洞详情

### 位置
`content/browser/devtools/protocol/storage_handler.cc:644, 667`

### 问题
`Storage.clearDataForOrigin` 和 `Storage.clearDataForStorageKey` 无 `is_trusted_` 检查。

untrusted 扩展客户端可以清除**任意 origin** 的所有存储数据（cookie、localStorage、indexedDB、cache、service workers）。

### 关键点
- `origin` 参数接受任意 URL，不限于 host_permissions 范围
- 这是跨域破坏性操作
- Storage domain 在 `IsDomainAvailableToUntrustedClient` 白名单中

### 与 Finding 245 的关系
- 245: 通过子 session 的 MayAccessAllCookies 删除所有 cookie
- 250: 直接通过 Storage.clearDataForOrigin 删除任意 origin 的所有数据（更广泛）

### 影响
- 比 245 更强：不仅删 cookie，还删 localStorage、indexedDB、CacheStorage、SW 注册
- 不需要子 session trick
- 直接在父 session 就能对任意 origin 操作

### 待验证
- Storage.clearDataForOrigin 的 origin 参数是否真的不做 host_permissions 过滤
- 如果确认，这比 245 的影响更大

## 可利用性评估: HIGH（如果确认 origin 参数不过滤）
