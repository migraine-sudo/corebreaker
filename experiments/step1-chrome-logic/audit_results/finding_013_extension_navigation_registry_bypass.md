# Finding 013: ExtensionNavigationRegistry::CanRedirect 逻辑 Bug — 跨扩展资源访问绕过

## 严重性: Medium-High

## 摘要

`ExtensionNavigationRegistry::CanRedirect()` 中存在一个逻辑 bug：无论 extension_id 是否匹配目标扩展，函数都返回 `true`。这使得任何拥有 `webRequest` 权限的扩展可以通过 redirect 访问其他扩展的非 web-accessible 资源，绕过 MV3 的 `web_accessible_resources` 安全限制。

## 受影响文件

- `extensions/browser/extension_navigation_registry.cc:85-89`
- 调用点: `extensions/browser/extension_navigation_throttle.cc:340-344`

## 漏洞详情

### Bug 代码

```cpp
// extension_navigation_registry.cc:66-90
bool ExtensionNavigationRegistry::CanRedirect(int64_t navigation_id,
                                              const GURL& gurl,
                                              const Extension& extension) {
  std::optional<Metadata> extension_redirect_recorded =
      GetAndErase(navigation_id);

  if (!extension_redirect_recorded.has_value()) {
    return false;
  }

  auto metadata = extension_redirect_recorded.value();
  if (metadata.gurl != gurl) {
    return false;
  }

  if (metadata.extension_id == extension.id()) {
    return true;
  }

  return true;  // ← BUG: 即使 extension_id 不匹配也返回 true
}
```

第 85-87 行的 `if` 语句是**死代码**：无论条件是否为真，函数都返回 `true`。

### 安全影响路径

```
ExtensionNavigationThrottle::WillStartRequest()
  → 检查 !is_accessible (资源不是 web accessible)
  → 调用 CanRedirect()
  → 如果 CanRedirect() 返回 false → 阻止请求
  → 如果 CanRedirect() 返回 true → 允许请求
  
由于 CanRedirect() 总是返回 true（当有 redirect record 时），
安全检查被绕过。
```

### 攻击场景

1. 恶意扩展 A（拥有 `webRequest` 权限）和目标扩展 B（有敏感的非 web-accessible 资源，如私钥、配置文件等）同时安装在用户浏览器中

2. 用户访问一个页面，扩展 A 使用 `chrome.webRequest.onBeforeRequest` 拦截导航并 redirect 到 `chrome-extension://<B-id>/secret-resource.html`

3. `RecordExtensionRedirect()` 记录了这次 redirect，包含扩展 A 的 ID

4. `ExtensionNavigationThrottle` 检查目标资源是否 web accessible → 不是

5. 调用 `CanRedirect(navigation_id, url, *target_extension_B)`
   - `metadata.extension_id` = A 的 ID
   - `extension.id()` = B 的 ID
   - 不匹配，但仍返回 `true`

6. 导航被允许 → 扩展 A 成功访问了扩展 B 的私有资源

## 正确的修复

```cpp
if (metadata.extension_id == extension.id()) {
    return true;
}

return false;  // ← 应该返回 false
```

或者按照 TODO 所说，改为检查 recorded extension 是否有对目标资源的 WAR 访问权限。

## 前提条件

- 需要安装一个恶意扩展（拥有 `webRequest` 权限）
- 目标扩展必须已安装
- 不能从普通网页直接利用

## VRP 可报告性

- **严重性**: Medium-High — 跨扩展安全边界绕过
- **已知性**: 有 TODO (`crbug.com/40060076`)，但 TODO 描述的是"验证 WAR 访问"，不是"修复返回值 bug"。实际的逻辑错误（return true 而非 false）看起来是无意的
- **VRP 价值**: Medium — 扩展隔离是 Chrome 安全模型的重要部分
- **代码年龄**: 文件 copyright 2025，是较新的代码

## 发现方法

通过 sub-agent 对 extensions/browser/ 下的 Extension URL handling 和 navigation throttle 进行系统性审计发现。
