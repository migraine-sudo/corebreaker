# 安装 PoC 扩展到 Safari

Safari 不支持直接"加载已解压扩展"（不像 Chrome）。需要通过以下方式之一：

## 方法 1：使用 `xcrun safari-web-extension-converter`（推荐）

这是 Apple 官方提供的转换工具，将 Chrome 格式的扩展转为 Safari 可用的 Xcode 项目。

```bash
# 1. 确保安装了 Xcode 和命令行工具
xcode-select --install

# 2. 转换扩展为 Xcode 项目
cd poc/safari-dnr-csp-bypass
xcrun safari-web-extension-converter extension/ \
  --project-location ./xcode-project \
  --app-name "DNR CSP Bypass PoC" \
  --bundle-identifier com.poc.dnr-csp-bypass \
  --no-open

# 3. 打开生成的 Xcode 项目
open xcode-project/DNR\ CSP\ Bypass\ PoC/DNR\ CSP\ Bypass\ PoC.xcodeproj

# 4. 在 Xcode 中：
#    - 选择你的开发者签名（或 "Sign to Run Locally"）
#    - 点击 Run (⌘R)
#    - 这会编译并安装扩展到 Safari
```

## 方法 2：手动 Xcode 步骤

如果转换工具报错：

1. 打开 Xcode > File > New > Project
2. 选 macOS > Safari Extension App
3. 填写名称，语言选 Swift
4. 将 `extension/` 目录下的文件复制到生成的 Resources 目录中，替换默认文件
5. Run (⌘R)

## 启用扩展

无论哪种方法，编译运行后：

1. **Safari > 设置 > 高级** → 勾选"在菜单栏中显示开发菜单"
2. **菜单栏 > 开发** → 勾选"允许未签名的扩展"
3. **Safari > 设置 > 扩展** → 启用 "DNR CSP Bypass PoC"
4. 确认扩展只显示 "declarativeNetRequest" 权限（无其他权限）

## 验证安装成功

```bash
# 启动演示服务器
cd test-server
python3 demo_server.py

# 在 Safari 中访问
# https://localhost:8443/demo
```

- 如果页面显示红色 "ATTACK SUCCESS" → 扩展工作正常，漏洞存在
- 如果页面显示绿色 "✓ 脚本正常加载" → 扩展未生效或漏洞已修补

## 注意事项

- "允许未签名的扩展" 选项在每次 Safari 重启后会被重置，需要重新勾选
- 需要 macOS 系统（iOS/iPadOS 无法加载未签名扩展进行测试）
- 如果遇到签名问题，在 Xcode 中选择 "Sign to Run Locally" 而非开发者证书
