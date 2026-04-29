# Finding 021: Captured Surface Control SendWheel() 缺少 relative_x/y 范围验证

## 严重性: Low-Medium (需要 compromised renderer)

## 摘要

`CapturedSurfaceController::DoSendWheel()` 不验证 `relative_x` 和 `relative_y` 参数的范围。Mojom 定义明确要求 `[0, 1)` 范围，但 browser 端直接将值乘以视口大小生成坐标，无任何钳位或验证。Compromised renderer 可以在被捕获 surface 的任意坐标注入 scroll 事件。

## 受影响文件

- `content/browser/media/captured_surface_controller.cc:139-142`
- Mojom 定义: `third_party/blink/public/mojom/mediastream/media_stream.mojom:217-229`

## Bug 代码

```cpp
// captured_surface_controller.cc:139-142
const double x =
    std::floor(action->relative_x * captured_viewport_size.width());
const double y =
    std::floor(action->relative_y * captured_viewport_size.height());
```

注意 `wheel_delta_x/y` 在 line 148-155 有正确的钳位（`kMaxWheelDeltaMagnitude`），但 `x, y` 坐标没有。

## 影响

- Compromised renderer 可以发送 `relative_x = -10.0` 或 `100.0`
- 产生超出视口范围的合成 wheel 事件
- 可以在被捕获 tab 的任意位置注入 scroll 操作
- 影响有限（仅是 scroll 操作，不是点击）

## Renderer 端检查

```cpp
// capture_controller.cc:199-200
if (relative_x < 0.0 || relative_x >= 1.0 || relative_y < 0.0 ||
    relative_y >= 1.0) {
```

Renderer 有正确的范围检查。因此需要 compromised renderer。

## VRP 评估

- **严重性**: Low-Medium — 需要 compromised renderer + 已有 screen capture 权限
- **VRP 价值**: Low — renderer 检查覆盖了正常路径
