# CoreBreaker — 核心组件漏洞挖掘系统

> 专注挖掘支撑 Chrome/Android/iOS/macOS 的核心组件漏洞——不限于C库，覆盖GPU栈、ML推理、媒体管线、协议解析等全部高赏金攻击面。一个上游漏洞可同时提交多家下游VRP。

## 一、定位

CoreBreaker 的目标不仅是传统C基础库，而是**所有被大厂产品深度嵌入的核心组件**——包括 GPU 着色器编译器、ML 推理引擎、媒体编解码器、协议栈等。这些组件的漏洞可以向 Google VRP、Apple Security Bounty、Microsoft Bug Bounty、Mozilla Bug Bounty 同时提交。

### 为什么不只做C库

基于 Chrome 361个CVE（2025.03–2026.04）和 Apple iOS 151个CVE（2025.01–2025.05）的实际公告数据分析：

**Chrome 漏洞分布：**
- 内存安全 56.2%，占赏金 **77.2%**（$986,000）
- 逻辑漏洞 39.9%，占赏金 **18.5%**（$237,000）
- 内存安全单价均值 $18,604，逻辑漏洞单价均值 $3,338（**5.6倍差距**）

**Apple 漏洞分布：**
- 内存安全 **30.7%**
- 输入验证 22.1%、逻辑/状态 19.3%、权限/访问控制 14.3%
- 非内存安全漏洞合计 **~70%**

**Chrome 赏金最高的组件（实际数据）：**

| 组件 | 赏金总额 | 均价 | 最高单笔 | 主要漏洞类型 |
|------|---------|------|---------|-------------|
| V8 | $430,000 | $28,667 | $55,000 | 类型混淆 |
| **WebML** | **$205,000** | **$41,000** | $43,000 | 堆溢出/整数溢出 |
| **ANGLE** | **$123,000** | **$61,500** | **$90,000** | 堆溢出 |
| ServiceWorker | $43,000 | $43,000 | $43,000 | UAF |
| WebGPU | $35,000 | $17,500 | $25,000 | 堆溢出 |
| Dawn | $15,000 | $15,000 | $15,000 | UAF |
| Mojo | $30,000 | $30,000 | $30,000 | 逻辑漏洞 |

ANGLE 单笔 $90,000 是 Chrome VRP 最高赏金。WebML 均价 $41,000 超过 V8 以外所有组件。GPU 栈（ANGLE+Dawn+WebGPU+Skia）合计 $208,000。这些都是开源可 fuzz 的目标。

**Apple CVE 最多的组件：**

| 组件 | CVE数 | 内存安全占比 |
|------|-------|------------|
| WebKit | 20 (13.2%) | 50% |
| AirPlay | 14 (9.3%) | 57% |
| Kernel | 8 (5.3%) | 混合 |
| CoreMedia | 7 (4.6%) | **71%** (含ITW零日) |
| CoreAudio | 5 (3.3%) | 输入验证为主 |

CoreMedia 71% 内存安全，含一个 ITW 零日 (CVE-2025-24085)。AirPlay 14个CVE、57%内存安全，网络可达。

与 FuzzMind 其他项目的关系：

| 项目 | 目标 | 方法 |
|------|------|------|
| Mantis | Android APK Java层 | LLM静态审计 |
| Ouroboros | JSC/V8 JS引擎 | LLM源码审计 + Fuzzilli |
| Arachne | Android闭源ARM64 .so | 覆盖率引导fuzzing |
| Chimera | AI Agent框架 | LLM并行审计 |
| **CoreBreaker** | **核心组件(C库+GPU栈+ML引擎+媒体+协议)** | **LLM驱动harness工程 + 覆盖率引导fuzzing** |

CoreBreaker 不替代其他项目——各系统并行运行：
- Ouroboros 继续跑 V8 Maglev（Apple/Chrome VRP）
- Arachne 继续跑 Dolby/PowerVR（Google VRP，闭源ARM64）
- CoreBreaker 覆盖所有**开源**高赏金核心组件

## 二、核心差异化：为什么不直接用 OSS-Fuzz

这些库全部已在 OSS-Fuzz 中，但 OSS-Fuzz 的覆盖率远非100%：

| 库 | OSS-Fuzz覆盖率 | 主要盲区 |
|----|---------------|---------|
| libxml2 | ~65% | XPath复杂表达式、Relax-NG/Schematron验证、XInclude、push-mode解析、Catalog |
| curl | ~55-60% | RTSP/MQTT/LDAP/SFTP协议、proxy链、HTTP/3(QUIC)、cookie引擎 |
| libarchive | ~55% | RAR5、LZH、ISO9660、CPIO writer、ACL/xattr、稀疏文件、多卷归档 |
| FreeType | ~65% | CFF2/OT可变字体、BDF/PCF位图字体、罕见TrueType指令 |
| SQLite | ~70% | 虚拟表模块、FTS5边界、窗口函数复杂frame、ALTER TABLE |
| HarfBuzz | ~60% | Khmer/Myanmar复杂文字整形、AAT布局表、hb-subset |
| libwebp | ~65% | 动画WebP、有损+alpha组合、增量解码 |
| libpng | ~75% | APNG(动画PNG)、色彩空间转换链、渐进/交错读取 |

近年绕过 OSS-Fuzz 的真实CVE证明盲区是可利用的：
- FreeType CVE-2025-27363: ITW OOB write，OSS-Fuzz未触及的TrueType glyph解析路径
- libxml2 CVE-2024-25062: UAF in xmlValidatePopElement，OSS-Fuzz harness未覆盖的验证路径
- curl CVE-2024-2398: HTTP/2内存泄漏，协议状态机逻辑fuzzer无法建模
- libarchive CVE-2024-26256: RAR格式RCE，格式特定路径覆盖率低
- SQLite 2024多个CVE: Trail of Bits通过grammar-aware fuzzing发现，OSS-Fuzz基础harness做不到

**CoreBreaker 的策略：用LLM分析OSS-Fuzz现有harness的盲区，针对性生成覆盖这些盲区的新harness。**

## 三、从现有项目复用什么

### 从 Ouroboros 复用（编排层）

| 模式 | 原始实现 | CoreBreaker中的角色 |
|------|---------|-------------------|
| 双持久会话 (`--resume`) | researcher + supervisor | **Harness Engineer** + **Research Director** |
| Fork-Join双管线 | Discovery ‖ Execution → Feedback | **分析管线** ‖ **Fuzzing管线** → 策略同步 |
| 6-action审核循环 | dig_deeper/proceed/abandon/... | 适配为harness审核动作 |
| 策略记忆+自动压缩 | `strategy-memory.json` | 直接复用，按库/攻击面维度组织 |
| 饱和度检测+强制pivot | dup_rounds / no_finding_rounds | 复用，阈值对齐AFL++ `cycles_wo_finds` |
| 成本追踪+预算硬限 | `ResourceGuard` | 直接复用 |
| Bootstrap动态队列生成 | 分析git log生成目标 | 改为分析OSS-Fuzz覆盖率报告生成目标 |

### 从 Arachne 复用（执行层）

| 模式 | 原始实现 | CoreBreaker中的角色 |
|------|---------|-------------------|
| 三级决策框架 | Level 1/2/3 | **直接复用**，最核心的运营智慧 |
| `fuzz_monitor.sh` 信号系统 | CONTINUE/ADJUST/STOP | 去掉ADB，直接读本地`fuzzer_stats` |
| `crash_collect.sh` 管线 | 采集/复现/最小化/回注 | 去掉ADB，改为本地操作 |
| Checksum fixup模式 | CRC-16重算 | 适用于PNG CRC-32、FLAC CRC等 |
| 多帧状态积累 | 不reset decoder | 适用于所有有状态的解析器 |
| 种子参数覆盖生成 | `gen_seeds.py` | 每个目标库定制种子生成器 |
| 目标评估评分 | `target_assess.sh` | 改为源码级评估 |

### 不需要带来的

- ARM64 trampoline引擎（有源码就用编译器插桩）
- Frida coverage（同上）
- CFI bypass（非Android场景）
- 手动bitmap写入（AFL++/libFuzzer自动处理）
- ADB/设备通信层

## 四、系统架构

```
┌──────────────────────────────────────────────────────────┐
│                    hunt-supervisor.py                      │
│              (改造自Ouroboros, Python主进程)                │
│                                                            │
│  ┌──────────────────┐  join()  ┌───────────────────────┐  │
│  │ Pipeline A        │◄───────►│ Pipeline B             │  │
│  │ (分析+Harness工程) │         │ (Fuzzing执行)          │  │
│  │                    │         │                         │  │
│  │ RECON              │         │ BUILD                   │  │
│  │  ↓                 │         │  ↓                      │  │
│  │ HARNESS_GEN        │         │ FUZZ                    │  │
│  │  ↓                 │         │  ↓                      │  │
│  │ REVIEW             │         │ MONITOR                 │  │
│  │  ↓                 │         │  ↓                      │  │
│  │ SEED_GEN           │         │ CRASH_COLLECT           │  │
│  └────────┬───────────┘         └──────────┬──────────────┘  │
│           └───────────┬────────────────────┘                 │
│                       ▼                                      │
│                 FEEDBACK (策略同步)                            │
│                       │                                      │
│            ┌──────────▼───────────┐                          │
│            │ Research Director     │                          │
│            │ (Opus, --resume)      │                          │
│            │ 评估覆盖率增长         │                          │
│            │ 评估crash质量         │                          │
│            │ 决定pivot/继续/升级    │                          │
│            └──────────────────────┘                          │
└──────────────────────────────────────────────────────────────┘

外部依赖：
  - AFL++ (afl-clang-fast编译, afl-fuzz运行)
  - libFuzzer (备选)
  - ASan / UBSan / MSan (编译器sanitizer)
  - Claude CLI (harness生成 + crash分析)
```

## 五、Pipeline A 详细设计（分析+Harness工程）

### Phase 1: RECON（侦察）

**输入：** 目标库名（如 `libxml2`）
**LLM角色：** Harness Engineer（Sonnet，有工具权限）

执行步骤：
1. `git clone` 目标库源码
2. `git clone` oss-fuzz 仓库，读取 `projects/<name>/` 下所有现有fuzz target
3. 分析OSS-Fuzz现有harness覆盖了哪些API
4. 分析目标库的**公开API全集**（读取头文件）
5. 识别**OSS-Fuzz未覆盖的API和代码路径**
6. 输出 `recon-report.json`

输出结构示例：

```json
{
  "library": "libxml2",
  "version": "2.13.x",
  "oss_fuzz_targets": ["xml_read_memory_fuzzer", "xpath_fuzzer"],
  "covered_apis": ["xmlReadMemory", "xmlXPathEval"],
  "uncovered_apis": [
    {
      "api": "xmlRelaxNGValidateDoc",
      "risk": "high",
      "reason": "complex grammar validation, no existing harness"
    },
    {
      "api": "xmlSchematronValidateDoc",
      "risk": "high",
      "reason": "Schematron engine, zero fuzz coverage"
    },
    {
      "api": "xmlCatalogResolve",
      "risk": "medium",
      "reason": "catalog resolution, file I/O paths"
    }
  ],
  "uncovered_features": [
    {
      "feature": "push-mode parsing (xmlCreatePushParserCtxt)",
      "reason": "all OSS-Fuzz harnesses use pull-mode"
    },
    {
      "feature": "HTML parser with SAX",
      "reason": "only DOM-style harness exists"
    }
  ],
  "build_notes": "cmake -DLIBXML2_WITH_SCHEMAS=ON -DLIBXML2_WITH_SCHEMATRON=ON needed",
  "downstream_vrp": ["Apple (system library)", "Google (Chrome/Android)", "Mozilla (Firefox)"]
}
```

### Phase 2: HARNESS_GEN（Harness生成）

**LLM角色：** Harness Engineer（Opus首次生成, Sonnet迭代改进）

从RECON报告中选择最高优先级的未覆盖API，生成三个文件：

**harness.c** — 兼容 libFuzzer + AFL++ 持久模式：
```c
#include <stdint.h>
#include <stddef.h>

// libFuzzer 入口
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 10 * 1024 * 1024) return 0;  // OOM保护
    // ... 目标API调用 ...
    return 0;
}

// AFL++ 持久模式兼容
#ifdef __AFL_FUZZ_TESTCASE
__AFL_FUZZ_INIT();
int main(int argc, char **argv) {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        LLVMFuzzerTestOneInput(buf, len);
    }
    return 0;
}
#endif
```

Harness生成遵循的原则（来自Arachne经验）：
- **Checksum fixup > bypass**: 重算校验和而非NOP掉校验，保证内部状态正确构建
- **多调用状态积累**: 有状态API不在每次调用间reset
- **特性标志全覆盖**: 启用所有可选解析选项（如libxml2的DTD加载、entity展开）
- **大小限制防OOM**: 硬编码上限

**build.sh** — 编译脚本
**gen_seeds.py** — 种子生成（每个合法参数组合一个种子）

### Phase 3: REVIEW（质量门控）

**LLM角色：** Research Director（Opus, --resume）

复用Ouroboros的审核循环，动作集适配为：

| 动作 | 含义 |
|------|------|
| `improve_harness` | harness有问题（编译错误/覆盖率低/API用法错误），给出修改指令 |
| `add_fixup` | 需要添加checksum fixup或header fixup |
| `expand_api` | 当前harness只覆盖一个API入口，应扩展 |
| `proceed` | harness质量OK，进入编译+fuzzing |
| `abandon` | 这个API不值得fuzz |
| `generate_seeds` | 先改进种子质量 |

审核依据：
- 编译是否通过（BUILD管线反馈）
- 初始覆盖率（跑10秒看edge数）
- 与OSS-Fuzz现有harness的差异度

最多5轮审核，与Ouroboros一致。

### Phase 4: SEED_GEN（种子生成）

LLM生成种子生成脚本，复用Arachne的参数覆盖模式：
- 每个合法枚举值各一个种子
- 极端大小（最小/最大/空文件）
- 特殊结构组合（嵌套、递归、跨引用）
- 针对具体库：如libxml2需要DTD种子、XSD种子、Relax-NG schema种子

## 六、Pipeline B 详细设计（Fuzzing执行）

几乎完全复用Arachne执行层，去掉Android/ADB：

### BUILD

```bash
# ASan + 源码插桩编译目标库
cd $TARGET_SRC && mkdir build && cd build
CC=afl-clang-fast CXX=afl-clang-fast++ \
  cmake .. -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g"
make -j$(nproc)

# 编译harness
afl-clang-fast -fsanitize=address,undefined -g -O1 \
  -I$TARGET_SRC/include \
  harness.c -o harness_asan \
  $TARGET_SRC/build/lib/libtarget.a

# CMPLOG版本（用于token提取）
AFL_LLVM_CMPLOG=1 afl-clang-fast ... -o harness_cmplog
```

### FUZZ

```bash
# 多实例并行
afl-fuzz -i corpus/ -o output/ -M main -- ./harness_asan @@
afl-fuzz -i corpus/ -o output/ -S variant01 -p exploit -- ./harness_asan @@
afl-fuzz -i corpus/ -o output/ -S cmplog01 -l 2 -c ./harness_cmplog -- ./harness_asan @@
```

### MONITOR

直接复用 `fuzz_monitor.sh` 信号逻辑，读本地 `output/main/fuzzer_stats`：

| 信号 | 条件 | 动作 |
|------|------|------|
| CRASH | `saved_crashes > 0` | 触发 CRASH_COLLECT |
| ANOMALY | `stability < 90%` 或 `exec_speed < 1` | 检查harness问题 |
| STOP | `pending_favs=0, cycles_wo_finds>50, time_wo_finds>3600s` | 停止，进入Level 2 |
| ADJUST | `pending_favs=0, cycles_wo_finds>20` | 换power schedule/加CMPLOG/加实例 |
| CONTINUE | `pending_favs>0` 或 `cycles_wo_finds<20` | 继续 |

### CRASH_COLLECT

复用Arachne管线：
1. 检测 `saved_crashes > 0`
2. 复现每个crash（跑harness，检查退出信号）
3. `afl-tmin -O` 最小化
4. 去重（ASan栈帧hash）
5. 分类（heap-use-after-free / heap-buffer-overflow / stack-overflow / integer-overflow 等）
6. 可选：最小化crash回注为新种子
7. 记录到 `crash_log.csv`

## 七、FEEDBACK 策略同步

复用Ouroboros策略引擎，信号来源变化：

| 信号 | 来源 |
|------|------|
| 覆盖率增长 | `fuzzer_stats` 的 `edges_found` |
| Crash数量/类型 | crash inventory |
| Harness质量 | 初始10秒覆盖率 vs 1小时覆盖率增长比 |
| 饱和度 | `cycles_without_finds` |
| Bug类型多样性 | ASan crash类型分布 |

Research Director 决策：
- **继续当前harness** — 覆盖率仍在增长
- **升级harness** — 覆盖率停滞但优化空间大（应用Arachne Level 2决策树）
- **Pivot到新API** — 当前API饱和，同库内切换下一个未覆盖API
- **Pivot到新库** — 当前库整体饱和，切换目标库
- **提交报告** — 有确认的可利用crash，生成多VRP报告模板

### Level 2 决策树（来自Arachne）

当覆盖率停滞时，按ROI排序的优化动作：

1. **种子质量提升** — 用LLM生成更有针对性的种子（30-72%覆盖率提升，1-2h投入）
2. **Harness扩展** — 增加API调用深度或启用更多特性标志（<15%提升，2-4h）
3. **Checksum fixup添加** — 如果格式有校验和gate（30-72%提升，1-2h）
4. **Custom mutator** — 对高度结构化格式（SQL、XML schema）写结构感知mutator（最高理论增益，1-2天）
5. **真饱和** — 进入Level 3目标经济学评估，决定是否切换

### Level 3 目标经济学（来自Arachne）

五维评分（1-5分）：
- 漏洞价值（30%权重）：下游VRP覆盖数 × 最高单价
- 覆盖效率（20%）：当前edges / 预估总edges
- 优化空间（25%）：未尝试的Level 2优化动作数
- 沉没成本（15%）：已投入的CPU时间和LLM成本
- 替代目标（10%）：队列中其他目标的预期价值

总分 >= 3.5: 继续投入。2.0-3.5: 后台运行同时启动新目标。< 2.0: 切换。

## 八、目标规划（数据驱动）

基于 Chrome 361 CVE + Apple 151 CVE 实际公告数据排序，不限于传统C库。

### Tier 0：数据证明最高ROI的目标

#### 1. ANGLE 着色器编译器 — Chrome VRP 单笔最高赏金

**实际数据：** $123,000总赏金，$61,500均价，单笔最高 **$90,000** (CVE-2026-6296)

**项目：** `chromium/angle`，开源，处理 GLSL/HLSL/Metal/SPIR-V 着色器编译转译

**为什么 Tier 0：**
- 单笔 $90,000 是 Chrome VRP 最高赏金记录之一
- 输入100%攻击者可控（任何网页通过 WebGL/WebGPU 提交着色器代码）
- `wgslfuzz` 研究者是这里的常客——已证明 fuzzing 有效
- 与 Arachne 的 libusc (PowerVR shader compiler) 同品类，但 ANGLE 是开源的，可以用源码插桩
- OSS-Fuzz 有基础覆盖但 ANGLE 代码量大（~2M LOC），着色器语言变体多

**攻击面：**
- GLSL→HLSL 转译路径
- GLSL→Metal 转译路径（Apple设备）
- GLSL→SPIR-V 转译路径（Vulkan）
- WGSL 解析器（WebGPU新语言）
- 着色器验证器/优化器

**Harness计划：**
1. `glsl_translator_fuzzer.c` — GLSL 各版本着色器转译
2. `wgsl_parser_fuzzer.c` — WGSL 解析
3. `spirv_validator_fuzzer.c` — SPIR-V 验证
4. `shader_optimizer_fuzzer.c` — 着色器优化 pass

#### 2. Chrome WebML / TFLite — 新组件，最高均价

**实际数据：** $205,000总赏金，**$41,000均价**，5个CVE全部是 Critical/High

**项目：** `third_party/tflite/` + `components/ml/`（Chrome内置ML推理），开源

**为什么 Tier 0：**
- 均价 $41,000 超过 V8 以外所有组件
- Chrome 内置 AI 功能（Gemini Nano on-device、AI writing、智能摘要）依赖此引擎
- 新代码，安全审计覆盖率极低
- 漏洞类型是经典的堆溢出/整数溢出——完美适配 fuzzing
- 输入是不受信任的 ML 模型文件（TFLite FlatBuffer 格式）和推理张量数据

**攻击面：**
- TFLite 模型文件解析（FlatBuffer 格式）
- 算子内核（Conv2D/MatMul/Reshape 等数百种算子的 C++ 实现）
- 量化/反量化路径
- Delegate 接口（GPU/NNAPI/XNNPACK delegate）
- Chrome 集成层（`components/ml/` 的模型加载和沙箱交互）

**Harness计划：**
1. `tflite_model_fuzzer.c` — TFLite FlatBuffer 模型解析
2. `tflite_op_fuzzer.c` — 逐算子 kernel fuzzing
3. `tflite_quantize_fuzzer.c` — 量化/反量化路径
4. `webml_inference_fuzzer.c` — Chrome WebML 推理管线

#### 3. Dawn / WebGPU — GPU 命令处理

**实际数据：** Dawn $15,000 + WebGPU $35,000 = $50,000合计，含 High/Critical

**项目：** `chromium/dawn`（WebGPU 实现），开源

**为什么 Tier 0：**
- WebGPU 是新标准，代码年轻，审计覆盖率低
- GPU 命令缓冲区处理涉及大量手动内存管理
- Dawn 同时被 Chrome 和 Firefox (wgpu-native via Dawn) 使用
- 着色器输入、命令缓冲区构造都是攻击者可控的

**Harness计划：**
1. `wgsl_dawn_fuzzer.c` — Dawn 的 WGSL 着色器处理
2. `command_buffer_fuzzer.c` — GPU 命令缓冲区序列化/反序列化
3. `dawn_wire_fuzzer.c` — Dawn Wire 协议（进程间 GPU 命令传递）

### Tier 1：经典路径 + 多VRP套利

#### 4. libxml2 — 最稳的启动目标

**OSS-Fuzz盲区：** Relax-NG验证、Schematron验证、XInclude处理、push-mode解析、Catalog解析

**下游VRP：** Apple（系统级依赖）+ Google（Chrome/Android）+ Mozilla（间接）

**为什么选：**
- CVE-2024-25062 证明验证路径是真实盲区
- Relax-NG/Schematron 在 OSS-Fuzz 中**完全没有harness**
- Push-mode 解析是全新的状态机路径
- 库大小适中（~300K LOC），编译简单，快速验证

**Harness计划：**
1. `relaxng_validate_fuzzer.c` — Relax-NG schema验证
2. `schematron_validate_fuzzer.c` — Schematron验证
3. `push_parser_fuzzer.c` — push-mode增量解析
4. `xinclude_fuzzer.c` — XInclude处理
5. `catalog_fuzzer.c` — XML Catalog解析

#### 5. libarchive — 格式多样性最高

**OSS-Fuzz盲区：** RAR5、LZH、ISO9660、CPIO变体、ACL/xattr、稀疏文件重建、多卷归档

**下游VRP：** Apple（macOS系统tar和Archive Utility）+ Google

**为什么选：**
- CVE-2024-26256 (RAR RCE) 证明格式特定路径脆弱
- macOS用户双击.zip/.rar直接触发，零交互

**Harness计划：**
1. `rar5_fuzzer.c` — RAR5格式解析
2. `lzh_fuzzer.c` — LZH格式解析
3. `iso9660_fuzzer.c` — ISO9660光盘镜像解析
4. `multivolume_fuzzer.c` — 多卷归档
5. `sparse_file_fuzzer.c` — 稀疏文件重建

#### 6. curl — 协议路径丰富度最高

**OSS-Fuzz盲区：** RTSP/MQTT/LDAP/SFTP、proxy链、HTTP/3(QUIC)、cookie引擎

**下游VRP：** Google + Apple + Microsoft + 自身HackerOne — 四家VRP全覆盖，套利价值最高

**Harness计划：**
1. `mqtt_fuzzer.c` — MQTT协议解析
2. `rtsp_fuzzer.c` — RTSP协议解析
3. `http3_fuzzer.c` — HTTP/3(QUIC)路径
4. `proxy_chain_fuzzer.c` — SOCKS5+HTTPS代理链
5. `cookie_engine_fuzzer.c` — cookie解析和状态机

#### 7. Apple CoreMedia / CoreAudio — Apple最肥的目标

**实际数据：** CoreMedia 7 CVE（71%内存安全，含ITW零日 CVE-2025-24085），CoreAudio 5 CVE

**为什么选：**
- 71% 内存安全 + 含 ITW 零日 = 真实可利用攻击面
- 媒体文件是 iMessage 零点击攻击链的核心入口（FORCEDENTRY先例）
- Apple 赏金最高类别：零点击远程代码执行 $500k–$1M

**攻击方式：**
- macOS 上直接 fuzz Apple 的 CoreMedia/CoreAudio 框架
- 需要构造调用 Apple 私有 API 的 harness（通过 dlopen/dlsym）
- 输入格式：AAC、ALAC、H.264、HEVC、HEIF

### Tier 2：第二批目标

| 目标 | 赏金数据/盲区 | 下游VRP | 推荐攻击角度 |
|------|-------------|---------|-------------|
| **FreeType** | CVE-2025-27363 ITW; OSS-Fuzz ~65% | G + A + Moz | BDF/PCF位图字体解析器，代码老旧极少被fuzz |
| **SQLite** | OSS-Fuzz ~70%覆盖 | G + A + Moz | grammar-aware fuzzing，LLM生成SQL种子 |
| **HarfBuzz** | OSS-Fuzz ~60% | G + A | Khmer/Myanmar复杂文字整形 |
| **libwebp** | CVE-2023-4863全平台影响 | G + A + Moz | 动画WebP、有损+alpha组合 |
| **libpng** | APNG路径几乎未被fuzz | G + A + Moz | APNG(动画PNG) |
| **AirPlay** | Apple 14 CVE, 57%内存安全 | A | 网络可达协议，需要协议逆向 |
| **Skia** | Chrome渲染引擎底层 | G | 图像解码、路径渲染 |

### 完整攻击面矩阵

| 攻击面 | 方法 | 赏金潜力 | 下游VRP |
|--------|------|---------|---------|
| **ANGLE着色器编译** | shader fuzzing | $33k–$90k/个 | Google (Chrome) |
| **WebML/TFLite** | 模型文件+算子fuzzing | $33k–$43k/个 | Google (Chrome) |
| **Dawn/WebGPU** | GPU命令fuzzing | $15k–$25k/个 | Google (Chrome) |
| **经典C库** (libxml2/curl/libarchive/FreeType) | 覆盖率引导fuzzing | $5k–$100k/个 | G + A + M + Moz（多家套利） |
| **Apple CoreMedia/CoreAudio** | 媒体格式fuzzing | $25k–$1M/个 | Apple |
| **AirPlay** | 协议fuzzing | $25k–$100k/个 | Apple |
| **SQLite** | grammar-aware fuzzing | $5k–$50k/个 | G + A + Moz |

### 下游VRP套利矩阵

| 目标 | Google | Apple | Microsoft | Mozilla | 自身赏金 |
|------|--------|-------|-----------|---------|---------|
| ANGLE | Chrome WebGL/WebGPU | - | - | - | 无（通过Google VRP） |
| WebML/TFLite | Chrome AI功能 | - | - | - | 无（通过Google VRP） |
| Dawn | Chrome WebGPU | - | - | - | 无（通过Google VRP） |
| libxml2 | Chrome/Android | iOS/macOS系统库 | - | - | 无 |
| libarchive | Android | macOS tar/Archive Utility | - | - | 无 |
| curl | Chrome/Android | iOS/macOS | Windows | - | HackerOne |
| FreeType | Chrome/Android字体 | iOS/macOS全设备 | - | Firefox | 无 |
| SQLite | Chrome/Android | iOS每个App | - | Firefox | 无 |
| zlib | Chrome/Android | iOS/macOS | Windows | Firefox | 无 |
| libpng | Chrome/Android | iOS/macOS | - | Firefox | 无 |
| libwebp | Chrome | iOS/macOS | - | Firefox | Google VRP |
| CoreMedia | - | Apple直接 | - | - | Apple SRB |
| AirPlay | - | Apple直接 | - | - | Apple SRB |

## 九、状态管理（复用Ouroboros schema）

```
state/
  hunt-state.json          # 全局迭代计数器和统计
  target-queue.json        # 库+API级别的优先级队列
  harness-inventory.json   # 已生成harness的状态(pending/building/fuzzing/exhausted)
  crash-inventory.json     # crash数据库(去重、分类、利用性评估)
  findings-log.jsonl       # 追加写入的发现日志
  strategy-memory.json     # 长期策略记忆(自动压缩)
  vrp-tracker.json         # VRP提交跟踪(哪个crash提交了哪些VRP)
```

新增 `vrp-tracker.json`，跟踪每个crash在不同VRP中的提交状态：

```json
{
  "crashes": {
    "crash_001": {
      "library": "libxml2",
      "type": "heap-buffer-overflow",
      "cve": null,
      "submissions": [
        {"vrp": "apple", "status": "submitted", "id": "APPLE-SA-xxxx", "date": "2026-05-01"},
        {"vrp": "google", "status": "draft", "id": null, "date": null}
      ]
    }
  }
}
```

## 十、项目目录结构

```
corebreaker/
  DESIGN.md                # 本文档
  CLAUDE.md                # Claude Code运行时指令
  scripts/
    hunt-supervisor.py     # 主编排引擎(改造自Ouroboros)
    bootstrap.py           # 初始化+OSS-Fuzz分析
    fuzz-monitor.sh        # fuzzing监控信号(改造自Arachne)
    crash-collect.sh       # crash采集管线(改造自Arachne)
    build-target.sh        # 目标库ASan编译
  platform/
    templates/
      harness_template.c   # libFuzzer+AFL++持久模式harness模板
      build_template.sh    # 编译脚本模板
      gen_seeds_template.py # 种子生成模板
  targets/
    # Tier 0: 高赏金组件
    angle/                 # ANGLE着色器编译器
    webml/                 # Chrome WebML/TFLite
    dawn/                  # Dawn/WebGPU
    # Tier 1: 经典C库套利
    libxml2/
    libarchive/
    curl/
    coremedia/             # Apple CoreMedia (macOS fuzzing)
    # Tier 2: 后续扩展
    freetype/
    sqlite/
    harfbuzz/
    ...
    # 每个target的子目录结构:
    #   harness/             # 生成的harness源码
    #   corpus/              # 种子语料
    #   output/              # AFL++输出
    #   findings/            # crash报告
    #   STATUS.md            # 当前状态
  state/                   # 运行时状态(JSON)
  knowledge/               # 目标特定知识(CVE模式、API文档、赏金数据)
  reports/                 # VRP提交报告
  .claude/
    commands/              # Claude Code skill定义
    agents/                # Agent定义
```

## 十一、启动路径

不要一开始就构建完整的supervisor系统。先验证核心假设。

### 第0步（本周）: 双轨手动验证

同时启动两个验证，分别覆盖 Tier 0 和 Tier 1：

**验证A — ANGLE shader fuzzer（Tier 0，高赏金）：**
1. `git clone` chromium/angle
2. 分析 OSS-Fuzz 已有的 ANGLE fuzz target
3. 让 Claude 针对 GLSL→SPIR-V 转译路径生成新 harness
4. 用 AFL++ 编译运行 24 小时
5. 对比 `wgslfuzz` 已有成果，确认是否有差异化空间

**验证B — libxml2 Relax-NG fuzzer（Tier 1，快速出结果）：**
1. 让 Claude 生成 Relax-NG 验证 harness
2. 用 AFL++ 编译运行 24 小时
3. 验证 OSS-Fuzz 盲区假设是否成立

两个验证中任一产出 crash → 路径可行，按该方向优先构建系统。

### 第1步（2周内）: 最小可用系统

- Fork Ouroboros 的 supervisor.py
- 去掉 JSC 特定逻辑，保留编排骨架
- Pipeline B 用 shell 脚本（复用 Arachne 的 monitor/crash_collect）
- Pipeline A 用 Claude CLI 生成 harness
- 在验证成功的目标上跑起来

### 第2步（1个月内）: 多目标扩展

- RECON 阶段自动分析 OSS-Fuzz 现有 harness 盲区
- FEEDBACK 阶段用覆盖率增长驱动决策
- 多目标并行（Tier 0 + Tier 1 各至少一个活跃 fuzzing 实例）
- 加入 WebML/TFLite 模型文件 fuzzing

### 第3步（2个月内）: VRP自动化 + Apple目标

- crash确认后自动生成多份VRP报告模板（Google/Apple/Microsoft格式）
- 跟踪每个crash在不同下游产品中的可复现性
- 构建下游产品版本对应关系（哪个版本的Chrome用哪个版本的libxml2）
- 启动 macOS 上的 CoreMedia/CoreAudio fuzzing（Apple SRB 高赏金路径）

## 十二、数据附录

### Chrome CVE类型分布（361 CVE, 2025.03–2026.04）

| 漏洞类型 | 数量 | 占比 | 赏金总额 |
|---------|------|------|---------|
| Use after free | 83 | 23.0% | $194,000 |
| Inappropriate implementation | 79 | 21.9% | $175,000 |
| Heap buffer overflow | 34 | 9.4% | $255,000 |
| Incorrect security UI | 21 | 5.8% | $26,500 |
| Integer overflow | 20 | 5.5% | $133,000 |
| Type Confusion | 19 | 5.3% | $344,000 |
| Insufficient policy enforcement | 17 | 4.7% | $14,000 |
| Out of bounds read | 16 | 4.4% | $46,000 |
| Insufficient validation | 12 | 3.3% | $11,500 |
| Race condition | 10 | 2.8% | $4,000 |
| 其他 | 50 | 13.8% | $75,000 |

内存安全占 56.2% 但拿走 77.2% 赏金。Type Confusion 仅 19个 但赏金 $344,000（均价最高）。

### Chrome Top 10 单笔赏金

| 赏金 | CVE | 类型 | 组件 |
|------|-----|------|------|
| $90,000 | CVE-2026-6296 | Heap buffer overflow | ANGLE |
| $55,000 | CVE-2025-13226~13230 (5个) | Type Confusion | V8 |
| $50,000 | CVE-2025-12428 | Type Confusion | V8 |
| $43,000 | CVE-2026-5858/5859/3914/3915 (4个) | Heap overflow / Integer overflow | WebML |
| $43,000 | CVE-2025-10200 | Use after free | ServiceWorker |
| $36,000 | CVE-2026-3916 | Out of bounds read | Web Speech |
| $32,000 | CVE-2026-3537 | Object lifecycle issue | PowerVR |
| $30,000 | CVE-2025-10201 | Inappropriate implementation | Mojo |

### Apple iOS 漏洞类别分布（151 CVE, 2025.01–2025.05）

| 类别 | 数量 | 占比 |
|------|------|------|
| 内存安全 | 43 | 30.7% |
| 输入验证 | 31 | 22.1% |
| 逻辑/状态 | 27 | 19.3% |
| 权限/访问控制 | 20 | 14.3% |
| 隐私/信息泄露 | 12 | 8.6% |
| 其他 | 7 | 5.0% |

### Apple 高CVE组件

| 组件 | CVE数 | 内存安全占比 | 备注 |
|------|-------|------------|------|
| WebKit | 20 | 50% | Ouroboros 覆盖 |
| AirPlay | 14 | 57% | 网络可达，CoreBreaker Tier 2 |
| Kernel | 8 | 混合 | 需内核fuzzing |
| CoreMedia | 7 | **71%** | 含ITW零日，CoreBreaker Tier 1 |
| Safari | 7 | 14%（大部分逻辑漏洞） | 导航/状态管理 |
| Siri | 6 | 0%（权限问题） | 超出CoreBreaker范围 |
| CoreAudio | 5 | 输入验证 | CoreBreaker可覆盖 |
