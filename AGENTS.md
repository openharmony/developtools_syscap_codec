# AGENTS.md — syscap_codec

OpenHarmony 系统能力（SysCap）编解码工具。产物包括 `syscap_tool`（CLI 二进制）和 `syscap_interface_shared`（供其它部件使用的共享库）。

## 构建系统

- **GN** 构建系统（非 CMake/Make）。依赖完整的 OpenHarmony 构建树。
- 根构建文件：`BUILD.gn`、`config.gni`。
- 使用 `ohos_executable`、`ohos_shared_library`、`ohos_unittest` 等模板定义目标。
- **无法独立编译** — 本仓库位于 OHOS 源码树的 `developtools/syscap_codec` 路径下。

## 关键目标及产物

| 目标 | 产物 | 用途 |
|---|---|---|
| `syscap_tool_bin` | `syscap_tool` | pcid/rpcid 编码、解码、比较的 CLI 工具 |
| `syscap_interface_shared` | `.so` 共享库 | 供其它 OHOS 部件调用的内部 API |
| `napi:systemcapability` | `.so` 模块 | 设备侧 JS API（`@ohos.systemCapability`） |
| `taihe/syscap:systemCapability_taihe_native` | `.so` + `.abc` | 新式 Taihe API（从 `.taihe` IDL 代码生成） |

## 目录结构

```
src/           — 核心编解码逻辑（C 语言）。所有目标共用。
  syscap_tool.c, create_pcid.c, endian_internal.c, context_tool.c, common_method.c, main.c
include/       — CLI 工具的对外头文件。
  syscap_tool.h, create_pcid.h, context_tool.h
  codec_config/syscap_define.h  — 所有 SysCap 的主列表（枚举 + 字符串数组）
interfaces/inner_api/ — 共享库消费者的内部 API。
napi/          — NAPI JS 绑定（C++ → JS）。
taihe/syscap/  — 新式 Taihe IDL 驱动 API（从 .taihe 文件代码生成，C++ → ETS）。
tools/         — 一致性检查和配置合并的 Python 脚本。
```

**注意**：同一套 `src/*.c` 源文件被重复编译到每一个目标中 — 内部不存在静态库。

> 嵌套指引：本仓**无** `CLAUDE.md`/`GEMINI.md`/`.cursorrules` 等嵌套指令文件，也无目录级 `AGENTS.md`。本文件是唯一的 agent 指引。深度知识见仓库内 `README_ZH.md` 与下方"知识路由"。

## 常见任务路径

每个任务开始前先定位到对应文件，再开始修改。

| 任务 | 关键文件 | 说明 |
| --- | --- | --- |
| 新增 SysCap 枚举 | `include/codec_config/syscap_define.h` | 末尾追加，遵守下方规则 |
| 修改 CLI 命令行行为 | `src/main.c` → `include/syscap_tool.h` → `src/syscap_tool.c` | 需同步更新 `PrintHelp()` |
| 修改共享库对外 API | `interfaces/inner_api/syscap_interface.h` → `interfaces/inner_api/syscap_interface.c` → `libsyscap_interface_shared.versionscript` | **三文件必须一致** |
| 修改 JS 端 API（NAPI） | `napi/napi_query_syscap.cpp` + `napi/query_syscap.js` | NAPI C++ 桥接层 |
| 修改 Taihe 端 API | `taihe/syscap/idl/ohos.systemCapability.taihe`（IDL 源） + `taihe/syscap/src/*.impl.cpp`（手写实现） | 生成文件不提交 |
| 修改编码/解码逻辑 | `src/syscap_tool.c` + `src/create_pcid.c` | 核心算法 |
| 修改字节序处理 | `src/endian_internal.c` + `src/endian_internal.h` | 跨平台大小端 |
| 运行一致性检查 | `tools/syscap_check.py` | 独立 Python 工具 |
| 添加/修改测试 | `test/unittest/common/syscap_codec_test.cpp` | gtest 框架 |

## 知识路由

遇到以下情况时，先查阅对应文件再做修改，避免出错。

### 按任务触发

- **新增 SysCap 枚举值** → 读 `include/codec_config/syscap_define.h` 全文 + 本节下方"syscap_define.h 规则"
- **修改共享库对外接口** → 读 `interfaces/inner_api/syscap_interface.h` 中的函数签名 + `libsyscap_interface_shared.versionscript` 中的符号列表
- **修改 Taihe IDL** → 读 `taihe/syscap/idl/ohos.systemCapability.taihe`，理解代码生成流程后再改
- **修改构建参数** → 读 `config.gni` + `BUILD.gn` 中的 `declare_args` 和条件编译分支
- **新增目标平台** → 读 `src/endian_internal.c` + `BUILD.gn` 中的 `is_mingw` / `ohos_lite` 分支

### 按术语触发

- **pcid** = Product Compatibility ID（设备能力标识），编码结果以 `.sc` 后缀存储
- **rpcid** = Required Product Compatibility ID（应用所需能力标识）
- **SysCap** = SystemCapability 系统能力，格式为 `SystemCapability.XX.Yyy`
- **NAPI** = Native API 桥接层，连接 C 核心逻辑与 JS 运行时
- **Taihe** = 新式 IDL 驱动 API 框架，`.taihe` 文件是唯一源头，生成代码不提交
- **版本脚本** = `libsyscap_interface_shared.versionscript`，控制 `.so` 导出符号，破坏即 ABI 断裂

### 按路径触发

- **改 `src/` 下任何文件** → 该文件被所有 4 个目标共同编译，影响全部产物
- **改 `interfaces/inner_api/`** → 影响 `syscap_interface_shared` + NAPI + Taihe 三个目标
- **改 `napi/`** → 仅影响设备侧 JS 模块，其余目标不变
- **改 `taihe/syscap/`** → 仅当 `support_jsapi && is_standard_system` 时生效
- **改 `tools/`** → 不参与编译，独立运行

### 编辑前自检（必做）

动手编辑前，agent 须在回复中明确以下三点，再开始改代码：
1. **任务类别**：这是改 CLI / 改共享库 API / 改 NAPI / 改 Taihe / 改编解码逻辑 / 改构建 / 改测试 / 还是其它？
2. **已读文档**：按上方"按任务/路径/术语触发"路由，实际读了哪些文件？
3. **命中约束**：本任务触及哪些"不可破坏 / 修改前必须确认 / syscap_define.h 规则 / Taihe 代码生成"条目？是否需要先请示？

## 禁止事项

以下规则在任何情况下都不应违反。如有疑问，先询问而不是直接操作。

### 不可破坏的约束

- **切勿**修改 `libsyscap_interface_shared.versionscript` 中已发布的符号名、签名或删除符号。这是共享库的 ABI 契约，破坏后下游部件动态链接失败。
- **切勿**修改 `interfaces/inner_api/syscap_interface.h` 中已发布函数的签名（参数类型、个数、返回值类型）。可以新增函数，不能变更已有函数。
- **切勿**在 `include/codec_config/syscap_define.h` 中删除或重排枚举值。废弃时只注释 `// abandoned`。
- **切勿**直接编辑 Taihe 代码生成器产出的文件（`*ani.cpp`、`*abi.c`、`@ohos.*.ets`）。这些文件由构建系统从 `.taihe` IDL 生成，手动修改会在下次构建时被覆盖。

### 修改前必须确认的事项

- 修改 `src/syscap_tool.c` 编码/解码逻辑 → 确认对 `syscap_tool` CLI 和共享库的行为影响
- 新增依赖 → 检查 `bundle.json` 中的 `deps.components` 并更新 `BUILD.gn`
- 新增平台条件编译 → 对照 `BUILD.gn:47-52`（`is_mingw`、`ohos_lite` 分支模式）
- 修改 `PRINT_ERR` 或错误返回码 → 确认所有调用方兼容新的错误处理路径

### License 敏感改动

- 新增/升级三方依赖（如 cJSON、bounds_checking_function、googletest）前，须检查 `OAT.xml` 白名单是否覆盖；未覆盖须先更新 `OAT.xml` 再引入。
- `bundle.json` 的 `deps.components` / `public_external_deps` 变更后，同步检查是否引入新的 license 义务。

## syscap_define.h 规则（极其重要）

文件：`include/codec_config/syscap_define.h`

- 新增 SysCap 必须在 `SystemCapabilityNum` 枚举和 `g_arraySyscap` 数组的**末尾**添加。
- **切勿删除**或调整顺序。要废弃某个条目，在对应枚举值后注释 `// abandoned` 即可。
- `g_arraySyscap` 数组必须按枚举值从小到大排序（追加式维护）。

## 自定义/扩展 SysCap 配置

`config.gni` 声明两个构建参数：
- `syscap_codec_config_path` — syscap_define.h 的路径（默认使用仓库内文件）。
- `syscap_codec_config_extern_path` — 当设置为非空路径时，构建时触发 `tools/syscap_config_merge.py` 生成 `syscap_define_custom.h`，并定义 `-DSYSCAP_DEFINE_EXTERN_ENABLE` 宏。

## Taihe 代码生成（IDL 驱动）

`taihe/syscap/idl/ohos.systemCapability.taihe` 是新 JS/ETS API 的源文件。构建过程生成：
- `ohos.systemCapability.ani.cpp`、`ohos.systemCapability.abi.c`（通过 `ohos_taihe` 代码生成器）
- `@ohos.systemCapability.ets` → 编译为 `.abc`

生成文件位于 `$taihe_file_path/out/developtools/syscap_codec/` 下，**不纳入版本管理**。
手写实现文件在 `taihe/syscap/src/`（`.impl.cpp`、`ani_constructor.cpp`）负责桥接生成代码与 C 核心逻辑。

Taihe 目标仅在 `support_jsapi && is_standard_system` 时构建。

## 跨平台

目标宿主平台：Linux x86_64、Windows x86_64、Darwin x86_64。
- MinGW 构建需要 `_POSIX_` 宏。
- 字节序转换在 `src/endian_internal.c` 中处理。
- **macOS 二进制必须在 macOS 宿主上构建**（无法从 Ubuntu 交叉编译）。

## 验证

### 最小检查（任何改动后必跑）

1. **语法/导入**：
   - 改动的 `.c/.h`：`gcc -fsyntax-only -I include -I interfaces/inner_api <file>` 或 `cppcheck <file>`
   - 改动的 `.py`：`python3 -m py_compile <file>`（本仓无统一 linter 配置，至少保证可导入）
   - 改动的 `.cpp`（NAPI/Taihe）：`cppcheck <file>`
2. **GN 生成**：若改了 `BUILD.gn`/`config.gni`，在 OHOS 源码树根执行 `hb build --build-only-gn` 或 `./build.sh --product-name rk3568 --build-only-gn`，确认 `gn gen` 不报错。
3. **相关测试套**：按下方"任务→测试"选择至少一项。

### 完整构建环境（有 OHOS 源码树）

```bash
# 编译 CLI 工具
ninja -C out/default developtools/syscap_codec:syscap_tool_bin

# 编译共享库
ninja -C out/default developtools/syscap_codec:syscap_interface_shared

# 编译 NAPI 模块（需 support_jsapi）
ninja -C out/default developtools/syscap_codec/napi:systemcapability

# 编译 Taihe 模块（需 support_jsapi && is_standard_system）
ninja -C out/default developtools/syscap_codec/taihe:taihe_group

# 运行单元测试
ninja -C out/default developtools/syscap_codec/test/unittest/common:unittest
```

### 任务→测试

| 改动类型 | 验证命令 |
| --- | --- |
| `src/` 编解码逻辑 | `ninja -C out/default developtools/syscap_codec/test/unittest/common:unittest` 后跑产物 |
| `interfaces/inner_api/` 对外 API | 编译 `:syscap_interface_shared` + 跑 unittest + 确认 versionscript 符号未变 |
| `napi/` JS 绑定 | `ninja -C out/default developtools/syscap_codec/napi:systemcapability` |
| `taihe/syscap/` IDL | `ninja -C out/default developtools/syscap_codec/taihe:taihe_group`（需 `support_jsapi && is_standard_system`） |
| `include/codec_config/syscap_define.h` | `python3 tools/syscap_check.py -p <ohos_root> -t component_codec` |
| `tools/*.py` | `python3 -m py_compile tools/syscap_check.py` + 手动跑一次 `-h` |
| `BUILD.gn` / `config.gni` | `hb build --build-only-gn` 确认生成不报错 |

### 无构建环境（降级验证）

```bash
# 1. 一致性检查（需要 OHOS 源码树路径）
python3 tools/syscap_check.py -p <ohos_root> -t component_codec

# 2. 手动确认 syscap_define.h 规则
#    - 枚举值只增不减
#    - g_arraySyscap 与枚举顺序一致
#    - 废弃项有 // abandoned 注释

# 3. 手动确认 version script
#    - 已发布符号未被删除或改名
#    - 新增函数需要同步加入 global 段

# 4. 语法检查（无需 OHOS 源码树）
gcc -fsyntax-only -I include -I interfaces/inner_api src/syscap_tool.c
python3 -m py_compile tools/syscap_check.py
```

### Done 定义

任务完成须满足：
1. 上述"最小检查"全部通过，且按"任务→测试"跑了对应验证。
2. 未触碰任何"不可破坏"条目，或已获"修改前必须确认"的授权。
3. 未手改任何生成文件（Taihe 代码生成产物、`syscap_define_custom.h`）。
4. 若改了公共面（versionscript / `syscap_interface.h` 签名 / `syscap_define.h` 枚举 / `config.gni` 构建参数），已说明兼容性影响。

每次修改完成后自检：

- [ ] `syscap_define.h` 枚举和数组只追加未删除，废弃项已注释
- [ ] `libsyscap_interface_shared.versionscript` 已发布符号未变更（新增需确认）
- [ ] `interfaces/inner_api/syscap_interface.h` 已有函数签名未修改
- [ ] 生成文件未被手动编辑（Taihe 代码生成产物）
- [ ] `src/` 中通用代码的修改已考虑对所有 4 个目标的影响
- [ ] 测试目标路径和文件名正确
- [ ] 若涉及跨平台修改，已检查 MinGW / macOS 条件分支
- [ ] 若改了三方依赖，已同步更新 `OAT.xml`

### 验证无法运行时

若环境无法构建/测试（缺 OHOS 源码树、无 product、无 prebuilts），**不要**声称完成。改为：列出已尝试命令与失败原因，明确标注"未验证"，并给出在正确环境应运行的完整命令清单。

### 最终回复须包含

- 改了什么（文件 + 简述）。
- 跑了哪些验证命令 + 结果。
- 命中了哪些约束（引用本文件"不可破坏 / 修改前必须确认 / syscap_define.h 规则 / Taihe 代码生成"条目）。
- 兼容性影响评估（若触及公共面）。
- 若无法验证：说明哪些命令已尝试、为何无法运行、建议人工补验什么。

## CLI 用法参考

```
syscap_tool -R/P -e/d -i filepath [-o outpath]
  -R, --rpcid  -P, --pcid  -e, --encode  -d, --decode
  -s, --string  -C, --compare  -v, --version
```

## 依赖

cJSON、bounds_checking_function（libsec）、NAPI（ace_napi）、node 头文件、googletest（仅测试）。
