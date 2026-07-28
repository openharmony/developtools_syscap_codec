# AGENTS.md — syscap_codec

OpenHarmony 系统能力（SysCap）编解码工具。产物包括 `syscap_tool`（CLI 二进制）和 `syscap_interface_shared`（供其他部件使用的共享库）。

## 构建系统

- **GN** 构建系统（非 CMake/Make）。依赖完整的 OpenHarmony 构建树。
- 根构建文件：`BUILD.gn`、`config.gni`。
- 使用 `ohos_executable`、`ohos_shared_library`、`ohos_unittest` 等模板定义目标。
- **无法独立编译** — 本仓库位于 OHOS 源码树的 `developtools/syscap_codec` 路径下。

## 关键目标及产物

| 目标 | 产物 | 用途 |
|---|---|---|
| `syscap_tool_bin` | `syscap_tool` | pcid/rpcid 编码、解码、比较的 CLI 工具 |
| `syscap_interface_shared` | `.so` 共享库 | 供其他 OHOS 部件调用的内部 API |
| `napi:systemcapability` | `.so` 模块 | 设备侧 JS API（`@ohos.systemCapability`） |
| `taihe/syscap:systemCapability_taihe_native` | `.so` + `.abc` | 新式 Taihe API（从 `.taihe` IDL 代码生成） |

## 目录结构

```
src/           — 核心编解码逻辑（C 语言）。所有目标共用。
  syscap_tool.c, create_pcid.c, endian_internal.c, context_tool.c, common_method.c, main.c
include/       — CLI 工具的对头文件。
  syscap_tool.h, create_pcid.h, context_tool.h
  codec_config/syscap_define.h  — 所有 SysCap 的主列表（枚举 + 字符串数组）
interfaces/inner_api/ — 共享库消费者的内部 API。
napi/          — NAPI JS 绑定（C++ → JS）。
taihe/syscap/  — 新式 Taihe IDL 驱动 API（从 .taihe 文件代码生成，C++ → ETS）。
tools/         — 一致性检查和配置合并的 Python 脚本。
```

**注意**：同一套 `src/*.c` 源文件被重复编译到每一个目标中 — 内部不存在静态库。

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

## 测试

唯一测试目标：`//developtools/syscap_codec/test/unittest/common:unittest`
- 基于 gtest（googletest）。
- 测试文件：`test/unittest/common/syscap_codec_test.cpp`。
- 需要完整 OHOS 构建系统才能编译运行。

## Python 工具

```
pip install -r tools/requirements.txt   # prettytable==3.3.0
```

- `tools/syscap_check.py` — 一致性检查（部件 vs syscap_define.h vs .d.ts 文件）。
- `tools/syscap_config_merge.py` — 构建时合并基础 + 扩展 syscap 配置（由 GN action 调用）。

## 跨平台

目标宿主平台：Linux x86_64、Windows x86_64、Darwin x86_64。
- MinGW 构建需要 `_POSIX_` 宏。
- 字节序转换在 `src/endian_internal.c` 中处理。
- **macOS 二进制必须在 macOS 宿主上构建**（无法从 Ubuntu 交叉编译）。

## CLI 用法参考

```
syscap_tool -R/P -e/d -i filepath [-o outpath]
  -R, --rpcid  -P, --pcid  -e, --encode  -d, --decode
  -s, --string  -C, --compare  -v, --version
```

## 依赖

cJSON、bounds_checking_function（libsec）、NAPI（ace_napi）、node 头文件、googletest（仅测试）。
