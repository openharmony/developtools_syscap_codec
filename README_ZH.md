# 系统能力编解码工具
系统能力(SystemCapability, 本文中使用SysCap缩写)编解码工具应用场景如下：

应用开发时，IDE会根据应用配置的SysCap和API版本生成描述RPCID(Required Product Compatibility ID)的json文件，并调用编解码工具syscap_tool将该json文件编码成RPCID。另一方面，IDE拿到开发者导入PCID(Product Compatibility ID)，使用该工具解码出设备的SysCap集合。该工具仅供IDE使用，对用户不可见。

提供的主要功能：

1. PCID编码：对描述SysCap集合的文件编码生成PCID。  

2. PCID解码：对编码后的PCID文件解码获取SysCap集合。

3. RPCID编码：对描述应用所需的SysCap集合的文件编码生成RPCID。

4. RPCID解码：对编码后的RPCID文件解码获取应用所需的SysCap集合。

5. 编码字符串：将sc后缀形式的PCID/RPCID编码为字符串形式。

6. PCID与RPCID比较：查询PCID是否满足RPCID的要求，并输出不满足的地方。

## 代码目录
```
/developtools
├── syscap_codec                 # syscap codec代码目录
│   ├── include                  # syscap_tool_shared对外接口定义
│   │   ├── syscap_define.h
│   │   └── syscap_tool.h         
│   ├── interfaces/inner_api     # 提供部件之间的接口
│   │   ├── syscap_interface.c
│   │   └── syscap_interface.h 
│   ├── napi                     # napi 接口实现
│   │   ├── BUILD.gn
│   │   ├── napi_query_syscap.cpp
│   │   └── syscap_interface.h 
│   ├── src
│   │   ├── endian_internel.h    # 内部实现的大小端转换接口定义(便于win、mac、linux平台通用)
│   │   ├── endian_internel.c    # 大小端转换实现
│   │   ├── main.c               # syscap_tool命令行工具代码实现 
│   │   └── syscap_tool.c        # syscap_tool编解码接口的实现
│   └── test 
│   │   ├── unittest/common      # inner 接口测试代码实现
│   │   │   ├── BUILD.gn
│   │   │   ├── include
│   │   │   │   └── syscap_codec_test.h
│   │   │   └── syscap_codec_test.cpp
│   │   └── syscap_tool_test.c   # syscap_tool功能测试代码实现
```

## API
PC端工具，不对外提供API。

## PC端编译说明  
syscap_tool PC端可执行文件编译步骤：
1. 编译命令：参考[编译构建](https://gitee.com/openharmony/build/blob/master/README_zh.md)文档，执行其指定的sdk编译命令来编译整个sdk，syscap_tool会被编译打包到里面。
2. 编译：在目标开发机上运行上面调整好的sdk编译命令，正常编译syscap_tool会输出到sdk平台相关目录下。

注意：ubuntu环境下只能编译windows/linux版本工具，mac版需要在macos开发机上编译。

## PC端获取说明
1. 下载sdk获取(建议)  
    通过访问本社区门禁[每日构建](http://ci.openharmony.cn/dailys/dailybuilds)网站，下载最新的ohos-sdk压缩包，并从相应平台的toolchains压缩包中提取syscap_tool。  
2. 支持运行环境  
    Windows x86_64/Linux x86_64/Darwin x86_64

## 命令帮助  
本工具一般被IDE、应用市场和包管理器集成，手工调试时可参考以下说明。

使用./syscap_tool -h或者./syscap_tool --help查看：
```shell
syscap_tool -R/P -e/d -i filepath [-o outpath]
-h, --help      : how to use
-R, --RPCID     : encode or decode RPCID
-P, --PCID      : encode or decode PCID
-C, --compare   : compare pcid with rpcid string format.
        -s, --string : input string.
-e, --encode    : encode to sc format.
        -s, --string : encode to string format.
-d, --decode    : decode to json format.
        -s, --string : decode string format.
-i filepath, --input filepath   : input file
-o outpath, --input outpath     : output path
-v, --version   : print syscap_tool version information.

syscap_tool v1.1.1
```
### 使用示例
```shell
# 将 RPCID.json 编码为SC格式，文件名RPCID.sc
syscap_tool -Rei RPCID.json -o path/

# 将 RPCID.sc 编码为JSON格式，文件名RPCID.json
syscap_tool -Rdi RPCID.sc -o path/

# 将 PCID.json 编码为SC格式，文件名PCID.sc
syscap_tool -Pei PCID.json -o path/

# 将 PCID.sc 编码为JSON格式，文件名PCID.json
syscap_tool -Pdi PCID.sc -o path/

# 将 RPCID.sc 编码为字符串格式，文件名RPCID.txt
syscap_tool -Resi RPCID.sc -o path/

# 将 PCID.sc 编码为字符串格式，文件名PCID.txt
syscap_tool -Pesi PCID.sc -o path/

# 比较字符串格式的PCID和RPCID，pcid 符合条件返回成功提示，不符合则提示原因。
syscap_tool -C pcid.txt rpcid.txt

# 功能类似 -C 选项，区别为 -SC 选项为直接输入字符串。
syscap_tool -sC "pcidstring" "rpcidstring"

# 将字符串格式的 pcid 转为 json 格式，文件名 PCID.json。
syscap_tool -Pdsi pcid.txt -o path/
```
**说明：**  -o 选项指定输出目录，缺省为当前目录。  

## Release Note
v1.1.0 2022-6-17 添加转字符串格式以及比较功能。  
v1.0.0 2022-3-8 首版本，提供Windows/Linux/Mac平台的系统能力编解码。