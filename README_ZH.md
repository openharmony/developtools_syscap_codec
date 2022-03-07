# 系统能力编解码工具

系统能力(SystemCapability, 本文中使用SysCap缩写)编解码工具的应用场景：

1.应用开发时，IDE会根据应用配置的Syscap和API版本生成描述RPCID的json文件，并调用编解码工具syscap_tool将该json文件编码成RPCID。另一方面，IDE拿到开发者导入PCID，使用该工具解码出设备的Syscap集合。该工具仅供IDE使用，对用户不可见。

2.应用分发时，应用市场调用该编解码工具syscap_tool,对应用的RPCID解码获得应用所需的Syscap集合。另一方面，对设备的PCID进行解码，获取系统的Syscap集合。


## 架构

SysCap编解码工具提供的主要功能：

1.PCID编码：对描述系统能力集合的文件编码生成PCID。

2.PCID解码：对编码后的PCID文件解码获取系统能力集合。

3.RPCID编码：对描述应用所需的系统能力集合的文件编码生成RPCID。

4.RPCID解码：对编码后的RPCID文件解码获取应用所需的系统能力集合。

## 目录

```
/developtools
├── syscap_codec                 # syscap codec代码目录
│   ├── include
│   │   └── syscap_tool.h        # syscap_tool_shared对外接口定义  
│   └── src
│   │   ├── endian_internel.h    # 内部实现的大小端转换接口定义(便于win、mac、linux平台通用)
│   │   ├── endian_internel.c    # 大小端转换实现
│   │   ├── main.c               # syscap_tool命令行工具代码实现 
│   │   └── syscap_tool.c        # syscap_tool编解码接口的实现
│   └── test 
│       └── syscap_tool_test.c   # syscap_tool功能测试代码实现
```

### API

PC端工具，不对外提供API。

### pc端编译说明


syscap_tool pc端可执行文件编译步骤：

1. 编译命令：编译sdk命令 请参考https://gitee.com/openharmony/build/blob/master/README_zh.md 仓编译sdk说明， 执行其指定的sdk编译命令来编译整个sdk， syscap_tool会被编译打包到里面。

2. 编译：在目标开发机上运行上面调整好的sdk编译命令， 正常编译syscap_tool会输出到sdk平台相关目录下； 注意： ubuntu环境下只能编译windows/linux版本工具，mac版需要在macos开发机上编译。

### pc端获取说明

[1.下载sdk获取(建议)](#section161941989591)

通过访问本社区网站下载dailybuilds或正式发布的sdk压缩包，从中根据自己平台到相应的目录toolchain下解压提取。


[2.自行编译](#section161941989592)

编译请参考上面单独小节，本项目仓prebuilt目录下不再提供预制。

[3.支持运行环境](#section161941989593)

Windows x86_64/Linux x86_64/Darwin x86_64 

### 命令帮助

本工具一般被IDE、应用市场和包管理器集成，手工调试时可参考以下说明。

使用./syscap_tool -h或者./syscap_tool --help查看：
```
./syscap_tool -R/P -e/d -i filepath [-o outpath]

-h, --help : how to use

-R, --RPCID : encode or decode RPCID

-P, --PCID : encode or decode PCID

-e, --encode : to encode

-d, --encode : to decode

-i filepath, --input filepath : input file

-o outpath, --input outpath : output path
```

### Release Note

v1.0.0 2022-3-8 首版本，提供Windows/Linux/Mac平台的系统能力编解码。