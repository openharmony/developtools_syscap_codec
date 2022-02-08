# SysCap编解码工具<a name="ZH-CN_TOPIC_0000001149090043"></a>

- [SysCap编解码工具<a name="ZH-CN_TOPIC_0000001149090043"></a>](#)
  - [简介<a name="section662115419449"></a>](#简介)
  - [架构<a name="section15908143623714"></a>](#架构)
  - [目录<a name="section161941989596"></a>](#目录)
    - [pc端编译说明<a name="section129654513262"></a>](#pc端编译说明)
    - [pc端获取说明<a name="section129654513263"></a>](#pc端获取说明)
    - [命令帮助<a name="section129654513265"></a>](#命令帮助)

## 简介<a name="section662115419449"></a>

SysCap编解码工具的应用场景：

1.设备开发时，设备厂商对OS不见进行拼装后，编译构建生成Syscap列表，厂商ID和API版本信息作为Syscap编解码工具的输入，生成PCID。

2.应用开发时，IDE根据应用配置的Syscap和API版本生成RPCID。开发者导入PCID时，使用Syscap编解码工具解码出设备的Syscap集合。

3.应用分发时，应用市场使用Syscap工具对应用RPCID和设备的PCID进行解码。

4.应用安装时，包管理使用Syscap工具解码应用需要的Syscap集合。

## 架构<a name="section15908143623714"></a>

SysCap编解码工具主要有两部分组成：

1. syscap_tool部分：运用于应用开发场景，供IDE使用，用于编码生成RPCID和解码PCID

2. syscap_tool_shared部分：用于设备开发、应用安装等场景，完成RPCID和PCID的编解码。

## 目录<a name="section161941989596"></a>

```
/developtools
├── syscap_codec                 # syscap codec代码目录
│   ├── include
│   │   └── syscap_tool.h        # syscap_tool_shared对外接口定义  
│   └── src
│       ├── endian_internel.h    # 内部实现的大小端转换接口定义(便于win、mac、linux平台通用)
│       ├── endian_internel.c    # 大小端转换实现
│       ├── main.c               # syscap_tool命令行工具代码实现 
│       └── syscap_tool.c        # syscap_tool编解码接口的实现
```

### pc端编译说明<a name="section129654513262"></a>


syscap_tool pc端可执行文件编译步骤：

1. 编译命令：编译sdk命令 请参考https://gitee.com/openharmony/build/blob/master/README_zh.md 仓编译sdk说明， 执行其指定的sdk编译命令来编译整个sdk， syscap_tool会被编译打包到里面。

2. 编译：在目标开发机上运行上面调整好的sdk编译命令， 正常编译syscap_tool会输出到sdk平台相关目录下； 注意： ubuntu环境下只能编译windows/linux版本工具，mac版需要在macos开发机上编译。

### pc端获取说明<a name="section129654513263"></a>

[1.下载sdk获取(建议)](#section161941989591)
```
通过访问本社区网站下载dailybuilds或正式发布的sdk压缩包，从中根据自己平台到相应的目录toolchain下解压提取
```

[2.自行编译](#section161941989592)

编译请参考上面单独小节，本项目仓prebuilt目录下不再提供预制


[3.支持运行环境](#section161941989593)

linux版本建议ubuntu 18.04以上 64位，其他相近版本也可。

### 命令帮助<a name="section129654513265"></a>

使用./syscap_tool -h或者./syscap_tool --help查看：

./syscap_tool -R/P -e/d -i filepath [-o outpath]

-h, --help : how to use

-R, --RPCID : encode or decode RPCID

-P, --PCID : encode or decode PCID

-e, --encode : to encode

-d, --encode : to decode

-i filepath, --input filepath : input file

-o outpath, --input outpath : output path

