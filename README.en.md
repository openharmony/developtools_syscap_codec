# System Capability Encoder and Decoder Tools

SysCap(SystemCapability) encoder and decoder tools common usage scenarios as follow：

1.Device development: After deivce developer assembling components completed, building system will generate SysCap list and collect vendor ID, API version as PCID encoder inputs.

2.APP development: IDE collect APP required SysCap and API verssion as in RPCID encoder input. And IDE will decode PCID to device SysCap list when it imported.

3.APP distribution: RPCID/PCID decoder used for APP distribution procedure, APP store will check whether device's SysCap satisfy APP required SysCap.

4.APP installation: Bundle tools used RPCID decoder to decode APP required SysCap list.

## Architecture

SysCap codec tools has two components：

1. syscap_tool：Binary used for APP developing, IDE invoker RPCID encoder and PCID decoder when APP compiling and PCID importing.

2. syscap_tool_shared：Shared library used for device developing and APP installing.

## File Structure

```
/developtools
├── syscap_codec                 # root directory
│   ├── include
│   │   └── syscap_tool.h        # interfaces
│   └── src
│       ├── endian_internel.h    # internal big/little endian conversion headers(common for win、mac、linux)
│       ├── endian_internel.c    # big/little endian conversion implement
│       ├── main.c               # command line implement
│       └── syscap_tool.c        # codec implement
```

### API

PC tools, no API provided.

### Building Manually

syscap_tool binary building steps as follow：

1. Build commands：SysCap tools binary building and installation will be tiggered by SDK compiling procedure. How to build SDK please refer to https://gitee.com/openharmony/build/blob/master/README_zh.md.

2. Building cmd should be adjust for host platform as same as SDK compiling, the archive will in corresponding platform directoty. Note: Ubuntu host only avaiable for windows/linux building, MacOs binary should building on MacOs host.

### Downloading Binary

[1.Downlaod SDK(recommonded))]

Download daily builds(http://ci.openharmony.cn/dailybuilds) which included SDK.

[3.Supported Host]

Windows x86_64/Linux x86_64/Darwin x86_64

### Help

SysCap tools usually integrate to IDE, APP store and bundle tools. Follow instructions for debugging manually:

./syscap_tool -h or ./syscap_tool --help：

./syscap_tool -R/P -e/d -i filepath [-o outpath]

-h, --help : how to use

-R, --RPCID : encode or decode RPCID

-P, --PCID : encode or decode PCID

-e, --encode : to encode

-d, --encode : to decode

-i filepath, --input filepath : input file

-o outpath, --input outpath : output path

### Release Note

v1.0.0 2022-3-8 first release, SysCap codec supported for Windows/Linux/Mac host.