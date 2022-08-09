# System Capability Encoder and Decoder Tools

SysCap(SystemCapability) encoder and decoder tools common usage scenarios as follow：

APP development: IDE collect APP required SysCap and API verssion as in RPCID encoder input. And IDE will decode PCID to device SysCap list when it imported. This tool is only for use by the IDE, developers will not be used directly.

Main function：

1. PCID Encode: Encode SysCap list to PCID.

2. PCID Decode: Decode PCID to get system SysCap list.

3. RPCID Encode: Encode APP required SysCap list to RPCID.

4. RPCID Decode: Decode RPCID to get APP required SysCap list.

## File Structure

```
/developtools
├── syscap_codec                 # root directory
│   ├── include
│   │   └── syscap_tool.h        # interfaces
│   └── src
│   │   ├── endian_internel.h    # internal big/little endian conversion headers(common for win、mac、linux)
│   │   ├── endian_internel.c    # big/little endian conversion implement
│   │   ├── main.c               # command line implement
│   │   └── syscap_tool.c        # codec implement
│   └── test 
│   |   └── syscap_tool_test.c   # syscap_tool test codec implement
|   |—— tools
|   │   │
|   │   └── syscap_check.py      # syscap一致性检查脚本
```

### API

PC tools, no API provided.

### Building Manually

syscap_tool binary building steps as follow：

1. Build commands：SysCap tools binary building and installation will be tiggered by SDK compiling procedure. How to build SDK please refer to https://gitee.com/openharmony/build/blob/master/README_zh.md.

2. Building cmd should be adjust for host platform as same as SDK compiling, the archive will in corresponding platform directoty.

Note: Ubuntu host only avaiable for windows/linux building, MacOs binary should building on MacOs host.

### Downloading Binary

1. Downlaod SDK(recommonded)

Download daily builds(http://ci.openharmony.cn/dailybuilds) which included SDK.

2. Supported Host

Windows x86_64/Linux x86_64/Darwin x86_64

### Help

SysCap tools usually integrate to IDE, APP store and bundle tools. Follow instructions for debugging manually:

./syscap_tool -h or ./syscap_tool --help：
```
./syscap_tool --help

./syscap_tool -R/P -e/d -i filepath [-o outpath]

-h, --help : how to use

-R, --RPCID : encode or decode RPCID

-P, --PCID : encode or decode PCID

-e, --encode : to encode

-d, --encode : to decode

-i filepath, --input filepath : input file

-o outpath, --input outpath : output path
```

## Syscap consistency check tool

### Functions and dependencies

The tool provides the following functions:

1. Collect syscap fields of all components (or specified components), compare them with arraySyscap in developtools/ syscap_codec/include/syscap_define.h, and output the check results. If they are inconsistent, output the cause of the discrepancy.
2. Collect the syscap fields of all components and compare them with the @syscap property set in *.d.ts in the Interface/sdk-js/api directory. If the check results are inconsistent, output the cause of the inconsistency.
3. Compare syscap attributes in *.d.ts in all interface/ sdK-JS/API directories with arraySyscap in developtools/syscap_codec/include/syscap_define.h. If they are inconsistent,  output the cause of the inconsistency.

### How to use it

This tool is written in Python language and needs to be executed using the Python interpreter.

requirements：

```txt
prettytable==3.3.0
```

usage：

```shell
# check syscap field in all components for consistency with arraySyscap in syscap_define.h
python3 syscap_check.py -p path_of_openarmony -t component_codec

# check that the SYSCAP field in bundle.json of the specified part is consistent with arraySyscap in syscap_define.h. Note： --bundles is valid only if --check_target is component_codec
python3 syscap_check.py -p path_of_openarmony -t component_codec -b path_of_component1/bundle.json path_of_component2/bundle.json

# check the consistency of the syscap field of all components with the "@syscap" property set in *.d.ts
python3 syscap_check.py -p path_of_openarmony -t component_sdk

# check the "@syscap" attribute set in *.d.ts for consistency with arraSyscap in syscap_define.h
python3 syscap_check.py -p path_of_openarmony -t sdk_codec
```

### Release Note

v1.0.0 2022-3-8 first release, SysCap codec supported for Windows/Linux/Mac host.
