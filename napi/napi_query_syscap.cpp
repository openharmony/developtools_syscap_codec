/*
 * Copyright (C) 2022-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstring>
#include <unistd.h>
#include <securec.h>
#include <cstdint>
#include "hilog/log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "syscap_interface.h"

namespace OHOS {
EXTERN_C_START
const int OS_SYSCAP_U32_NUM = 30;
const int U32_TO_STR_MAX_LEN = 11;
const int SYSCAP_STR_MAX_LEN = 128;

#define PRINT_ERR(...) \
    do { \
        printf("ERROR: in file %s at line %d -> ", __FILE__, __LINE__); \
        printf(__VA_ARGS__); \
    } while (0)

napi_value QuerySystemCapability(napi_env env, napi_callback_info info)
{
    bool retBool;
    int retError, priOutputLen, priCapArrayCnt, sumLen;
    int i = 0;
    int *osOutput = nullptr;
    uint32_t *osCapU32 = nullptr;
    char *priOutput = nullptr;
    char *temp = nullptr;
    char *allSyscapBUffer = nullptr;
    char osCapArray[OS_SYSCAP_U32_NUM][U32_TO_STR_MAX_LEN] = {};
    char (*priCapArray)[SYSCAP_STR_MAX_LEN] = nullptr;
    napi_status ret = napi_ok;
    napi_value result = nullptr;

    (void)info;

    retBool = EncodeOsSyscap(&osOutput);
    if (!retBool) {
        PRINT_ERR("get encoded os syscap failed.");
        result = nullptr;
        goto FREE_OSOUTPUT;
    }
    retBool = EncodePrivateSyscap(&priOutput, &priOutputLen);
    if (!retBool) {
        PRINT_ERR("get encoded private syscap failed.");
        result = nullptr;
        goto FREE_PRIOUTPUT;
    }

    osCapU32 = reinterpret_cast<uint32_t *>(osOutput + 2);  // 2, header of pcid.sc
    for (i = 0; i < OS_SYSCAP_U32_NUM; i++) {
        retError = sprintf_s(osCapArray[i], U32_TO_STR_MAX_LEN, "%u", osCapU32[i]);
        if (retError == -1) {
            PRINT_ERR("get uint32_t syscap string failed.");
            result = nullptr;
            goto FREE_PRIOUTPUT;
        }
    }

    retBool = DecodePrivateSyscap(priOutput, &priCapArray, &priCapArrayCnt);
    if (!retBool) {
        PRINT_ERR("get encoded private syscap failed.");
        result = nullptr;
        goto FREE_PRICAP_ARRAY;
    }

    // calculate all string length
    sumLen = 0;
    for (i = 0; i < OS_SYSCAP_U32_NUM; i++) {
        sumLen += strlen(osCapArray[i]);
    }
    for (i = 0; i < priCapArrayCnt; i++) {
        sumLen += strlen(*(priCapArray + i));
    }
    sumLen += (OS_SYSCAP_U32_NUM + priCapArrayCnt + 1);  // split with ','

    // splicing string
    allSyscapBUffer = (char *)malloc(sumLen);
    if (allSyscapBUffer ==nullptr) {
        PRINT_ERR("malloc failed!");
        result = nullptr;
        goto FREE_PRICAP_ARRAY;
    }
    (void)memset_s(allSyscapBUffer, sumLen, 0, sumLen);
    temp = *osCapArray;

    for (i = 1; i < OS_SYSCAP_U32_NUM; i++) {
        retError = sprintf_s(allSyscapBUffer, sumLen, "%s,%s", temp, osCapArray[i]);
        if (retError == -1) {
            PRINT_ERR("splicing os syscap string failed.");
            result = nullptr;
            goto FREE_PRICAP_ARRAY;
        }
        temp = allSyscapBUffer;
    }
    for (i = 0; i < priCapArrayCnt; i++) {
        retError = sprintf_s(allSyscapBUffer, sumLen, "%s,%s", temp, *(priCapArray + i));
        if (retError == -1) {
            PRINT_ERR("splicing pri syscap string failed.");
            result = nullptr;
            goto FREE_PRICAP_ARRAY;
        }
        temp = allSyscapBUffer;
    }
    ret = napi_create_string_utf8(env, allSyscapBUffer, sumLen, &result);
    if (ret != napi_ok) {
        result = nullptr;
        goto FREE_ALL_SYSCAP_BUFFER;
    }
    
FREE_ALL_SYSCAP_BUFFER:
    free(allSyscapBUffer);
FREE_PRICAP_ARRAY:
    free(priCapArray);
FREE_PRIOUTPUT:
    free(priOutput);
FREE_OSOUTPUT:
    free(osOutput);
    temp = nullptr;

    return result;
}

napi_value QuerryExport(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("querySystemCapabilities", QuerySystemCapability),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}
EXTERN_C_END
/*
 * Module define
 */
static napi_module systemCapabilityModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = QuerryExport,
    .nm_modname = "systemCapability",
    .nm_priv = ((void*)0),
    .reserved = {0},
};

/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void systemCapabilityRegisterModule(void)
{
    napi_module_register(&systemCapabilityModule);
}
}