/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "ohos.systemCapability.proj.hpp"
#include "ohos.systemCapability.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <securec.h>
#include "syscap_interface.h"
#include "context_tool.h"

using namespace taihe;

namespace {
// To be implemented.
constexpr size_t OS_SYSCAP_U32_NUM = 30;
constexpr size_t PCID_MAIN_U32 = OS_SYSCAP_U32_NUM + 2;
constexpr size_t U32_TO_STR_MAX_LEN = 11;
constexpr size_t KEY_BUFFER_SIZE = 32;

struct SystemCapabilityAsyncContext {
    char key[KEY_BUFFER_SIZE] = { 0 };
    size_t keyLen = 0;
    char *value = nullptr;
    size_t valueLen = 0;
    int status = 0;
};

static char* CalculateAllStringLength(char osCapArray[PCID_MAIN_U32][U32_TO_STR_MAX_LEN],
    char (*priCapArray)[SINGLE_SYSCAP_LEN], bool retBool, int priCapArrayCnt)
{
    errno_t err = EOK;
    char *temp = nullptr;
    int retError;
    int sumLen = 0;
    char *allSyscapBuffer = nullptr;

    if (!retBool) {
        PRINT_ERR("get encoded private syscap failed.");
        return allSyscapBuffer;
    }

    for (size_t i = 0; i < PCID_MAIN_U32; i++) {
        sumLen += strlen(osCapArray[i]);
    }
    for (int i = 0; i < priCapArrayCnt; i++) {
        sumLen += strlen(*(priCapArray + i));
    }
    sumLen += (PCID_MAIN_U32 + priCapArrayCnt + 1);  // split with ','

    // splicing string
    allSyscapBuffer = (char *)malloc(sumLen);
    if (allSyscapBuffer == nullptr) {
        PRINT_ERR("malloc failed!");
        return allSyscapBuffer;
    }
    err = memset_s(allSyscapBuffer, sumLen, 0, sumLen);
    if (err != EOK) {
        PRINT_ERR("memset failed!");
        free(allSyscapBuffer);
        return nullptr;
    }
    temp = *osCapArray;

    for (size_t i = 1; i < PCID_MAIN_U32; i++) {
        retError = sprintf_s(allSyscapBuffer, sumLen, "%s,%s", temp, osCapArray[i]);
        if (retError == -1) {
            PRINT_ERR("splicing os syscap string failed.");
            free(allSyscapBuffer);
            return nullptr;
        }
        temp = allSyscapBuffer;
    }
    for (int i = 0; i < priCapArrayCnt; i++) {
        retError = sprintf_s(allSyscapBuffer, sumLen, "%s,%s", temp, *(priCapArray + i));
        if (retError == -1) {
            PRINT_ERR("splicing pri syscap string failed.");
            free(allSyscapBuffer);
            return nullptr;
        }
        temp = allSyscapBuffer;
    }
    return allSyscapBuffer;
}

static char* GetSystemCapability()
{
    bool retBool;
    int retError;
    int priOutputLen;
    int priCapArrayCnt;
    char osOutput[SINGLE_SYSCAP_LEN] = {};

    uint32_t *osCapU32 = nullptr;
    char *priOutput = nullptr;

    char *allSyscapBuffer = nullptr;
    char osCapArray[PCID_MAIN_U32][U32_TO_STR_MAX_LEN] = {};
    char (*priCapArray)[SINGLE_SYSCAP_LEN] = nullptr;

    retBool = EncodeOsSyscap(osOutput, PCID_MAIN_BYTES);
    if (!retBool) {
        PRINT_ERR("get encoded os syscap failed.");
        return nullptr;
    }
    retBool = EncodePrivateSyscap(&priOutput, &priOutputLen);
    if (!retBool) {
        PRINT_ERR("get encoded private syscap failed.");
        goto FREE_PRIOUTPUT;
    }

    osCapU32 = reinterpret_cast<uint32_t *>(osOutput);
    for (size_t i = 0; i < PCID_MAIN_U32; i++) { // 2, header of pcid.sc
        retError = sprintf_s(osCapArray[i], U32_TO_STR_MAX_LEN, "%u", osCapU32[i]);
        if (retError == -1) {
            PRINT_ERR("get uint32_t syscap string failed.");
            goto FREE_PRIOUTPUT;
        }
    }
    retBool = DecodePrivateSyscap(priOutput, &priCapArray, &priCapArrayCnt);
    allSyscapBuffer = CalculateAllStringLength(osCapArray, priCapArray, retBool, priCapArrayCnt);
    free(priCapArray);

FREE_PRIOUTPUT:
    free(priOutput);

    return allSyscapBuffer;
}

string querySystemCapabilitie()
{
    SystemCapabilityAsyncContext *asyncContext = new SystemCapabilityAsyncContext();
    char *syscapStr = GetSystemCapability();
    if (syscapStr != nullptr) {
        asyncContext->value = syscapStr;
        asyncContext->status = 0;
    } else {
        asyncContext->status = 1;
    }
    string value = "";
    if (!asyncContext->status) {
        value = asyncContext->value;
    } else {
        taihe::set_business_error(-1, "key does not exist");
    }
    return value;
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_querySystemCapabilitie(querySystemCapabilitie);
// NOLINTEND
