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

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <securec.h>
#include <limits.h>
#include "cJSON.h"
#include "syscap_tool.h"
#include "endian_internal.h"
#include "syscap_interface.h"
#include "context_tool.h"

#ifdef SYSCAP_DEFINE_EXTERN_ENABLE
#include "syscap_define_custom.h"
#else
#include "syscap_define.h"
#endif

#define OS_SYSCAP_BYTES 120
#define SYSCAP_PREFIX_LEN 17
#define SINGLE_FEAT_LEN (SINGLE_SYSCAP_LEN - SYSCAP_PREFIX_LEN)
#define RPCID_OUT_BUFFER 32
#define PCID_OUT_BUFFER RPCID_OUT_BUFFER
#define UINT8_BIT 8
#define INT_BIT 32
#define U32_TO_STR_MAX_LEN 11

typedef struct ProductCompatibilityID {
    uint16_t apiVersion : 15;
    uint16_t apiVersionType : 1;
    uint16_t systemType : 3;
    uint16_t reserved : 13;
    uint32_t manufacturerID;
    uint8_t osSyscap[OS_SYSCAP_BYTES];
} PCIDMain;

static const char *g_pcidPath = "/system/etc/PCID.sc";

bool EncodeOsSyscap(char *output, int len)
{
    int32_t ret;
    int32_t res;
    char *contextBuffer = NULL;
    uint32_t bufferLen;

    if (len != PCID_MAIN_BYTES) {
        PRINT_ERR("Os Syscap input len(%d) must be equal to 128.\n", len);
        return false;
    }

    ret = GetFileContext(g_pcidPath, &contextBuffer, &bufferLen);
    if (ret != 0) {
        PRINT_ERR("GetFileContext failed, input file : /system/etc/PCID.sc\n");
        return false;
    }

    res = memcpy_s(output, PCID_MAIN_BYTES, contextBuffer, PCID_MAIN_BYTES);
    if (res != 0) {
        PRINT_ERR("memcpy_s failed.");
        FreeContextBuffer(contextBuffer);
        return false;
    }

    FreeContextBuffer(contextBuffer);
    return true;
}

bool EncodePrivateSyscap(char **output, int *outputLen)
{
    int32_t ret;
    char *contextBuffer = NULL;
    char *outputStr = NULL;
    uint32_t bufferLen;

    ret = GetFileContext(g_pcidPath, &contextBuffer, &bufferLen);
    if (ret != 0) {
        PRINT_ERR("GetFileContext failed, input file : /system/etc/PCID.sc\n");
        return false;
    }

    uint32_t priLen = bufferLen - PCID_MAIN_BYTES - 1;
    if ((int)priLen <= 0) {
        *outputLen = 0;
        return false;
    }
    outputStr = (char *)calloc(priLen, sizeof(char));
    if (outputStr == NULL) {
        PRINT_ERR("malloc buffer failed, size = %u, errno = %d\n", priLen, errno);
        *outputLen = 0;
        return false;
    }

    ret = strncpy_s(outputStr, priLen, contextBuffer + PCID_MAIN_BYTES, priLen - 1);
    if (ret != 0) {
        PRINT_ERR("strcpy_s failed.");
        FreeContextBuffer(contextBuffer);
        free(outputStr);
        *outputLen = 0;
        return false;
    }

    FreeContextBuffer(contextBuffer);
    *outputLen = (int)strlen(outputStr);
    *output = outputStr;
    return true;
}

bool DecodeOsSyscap(const char input[PCID_MAIN_BYTES], char (**output)[SINGLE_SYSCAP_LEN], int *outputCnt)
{
    errno_t nRet = 0;
    uint16_t indexOfSyscap[CHAR_BIT * OS_SYSCAP_BYTES] = {0};
    uint16_t countOfSyscap = 0;
    uint16_t i, j;

    uint8_t *osSyscap = (uint8_t *)(input + 8); // 8, int[2] of pcid header

    for (i = 0; i < OS_SYSCAP_BYTES; i++) {
        for (j = 0; j < CHAR_BIT; j++) {
            if (osSyscap[i] & (0x01 << j)) {
                indexOfSyscap[countOfSyscap++] = i * CHAR_BIT + j;
            }
        }
    }

    *outputCnt = countOfSyscap;
    char (*strSyscap)[SINGLE_SYSCAP_LEN] = NULL;
    strSyscap = (char (*)[SINGLE_SYSCAP_LEN])malloc(countOfSyscap * SINGLE_SYSCAP_LEN);
    if (strSyscap == NULL) {
        PRINT_ERR("malloc failed.");
        *outputCnt = 0;
        return false;
    }
    (void)memset_s(strSyscap, countOfSyscap * SINGLE_SYSCAP_LEN, \
                   0, countOfSyscap * SINGLE_SYSCAP_LEN);
    *output = strSyscap;

    for (i = 0; i < countOfSyscap; i++) {
        for (j = 0; j < sizeof(g_arraySyscap) / sizeof(SyscapWithNum); j++) {
            if (g_arraySyscap[j].num == indexOfSyscap[i]) {
                nRet = strcpy_s(*strSyscap, SINGLE_SYSCAP_LEN, g_arraySyscap[j].str);
                if (nRet != EOK) {
                    printf("strcpy_s failed. error = %d\n", nRet);
                    *outputCnt = 0;
                    free(strSyscap);
                    strSyscap = NULL;
                    return false;
                }
                strSyscap++;
                break;
            }
        }
    }

    return true;
}

int32_t GetPriSyscapCount(char *input)
{
    int32_t syscapCnt = 0;

    char *inputPos = input;
    while (*inputPos != '\0') {
        if (*inputPos == ',') {
            syscapCnt++;
        }
        inputPos++;
    }

    return syscapCnt;
}

bool DecodePrivateSyscap(char *input, char (**output)[SINGLE_SYSCAP_LEN], int *outputCnt)
{
    char *inputPos = input;
    char (*outputArray)[SINGLE_SYSCAP_LEN] = NULL;

    if (input == NULL) {
        return false;
    }

    int syscapCnt = GetPriSyscapCount(inputPos);
    *outputCnt = syscapCnt;
    if (syscapCnt == 0) {
        return true;
    }

    int bufferLen = SINGLE_SYSCAP_LEN * syscapCnt;
    outputArray = (char (*)[SINGLE_SYSCAP_LEN])malloc(bufferLen);
    if (outputArray == NULL) {
        return false;
    }
    (void)memset_s(outputArray, bufferLen, 0, bufferLen);

    *output = outputArray;
    inputPos = input;
    char buffer[SINGLE_FEAT_LEN] = {0};
    char *bufferPos = buffer;
    while (*inputPos != '\0') {
        if (*inputPos == ',') {
            *bufferPos = '\0';
            if (sprintf_s(*outputArray, SINGLE_SYSCAP_LEN, "SystemCapability.%s", buffer) == -1) {
                free(outputArray);
                return false;
            }
            bufferPos = buffer;
            outputArray++;
            inputPos++;
            continue;
        }
        *bufferPos++ = *inputPos++;
    }

    return true;
}

static int SetOsSysCapBitMap(uint8_t *out, uint16_t outLen, const uint16_t *index, uint16_t indexLen)
{
    uint16_t sector, pos;

    if (outLen != OS_SYSCAP_BYTES) {
        PRINT_ERR("Input array error.\n");
        return -1;
    }

    for (uint16_t i = 0; i < indexLen; i++) {
        sector = index[i] / UINT8_BIT;
        pos = index[i] % UINT8_BIT;
        if (sector >= OS_SYSCAP_BYTES) {
            PRINT_ERR("Syscap num(%u) out of range(120).\n", sector);
            return -1;
        }
        out[sector] |=  (1 << pos);
    }
    return 0;
}

static int32_t ParseRpcidToJson(char *input, uint32_t inputLen, cJSON *rpcidJson)
{
    uint32_t i;
    int32_t ret = 0;
    uint16_t sysCapLength = NtohsInter(*(uint16_t *)(input + sizeof(uint32_t)));
    uint16_t sysCapCount = sysCapLength / SINGLE_FEAT_LEN;
    char *sysCapBegin = input + sizeof(RPCIDHead) + sizeof(uint32_t);
    RPCIDHead *rpcidHeader = (RPCIDHead *)input;
    cJSON *sysCapJson = cJSON_CreateArray();
    for (i = 0; i < sysCapCount; i++) {
        char *temp = sysCapBegin + i * SINGLE_FEAT_LEN;
        if (strlen(temp) >= SINGLE_FEAT_LEN) {
            PRINT_ERR("Get SysCap failed, string length too long.\n");
            ret = -1;
            goto FREE_SYSCAP_OUT;
        }
        char buffer[SINGLE_SYSCAP_LEN] = "SystemCapability.";

        ret = strncat_s(buffer, sizeof(buffer), temp, SINGLE_FEAT_LEN);
        if (ret != EOK) {
            PRINT_ERR("strncat_s failed.\n");
            goto FREE_SYSCAP_OUT;
        }

        if (!cJSON_AddItemToArray(sysCapJson, cJSON_CreateString(buffer))) {
            PRINT_ERR("Add syscap string to json failed.\n");
            ret = -1;
            goto FREE_SYSCAP_OUT;
        }
    }

    if (!cJSON_AddNumberToObject(rpcidJson, "api_version", NtohsInter(rpcidHeader->apiVersion))) {
        PRINT_ERR("Add api_version to json failed.\n");
        ret = -1;
        goto FREE_SYSCAP_OUT;
    }
    if (!cJSON_AddItemToObject(rpcidJson, "syscap", sysCapJson)) {
        PRINT_ERR("Add syscap to json failed.\n");
        ret = -1;
        goto FREE_SYSCAP_OUT;
    }

    return 0;
FREE_SYSCAP_OUT:
    cJSON_Delete(sysCapJson);
    return ret;
}

char *DecodeRpcidToStringFormat(const char *inputFile)
{
    int32_t ret = 0;
    int32_t sysCapArraySize;
    uint32_t bufferLen, i;
    uint16_t indexOs = 0;
    uint16_t indexPri = 0;
    uint16_t *osSysCapIndex;
    char *contextBuffer = NULL;
    char *priSyscapArray = NULL;
    char *priSyscap = NULL;
    char *outBuffer = NULL;
    cJSON *cJsonTemp = NULL;
    cJSON *rpcidRoot = NULL;
    cJSON *sysCapDefine = NULL;
    cJSON *sysCapArray = NULL;

    // check rpcid.sc
    if (CheckRpcidFormat(inputFile, &contextBuffer, &bufferLen)) {
        PRINT_ERR("Check rpcid.sc format failed. Input file: %s\n", inputFile);
        goto FREE_CONTEXT_OUT;
    }

    // parse rpcid to json
    rpcidRoot = cJSON_CreateObject();
    if (ParseRpcidToJson(contextBuffer, bufferLen, rpcidRoot)) {
        PRINT_ERR("Prase rpcid to json failed. Input file: %s\n", inputFile);
        goto FREE_RPCID_ROOT;
    }

    // trans to string format
    sysCapDefine =  CreateWholeSyscapJsonObj();
    sysCapArray = cJSON_GetObjectItem(rpcidRoot, "syscap");
    if (sysCapArray == NULL || !cJSON_IsArray(sysCapArray)) {
        PRINT_ERR("Get syscap failed. Input file: %s\n", inputFile);
        goto FREE_WHOLE_SYSCAP;
    }
    sysCapArraySize = cJSON_GetArraySize(sysCapArray);
    if (sysCapArraySize < 0) {
        PRINT_ERR("Get syscap size failed. Input file: %s\n", inputFile);
        goto FREE_WHOLE_SYSCAP;
    }
    // malloc for save os syscap index
    osSysCapIndex = (uint16_t *)malloc(sizeof(uint16_t) * sysCapArraySize);
    if (osSysCapIndex == NULL) {
        PRINT_ERR("malloc failed.\n");
        goto FREE_WHOLE_SYSCAP;
    }
    (void)memset_s(osSysCapIndex, sizeof(uint16_t) * sysCapArraySize,
                   0, sizeof(uint16_t) * sysCapArraySize);
    // malloc for save private syscap string
    priSyscapArray = (char *)malloc(sysCapArraySize * SINGLE_SYSCAP_LEN);
    if (priSyscapArray == NULL) {
        PRINT_ERR("malloc(%u) failed.\n", (uint32_t)sysCapArraySize * SINGLE_SYSCAP_LEN);
        goto FREE_MALLOC_OSSYSCAP;
    }
    (void)memset_s(priSyscapArray, sysCapArraySize * SINGLE_SYSCAP_LEN,
                   0, sysCapArraySize * SINGLE_SYSCAP_LEN);
    priSyscap = priSyscapArray;
    // part os syscap and ptivate syscap
    for (i = 0; i < (uint32_t)sysCapArraySize; i++) {
        cJSON *cJsonItem = cJSON_GetArrayItem(sysCapArray, i);
        cJsonTemp = cJSON_GetObjectItem(sysCapDefine, cJsonItem->valuestring);
        if (cJsonTemp != NULL) {
            osSysCapIndex[indexOs++] = (uint16_t)(cJsonTemp->valueint);
        } else {
            ret = strcpy_s(priSyscap, SINGLE_SYSCAP_LEN, cJsonItem->valuestring);
            if (ret != EOK) {
                PRINT_ERR("strcpy_s failed.\n");
                goto FREE_MALLOC_PRISYSCAP;
            }
            priSyscapArray += SINGLE_SYSCAP_LEN;
            indexPri++;
        }
    }
    uint32_t outUint[RPCID_OUT_BUFFER] = {0};
    outUint[0] = *(uint32_t *)contextBuffer;
    outUint[1] = *(uint32_t *)(contextBuffer + sizeof(uint32_t));
    uint8_t *osOutUint = (uint8_t *)(outUint + 2);
    if (SetOsSysCapBitMap(osOutUint, 120, osSysCapIndex, indexOs)) {  // 120, len of osOutUint
        PRINT_ERR("Set os syscap bit map failed.\n");
        goto FREE_MALLOC_PRISYSCAP;
    }

    uint16_t outBufferLen = U32_TO_STR_MAX_LEN * RPCID_OUT_BUFFER +
                            SINGLE_SYSCAP_LEN * indexPri;
    outBuffer = (char *)malloc(outBufferLen);
    if (outBuffer == NULL) {
        PRINT_ERR("malloc(%u) failed.\n", outBufferLen);
        goto FREE_MALLOC_PRISYSCAP;
    }
    (void)memset_s(outBuffer, outBufferLen, 0, outBufferLen);

    ret = sprintf_s(outBuffer, outBufferLen, "%u", outUint[0]);
    if (ret == -1) {
        PRINT_ERR("sprintf_s failed.\n");
        outBuffer = NULL;
        goto FREE_MALLOC_PRISYSCAP;
    }
    for (i = 1; i < RPCID_OUT_BUFFER; i++) {
        ret = sprintf_s(outBuffer, outBufferLen, "%s,%u", outBuffer, outUint[i]);
        if (ret == -1) {
            PRINT_ERR("sprintf_s failed.\n");
            outBuffer = NULL;
            goto FREE_MALLOC_PRISYSCAP;
        }
    }

    for (i = 0; i < indexPri; i++) {
        ret = sprintf_s(outBuffer, outBufferLen, "%s,%s", outBuffer,
                        priSyscapArray + i * SINGLE_SYSCAP_LEN);
        if (ret == -1) {
            PRINT_ERR("sprintf_s failed.\n");
            outBuffer = NULL;
            goto FREE_MALLOC_PRISYSCAP;
        }
    }

FREE_MALLOC_PRISYSCAP:
    free(priSyscap);
FREE_MALLOC_OSSYSCAP:
    free(osSysCapIndex);
FREE_WHOLE_SYSCAP:
    cJSON_Delete(sysCapDefine);
FREE_RPCID_ROOT:
    cJSON_Delete(rpcidRoot);
FREE_CONTEXT_OUT:
    FreeContextBuffer(contextBuffer);
    return outBuffer;
}

int32_t ComparePcidString(const char *pcidString, const char *rpcidString, CompareError *result)
{
    int32_t ret;
    uint16_t versionFlag = 0;
    uint16_t ossyscapFlag = 0;
    uint16_t prisyscapFlag = 0;
    char *pcidPriSyscap = NULL;
    char *rpcidPriSyscap = NULL;
    bool priSysFound;
    uint32_t pcidPriSyscapLen, rpcidPriSyscapLen;
    uint32_t i, j;
    uint32_t retFlag = 0;
    uint32_t pcidOsAarry[PCID_OUT_BUFFER] = {0};
    uint32_t rpcidOsAarry[PCID_OUT_BUFFER] = {0};
    const size_t allSyscapNum = sizeof(g_arraySyscap) / sizeof(SyscapWithNum);

    ret =  SeparateSyscapFromString(pcidString, pcidOsAarry, PCID_OUT_BUFFER,
                                    &pcidPriSyscap, &pcidPriSyscapLen);
    ret += SeparateSyscapFromString(rpcidString, rpcidOsAarry, RPCID_OUT_BUFFER,
                                    &rpcidPriSyscap, &rpcidPriSyscapLen);
    if (ret != 0) {
        PRINT_ERR("Separate syscap from string failed. ret = %d\n", ret);
        return -1;
    }
    result->missSyscapNum = 0;
    // compare version
    uint16_t pcidVersion = NtohsInter(((PCIDMain *)pcidOsAarry)->apiVersion);
    uint16_t rpcidVersion = NtohsInter(((RPCIDHead *)rpcidOsAarry)->apiVersion);
    if (pcidVersion < rpcidVersion) {
        result->targetApiVersion = rpcidVersion;
        versionFlag = 1;
    }
    // compare os sysscap
    for (i = 2; i < PCID_OUT_BUFFER; i++) { // 2, header of pcid & rpcid
        uint32_t blockBits = (pcidOsAarry[i] ^ rpcidOsAarry[i]) & rpcidOsAarry[i];
        if (!blockBits) {
            continue;
        }
        for (uint8_t k = 0; k < INT_BIT; k++) {
            if (blockBits & (1U << k)) {
                char *tempSyscap = (char *)malloc(sizeof(char) * SINGLE_SYSCAP_LEN);
                if (tempSyscap == NULL) {
                    PRINT_ERR("malloc failed.\n");
                    FreeCompareError(result);
                    return -1;
                }
                uint32_t pos = (i - 2) * INT_BIT + k;
                uint32_t t;
                for (t = 0; t < allSyscapNum; t++) {
                    if (g_arraySyscap[t].num == pos) {
                        break;
                    }
                }
                ret = strcpy_s(tempSyscap, sizeof(char) * SINGLE_SYSCAP_LEN,
                               g_arraySyscap[t].str); // 2, header of pcid & rpcid
                if (ret != EOK) {
                    PRINT_ERR("strcpy_s failed.\n");
                    FreeCompareError(result);
                    return -1;
                }
                result->syscap[ossyscapFlag++] = tempSyscap;
            }
        }
    }
    // compare pri syscap
    priSysFound = false;
    for (i = 0; i < rpcidPriSyscapLen; i++) {
        for (j = 0; j < pcidPriSyscapLen; j++) {
            if (strcmp(rpcidPriSyscap + SINGLE_SYSCAP_LEN * i,
                       pcidPriSyscap + SINGLE_SYSCAP_LEN * j) == 0) {
                priSysFound = true;
                break;
            }
        }
        if (priSysFound != true) {
            char *temp = (char *)malloc(sizeof(char) * SINGLE_SYSCAP_LEN);
            if (temp == NULL) {
                PRINT_ERR("malloc failed.\n");
                FreeCompareError(result);
                return -1;
            }
            ret = strcpy_s(temp, sizeof(char) * SINGLE_SYSCAP_LEN,
                           rpcidPriSyscap + SINGLE_SYSCAP_LEN * i);
            if (ret != EOK) {
                FreeCompareError(result);
                PRINT_ERR("strcpy_s failed.\n");
                return -1;
            }
            result->syscap[ossyscapFlag + prisyscapFlag] = temp;
            ++prisyscapFlag;
        }
        priSysFound = false;
    }

    if (versionFlag > 0) {
        retFlag |= 1U << 0;
    }
    if (ossyscapFlag > 0 || prisyscapFlag > 0) {
        retFlag |= 1U << 1;
        result->missSyscapNum = ossyscapFlag + prisyscapFlag;
    }
    return (int32_t)retFlag;
}

int32_t FreeCompareError(CompareError *result)
{
    if (result == NULL) {
        return 0;
    }
    for (int i = 0; i < result->missSyscapNum; i++) {
        free(result->syscap[i]);
        result->syscap[i] = NULL;
    }
    result->missSyscapNum = 0;
    result->targetApiVersion = 0;
    return 0;
}