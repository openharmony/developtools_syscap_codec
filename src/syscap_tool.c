/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include "securec.h"
#include "endian_internal.h"
#include "cJSON.h"
#include "syscap_define.h"
#include "create_pcid.h"
#include "syscap_tool.h"

typedef struct RequiredProductCompatibilityIDHead {
    uint16_t apiVersion : 15;
    uint16_t apiVersionType : 1;
} RPCIDHead;

#define SYSCAP_PREFIX_LEN 17
#define SINGLE_FEAT_LEN (SINGLE_SYSCAP_LEN - SYSCAP_PREFIX_LEN)
#define UINT8_BIT 8
#define INT_BIT 32
#define RPCID_OUT_BUFFER 32
#define PCID_OUT_BUFFER RPCID_OUT_BUFFER
#define BYTES_OF_OS_SYSCAP 120
#define U32_TO_STR_MAX_LEN 11
#define STRING_FORMAT_LEN_MAX 1024

#define PRINT_ERR(...) \
    do { \
        printf("ERROR: [%s: %d] -> ", __FILE__, __LINE__); \
        printf(__VA_ARGS__); \
    } while (0)

static void FreeContextBuffer(char *contextBuffer)
{
    (void)free(contextBuffer);
}

static int32_t GetFileContext(char *inputFile, char **contextBufPtr, uint32_t *bufferLen)
{
    int32_t ret;
    FILE *fp = NULL;
    struct stat statBuf;
    char *contextBuffer = NULL;
    char path[PATH_MAX + 1] = {0x00};

#ifdef _POSIX_
    if (strlen(inputFile) > PATH_MAX || strncpy_s(path, PATH_MAX, inputFile, strlen(inputFile)) != EOK) {
        PRINT_ERR("get path(%s) failed\n", inputFile);
        return -1;
    }
#else
    if (strlen(inputFile) > PATH_MAX || realpath(inputFile, path) == NULL) {
        PRINT_ERR("get file(%s) real path failed\n", inputFile);
        return -1;
    }
#endif

    ret = stat(path, &statBuf);
    if (ret != 0) {
        PRINT_ERR("get file(%s) st_mode failed, errno = %d\n", path, errno);
        return -1;
    }
    if (!(statBuf.st_mode & S_IRUSR)) {
        PRINT_ERR("don't have permission to read the file(%s)\n", path);
        return -1;
    }
    contextBuffer = (char *)malloc(statBuf.st_size + 1);
    if (contextBuffer == NULL) {
        PRINT_ERR("malloc buffer failed, size = %d, errno = %d\n", (int32_t)statBuf.st_size + 1, errno);
        return -1;
    }
    fp = fopen(path, "rb");
    if (fp == NULL) {
        PRINT_ERR("open file(%s) failed, errno = %d\n", path, errno);
        FreeContextBuffer(contextBuffer);
        return -1;
    }
    size_t retFread = fread(contextBuffer, statBuf.st_size, 1, fp);
    if (retFread != 1) {
        PRINT_ERR("read file(%s) failed, errno = %d\n", path, errno);
        FreeContextBuffer(contextBuffer);
        (void)fclose(fp);
        return -1;
    }
    contextBuffer[statBuf.st_size] = '\0';
    (void)fclose(fp);

    *contextBufPtr = contextBuffer;
    *bufferLen = statBuf.st_size + 1;
    return 0;
}

static int32_t ConvertedContextSaveAsFile(char *outDirPath, const char *filename,
                                          char *convertedBuffer, size_t bufferLen)
{
    int32_t ret;
    FILE *fp = NULL;
    char path[PATH_MAX + 1] = {0x00};

#ifdef _POSIX_
    if (strlen(outDirPath) >= PATH_MAX || strncpy_s(path, PATH_MAX, outDirPath, strlen(outDirPath)) != EOK) {
        PRINT_ERR("get path(%s) failed\n", outDirPath);
        return -1;
    }
#else
    if (strlen(outDirPath) >= PATH_MAX || realpath(outDirPath, path) == NULL) {
        PRINT_ERR("get file(%s) real path failed\n", outDirPath);
        return -1;
    }
#endif

    int32_t pathLen = strlen(path);
    if (path[pathLen - 1] != '/' && path[pathLen - 1] != '\\') {
        path[pathLen] = '/';
    }

    if (strlen(filename) + 1 > PATH_MAX) {
        PRINT_ERR("filename(%s) too long.\n", filename);
        return -1;
    }
    ret = strncat_s(path, PATH_MAX, filename, strlen(filename));
    if (ret != 0) {
        PRINT_ERR("strncat_s failed, (%s, %d, %s, %d), errno = %d\n",
                  path, PATH_MAX, filename, (int32_t)strlen(filename) + 1, errno);
        return -1;
    }

    fp = fopen(path, "wb");
    if (fp == NULL) {
        PRINT_ERR("can`t create file(%s), errno = %d\n", path, errno);
        return -1;
    }

    size_t retFwrite = fwrite(convertedBuffer, bufferLen, 1, fp);
    if (retFwrite != 1) {
        PRINT_ERR("can`t write file(%s),errno = %d\n", path, errno);
        (void)fclose(fp);
        return -1;
    }

    (void)fclose(fp);

    return 0;
}

static cJSON *CreateWholeSyscapJsonObj(void)
{
    size_t allSyscapNum = sizeof(g_arraySyscap) / sizeof(SyscapWithNum);
    cJSON *root =  cJSON_CreateObject();
    for (size_t i = 0; i < allSyscapNum; i++) {
        cJSON_AddItemToObject(root, g_arraySyscap[i].str, cJSON_CreateNumber(g_arraySyscap[i].num));
    }
    return root;
}

int32_t RPCIDEncode(char *inputFile, char *outputPath)
{
    int32_t ret;
    char *contextBuffer = NULL;
    uint32_t bufferLen, sysCapSize;
    char *convertedBuffer = NULL;
    uint32_t convertedBufLen = sizeof(RPCIDHead);
    RPCIDHead *headPtr = NULL;
    char *fillTmpPtr = NULL;
    cJSON *cjsonObjectRoot = NULL;
    cJSON *apiVerItem = NULL;
    cJSON *sysCapPtr = NULL;
    cJSON *arrayItemPtr = NULL;

    ret = GetFileContext(inputFile, &contextBuffer, &bufferLen);
    if (ret != 0) {
        PRINT_ERR("GetFileContext failed, input file : %s\n", inputFile);
        return ret;
    }

    cjsonObjectRoot = cJSON_ParseWithLength(contextBuffer, bufferLen);
    if (cjsonObjectRoot == NULL) {
        PRINT_ERR("cJSON_Parse failed, context buffer is:\n%s\n", contextBuffer);
        ret = -1;
        goto FREE_CONTEXT_OUT;
    }

    sysCapPtr = cJSON_GetObjectItem(cjsonObjectRoot, "syscap");
    if (sysCapPtr == NULL || !cJSON_IsArray(sysCapPtr)) {
        PRINT_ERR("get \"syscap\" object failed.\n");
        ret = -1;
        goto FREE_CONTEXT_OUT;
    }

    ret = cJSON_GetArraySize(sysCapPtr);
    if (ret < 0) {
        PRINT_ERR("get \"syscap\" array size failed\n");
        ret = -1;
        goto FREE_CONTEXT_OUT;
    }
    sysCapSize = (uint32_t)ret;
    // 2, to save SysCaptype & SysCapLength
    convertedBufLen += (2 * sizeof(uint16_t) + sysCapSize * SINGLE_FEAT_LEN);

    convertedBuffer = (char *)malloc(convertedBufLen);
    if (convertedBuffer == NULL) {
        PRINT_ERR("malloc failed\n");
        ret = -1;
        goto FREE_CONTEXT_OUT;
    }
    (void)memset_s(convertedBuffer, convertedBufLen, 0, convertedBufLen);

    headPtr = (RPCIDHead *)convertedBuffer;
    apiVerItem = cJSON_GetObjectItem(cjsonObjectRoot, "api_version");
    if (apiVerItem == NULL || !cJSON_IsNumber(apiVerItem)) {
        PRINT_ERR("get \"api_version\" failed\n");
        ret = -1;
        goto FREE_CONVERT_OUT;
    }
    headPtr->apiVersion = HtonsInter((uint16_t)apiVerItem->valueint);
    headPtr->apiVersionType = 1;

    fillTmpPtr = convertedBuffer + sizeof(RPCIDHead);

    *(uint16_t *)fillTmpPtr = HtonsInter(2); // 2, SysCap Type, 2: request Cap
    fillTmpPtr += sizeof(uint16_t);
    // fill osCap Length
    *(uint16_t *)fillTmpPtr = HtonsInter((uint16_t)(sysCapSize * SINGLE_FEAT_LEN));
    fillTmpPtr += sizeof(uint16_t);
    for (uint32_t i = 0; i < sysCapSize; i++) {
        arrayItemPtr = cJSON_GetArrayItem(sysCapPtr, (int)i);
        char *pointPos = strchr(arrayItemPtr->valuestring, '.');
        if (pointPos == NULL) {
            PRINT_ERR("context of \"syscap\" array is invalid\n");
            ret = -1;
            goto FREE_CONVERT_OUT;
        }
        ret = strncmp(arrayItemPtr->valuestring, "SystemCapability.", pointPos - arrayItemPtr->valuestring + 1);
        if (ret != 0) {
            PRINT_ERR("context of \"syscap\" array is invalid\n");
            ret = -1;
            goto FREE_CONVERT_OUT;
        }

        ret = memcpy_s(fillTmpPtr, SINGLE_FEAT_LEN, pointPos + 1, strlen(pointPos + 1));
        if (ret != 0) {
            PRINT_ERR("context of \"syscap\" array is invalid\n");
            ret = -1;
            goto FREE_CONVERT_OUT;
        }
        fillTmpPtr += SINGLE_FEAT_LEN;
    }

    ret = ConvertedContextSaveAsFile(outputPath, "RPCID.sc", convertedBuffer, convertedBufLen);
    if (ret != 0) {
        PRINT_ERR("ConvertedContextSaveAsFile failed, outputPath:%s, filename:rpcid.sc\n", outputPath);
        goto FREE_CONVERT_OUT;
    }

FREE_CONVERT_OUT:
    free(convertedBuffer);
FREE_CONTEXT_OUT:
    FreeContextBuffer(contextBuffer);
    return ret;
}

static int32_t ParseRpcidToJson(char *input, uint32_t inputLen, cJSON *rpcidJson)
{
    uint32_t i;
    int32_t ret = 0;
    uint16_t sysCapLength = NtohsInter(*(uint16_t *)(input + sizeof(uint32_t)));
    if (sysCapLength > inputLen - sizeof(uint32_t)) {
        PRINT_ERR("Get sysCapLength(%u) error, inputLen = %u\n", sysCapLength, inputLen);
        return -1;
    }
    uint16_t sysCapCount = sysCapLength / SINGLE_FEAT_LEN;
    char *sysCapBegin = input + sizeof(RPCIDHead) + sizeof(uint32_t);
    RPCIDHead *rpcidHeader = (RPCIDHead *)input;
    cJSON *sysCapJson = cJSON_CreateArray();
    for (i = 0; i < sysCapCount; i++) {
        char *temp = sysCapBegin + i * SINGLE_FEAT_LEN;
        if (strlen(temp) >= SINGLE_FEAT_LEN || strlen(temp) == 0) {
            PRINT_ERR("Get SysCap failed, string length(%u) error.\n", (uint32_t)strlen(temp));
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

static int32_t CheckRpcidFormat(char *inputFile, char **Buffer, uint32_t *Len)
{
    uint32_t bufferLen;
    uint16_t sysCaptype, sysCapLength;
    char *contextBuffer = NULL;
    RPCIDHead *rpcidHeader = NULL;

    if (GetFileContext(inputFile, &contextBuffer, &bufferLen)) {
        PRINT_ERR("GetFileContext failed, input file : %s\n", inputFile);
        return -1;
    }
    if (bufferLen < (2 * sizeof(uint32_t))) { // 2, header of rpcid.sc
        PRINT_ERR("Parse file failed(format is invalid), input file : %s\n", inputFile);
        return -1;
    }
    rpcidHeader = (RPCIDHead *)contextBuffer;
    if (rpcidHeader->apiVersionType != 1) {
        PRINT_ERR("Parse file failed(apiVersionType != 1), input file : %s\n", inputFile);
        return -1;
    }
    sysCaptype = NtohsInter(*(uint16_t *)(rpcidHeader + 1));
    if (sysCaptype != 2) { // 2, app syscap type
        PRINT_ERR("Parse file failed(sysCaptype != 2), input file : %s\n", inputFile);
        return -1;
    }
    sysCapLength = NtohsInter(*(uint16_t *)((char *)(rpcidHeader + 1) + sizeof(uint16_t)));
    if (bufferLen < sizeof(RPCIDHead) + sizeof(uint32_t) + sysCapLength) {
        PRINT_ERR("Parse file failed(SysCap length exceeded), input file : %s\n", inputFile);
        return -1;
    }

    *Buffer = contextBuffer;
    *Len = bufferLen;
    return 0;
}

int32_t RPCIDDecode(char *inputFile, char *outputPath)
{
    int32_t ret = 0;
    char *contextBuffer = NULL;
    char *convertedBuffer = NULL;
    uint32_t bufferLen;

    // check rpcid.sc
    if (CheckRpcidFormat(inputFile, &contextBuffer, &bufferLen)) {
        PRINT_ERR("Check rpcid.sc format failed. Input failed: %s\n", inputFile);
        goto FREE_CONTEXT_OUT;
    }

    // parse rpcid to json
    cJSON *rpcidRoot = cJSON_CreateObject();
    if (ParseRpcidToJson(contextBuffer, bufferLen, rpcidRoot) != 0) {
        PRINT_ERR("Prase rpcid to json failed. Input failed: %s\n", inputFile);
        goto FREE_RPCID_ROOT;
    }

    // save to json file
    convertedBuffer = cJSON_Print(rpcidRoot);
    ret = ConvertedContextSaveAsFile(outputPath, "RPCID.json", convertedBuffer, strlen(convertedBuffer));
    if (ret != 0) {
        PRINT_ERR("ConvertedContextSaveAsFile failed, outputPath:%s, filename:rpcid.json\n", outputPath);
        goto FREE_RPCID_ROOT;
    }

FREE_RPCID_ROOT:
    cJSON_Delete(rpcidRoot);
FREE_CONTEXT_OUT:
    FreeContextBuffer(contextBuffer);
    return ret;
}

static int SetOsSysCapBitMap(uint8_t *out, uint16_t outLen, const uint16_t *index, uint16_t indexLen)
{
    uint16_t sector, pos;

    if (outLen != BYTES_OF_OS_SYSCAP) {
        PRINT_ERR("Input array error.\n");
        return -1;
    }

    for (uint16_t i = 0; i < indexLen; i++) {
        sector = index[i] / UINT8_BIT;
        pos = index[i] % UINT8_BIT;
        if (sector >= BYTES_OF_OS_SYSCAP) {
            PRINT_ERR("Syscap num(%u) out of range(120).\n", sector);
            return -1;
        }
        out[sector] |=  (1 << pos);
    }
    return 0;
}

int32_t EncodeRpcidscToString(char *inputFile, char *outDirPath)
{
    int32_t ret = 0;
    int32_t sysCapArraySize;
    uint32_t bufferLen;
    uint16_t indexPri = 0;
    uint16_t *osSysCapIndex;
    char *contextBuffer = NULL;
    char *priSyscapArray = NULL;
    char *priSyscap = NULL;
    cJSON *cJsonTemp = NULL;
    cJSON *rpcidRoot = NULL;
    cJSON *sysCapDefine = NULL;
    cJSON *sysCapArray = NULL;

    // check rpcid.sc
    if (CheckRpcidFormat(inputFile, &contextBuffer, &bufferLen) != 0) {
        PRINT_ERR("Check rpcid.sc format failed. Input file: %s\n", inputFile);
        goto FREE_CONTEXT_OUT;
    }

    // parse rpcid to json
    rpcidRoot = cJSON_CreateObject();
    if (ParseRpcidToJson(contextBuffer, bufferLen, rpcidRoot) != 0) {
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
    priSyscapArray = (char *)malloc((uint32_t)sysCapArraySize * SINGLE_SYSCAP_LEN);
    if (priSyscapArray == NULL) {
        PRINT_ERR("malloc(%d) failed.\n", sysCapArraySize * SINGLE_SYSCAP_LEN);
        goto FREE_MALLOC_OSSYSCAP;
    }
    (void)memset_s(priSyscapArray, (size_t)(sysCapArraySize * SINGLE_SYSCAP_LEN),
                   0, (size_t)(sysCapArraySize * SINGLE_SYSCAP_LEN));
    priSyscap = priSyscapArray;
    // part os syscap and ptivate syscap
    uint16_t indexOs = 0;
    for (int i = 0; i < sysCapArraySize; i++) {
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
            priSyscap += SINGLE_SYSCAP_LEN;
            indexPri++;
        }
    }
    uint32_t outUint[RPCID_OUT_BUFFER] = {0};
    outUint[0] = *(uint32_t *)contextBuffer;
    outUint[1] = *(uint32_t *)(contextBuffer + sizeof(uint32_t));
    uint8_t *osOutUint = (uint8_t *)(outUint + 2);
    if (SetOsSysCapBitMap(osOutUint, 120, osSysCapIndex, indexOs) != 0) {  // 120, len of osOutUint
        PRINT_ERR("Set os syscap bit map failed.\n");
        goto FREE_MALLOC_PRISYSCAP;
    }

    uint16_t outBufferLen = U32_TO_STR_MAX_LEN * RPCID_OUT_BUFFER
                            + SINGLE_SYSCAP_LEN * indexPri;
    char *outBuffer = (char *)malloc(outBufferLen);
    if (outBuffer == NULL) {
        PRINT_ERR("malloc(%u) failed.\n", outBufferLen);
        goto FREE_MALLOC_PRISYSCAP;
    }
    (void)memset_s(outBuffer, outBufferLen, 0, outBufferLen);

    ret = sprintf_s(outBuffer, outBufferLen, "%u", outUint[0]);
    if (ret == -1) {
        PRINT_ERR("sprintf_s failed.\n");
        goto FREE_OUTBUFFER;
    }
    for (int i = 1; i < RPCID_OUT_BUFFER; i++) {
        ret = sprintf_s(outBuffer, outBufferLen, "%s,%u", outBuffer, outUint[i]);
        if (ret == -1) {
            PRINT_ERR("sprintf_s failed.\n");
            goto FREE_OUTBUFFER;
        }
    }

    for (uint16_t i = 0; i < indexPri; i++) {
        ret = sprintf_s(outBuffer, outBufferLen, "%s,%s", outBuffer,
                        priSyscapArray + i * SINGLE_SYSCAP_LEN);
        if (ret == -1) {
            PRINT_ERR("sprintf_s failed.\n");
            goto FREE_OUTBUFFER;
        }
    }

    const char outputFilename[] = "RPCID.txt";
    ret = ConvertedContextSaveAsFile(outDirPath, outputFilename, outBuffer, strlen(outBuffer));
    if (ret != 0) {
        PRINT_ERR("Save to txt file failed. Output path:%s/%s\n", outDirPath, outputFilename);
        goto FREE_OUTBUFFER;
    }

FREE_OUTBUFFER:
    free(outBuffer);
FREE_MALLOC_PRISYSCAP:
    free(priSyscapArray);
FREE_MALLOC_OSSYSCAP:
    free(osSysCapIndex);
FREE_WHOLE_SYSCAP:
    cJSON_Delete(sysCapDefine);
FREE_RPCID_ROOT:
    cJSON_Delete(rpcidRoot);
FREE_CONTEXT_OUT:
    FreeContextBuffer(contextBuffer);
    return ret;
}

int32_t SeparateSyscapFromString(const char *inputString, uint32_t *osArray, uint32_t osArraySize,
                                 char **priSyscap, uint32_t *priSyscapLen)
{
    int32_t ret = 0;
    uint32_t i;
    
    uint32_t count = 0;
    char *temp = NULL;
    char *tok = NULL;
    char *private = NULL;

    if (osArraySize != PCID_OUT_BUFFER) {
        return -1;
    }

    // copy to temp string input
    if (inputString == NULL) {
        PRINT_ERR("inputString is null.\n");
        return -1;
    }
    size_t inputLen = strlen(inputString);
    if (inputLen > STRING_FORMAT_LEN_MAX) {
        PRINT_ERR("input string too long(%zu).\n", inputLen);
        return -1;
    }
    char *input = (char *)malloc(inputLen + 1);
    if (input == NULL) {
        PRINT_ERR("malloc failed.\n");
        return -1;
    }
    ret = strcpy_s(input, inputLen + 1, inputString);
    if (ret != EOK) {
        PRINT_ERR("strcpy_s failed.\n");
        free(input);
        return -1;
    }
    input[inputLen] = '\0';

    // get os syscap data
    for (i = 0; i < PCID_OUT_BUFFER; i++) {
        ret = sscanf_s(input, "%u,%s", &osArray[i], input, inputLen);
        if (ret == -1) {
            PRINT_ERR("sscanf_s failed.\n");
            free(input);
            return -1;
        }
    }

    // count private syscap
    if (*input == '\0') {
        *priSyscap = 0;
        *priSyscapLen = 0;
        goto SKIP_PRI_SYSCAP;
    }
    for (i = 0; *(input + i) != '\0'; i++) {
        if (*(input + i) == ',') {
            count++;
        }
    }
    count++;
    // get private syscap string
    char *priSysCapOut = (char *)malloc(SINGLE_SYSCAP_LEN * count);
    if (priSysCapOut == NULL) {
        PRINT_ERR("sscanf_s failed.\n");
        free(input);
        return -1;
    }
    (void)memset_s(priSysCapOut, SINGLE_SYSCAP_LEN * count, 0, SINGLE_SYSCAP_LEN * count);
    private = priSysCapOut;

    temp = strtok_r(input, ",", &tok);
    while (temp) {
        ret = strncpy_s(private, SINGLE_SYSCAP_LEN,
                        temp, SINGLE_SYSCAP_LEN - 1);
        if (ret != EOK) {
            PRINT_ERR("strncpy_s failed.\n");
            free(input);
            free(private);
            return -1;
        }
        temp = strtok_r(NULL, ",", &tok);
        private += SINGLE_SYSCAP_LEN;
    }

    *priSyscap = priSysCapOut;
    *priSyscapLen = count;

SKIP_PRI_SYSCAP:
    free(input);
    return 0;
}

int32_t ComparePcidWithRpcidString(char *pcidFile, char *rpcidFile, uint32_t type)
{
    int32_t ret;
    int32_t versionFlag = 0;
    int32_t ossyscapFlag = 0;
    int32_t prisyscapFlag = 0;
    char *pcidContent = NULL;
    char *rpcidContent = NULL;
    char *pcidPriSyscap = NULL;
    char *rpcidPriSyscap = NULL;
    uint32_t pcidContentLen, rpcidContentLen, pcidPriSyscapLen, rpcidPriSyscapLen;
    uint32_t i, j, temp1, temp2;
    bool priSysFound;
    uint32_t pcidOsAarry[PCID_OUT_BUFFER] = {0};
    uint32_t rpcidOsAarry[PCID_OUT_BUFFER] = {0};
    const size_t allSyscapNum = sizeof(g_arraySyscap) / sizeof(SyscapWithNum);

    if (type == TYPE_FILE) {
        if (GetFileContext(pcidFile, &pcidContent, &pcidContentLen)) {
            PRINT_ERR("Get pcid file context failed, input file : %s\n", pcidFile);
            return -1;
        }
        if (GetFileContext(rpcidFile, &rpcidContent, &rpcidContentLen)) {
            PRINT_ERR("Get rpcid file context failed, input file : %s\n", rpcidFile);
            free(pcidContent);
            return -1;
        }
    } else if (type == TYPE_STRING) {
        pcidContent = pcidFile;
        rpcidContent = rpcidFile;
    } else {
        PRINT_ERR("Input file type error, type=%u\n", type);
        return -1;
    }

    ret =  SeparateSyscapFromString(pcidContent, pcidOsAarry, PCID_OUT_BUFFER,
                                    &pcidPriSyscap, &pcidPriSyscapLen);
    ret += SeparateSyscapFromString(rpcidContent, rpcidOsAarry, RPCID_OUT_BUFFER,
                                    &rpcidPriSyscap, &rpcidPriSyscapLen);
    if (ret != 0) {
        PRINT_ERR("Separate syscap from string failed. ret = %d\n", ret);
        return -1;
    }
    // compare version
    uint16_t pcidVersion = NtohsInter(((PCIDMain *)pcidOsAarry)->apiVersion);
    uint16_t rpcidVersion = NtohsInter(((RPCIDHead *)rpcidOsAarry)->apiVersion);
    if (pcidVersion < rpcidVersion) {
        printf("ERROR: Pcid version(%u) less than rpcid version(%u).\n", pcidVersion, rpcidVersion);
        versionFlag = 1;
    }
    // compare os syscap
    for (i = 2; i < PCID_OUT_BUFFER; i++) { // 2, header of pcid & rpcid
        temp1 = pcidOsAarry[i] ^ rpcidOsAarry[i];
        temp2 = temp1 & rpcidOsAarry[i];
        if (!temp2) {
            continue;
        }
        for (uint8_t k = 0; k < INT_BIT; k++) {
            if (!(temp2 & (1U << k))) {
                continue;
            }
            // 2, header of pcid & rpcid
            size_t pos = (size_t)((i - 2) * INT_BIT + k);
            if (pos < allSyscapNum) {
                printf("Missing: %s\n", g_arraySyscap[pos].str);
                ossyscapFlag += 1;
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
            printf("Missing: %s\n", rpcidPriSyscap + SINGLE_SYSCAP_LEN * i);
            prisyscapFlag += 1;
        }
        priSysFound = false;
    }

    if (!versionFlag && !ossyscapFlag && !prisyscapFlag) {
        printf("Succeed! The pcid meets the rpcid.\n");
    } else {
        printf("Fail! The pcid does not meet the rpcid\n");
    }
    return 0;
}
