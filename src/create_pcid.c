/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include "securec.h"
#include "cJSON.h"
#include "endian_internal.h"
#include "syscap_define.h"
#include "create_pcid.h"

#define SYSCAP_PREFIX_LEN 17
#define SINGLE_FEAT_LEN (SINGLE_SYSCAP_LEN - SYSCAP_PREFIX_LEN)
#define PCID_OUT_BUFFER 32
#define PRIVATE_SYSCAP_SIZE 1000
#define UINT8_BIT 8

#define U32_TO_STR_MAX_LEN 11

#define PRINT_ERR(...) \
    do { \
        printf("ERROR: [%s: %d] -> ", __FILE__, __LINE__); \
        printf(__VA_ARGS__); \
    } while (0)

static void FreeContextBuffer(char *contextBuffer)
{
    (void)free(contextBuffer);
}

static int32_t GetFileContext(char *inputFile, char **contextBufPtr, size_t *contextBufLen)
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
    *contextBufLen = statBuf.st_size + 1;
    return 0;
}

static int32_t ConvertedContextSaveAsFile(char *outDirPath, const char *filename, \
                                          char *convertedBuffer, size_t contextBufLen)
{
    int32_t ret;
    FILE *fp = NULL;
    char path[PATH_MAX + 1] = {0x00};

#ifdef _POSIX_
    if (strlen(outDirPath) > PATH_MAX || strncpy_s(path, PATH_MAX, outDirPath, strlen(outDirPath)) != EOK) {
        PRINT_ERR("get path(%s) failed\n", outDirPath);
        return -1;
    }
#else
    if (strlen(outDirPath) > PATH_MAX || realpath(outDirPath, path) == NULL) {
        PRINT_ERR("get file(%s) real path failed\n", outDirPath);
        return -1;
    }
#endif
    int32_t pathLen = strlen(path);
    if (path[pathLen - 1] != '/' && path[pathLen - 1] != '\\') {
        path[pathLen] = '/';
    }

    if (strlen(path) + strlen(filename) + 1 > PATH_MAX) {
        PRINT_ERR("length of path too long.\n");
        return -1;
    }
    ret = strncat_s(path, PATH_MAX, filename, strlen(filename) + 1);
    if (ret != 0) {
        PRINT_ERR("strncat_s failed, (%s, %d, %s, %d), errno = %d\n",
                  path, PATH_MAX, filename, (int32_t)strlen(filename) + 1, errno);
        return -1;
    }

    fp = fopen(path, "wb");
    if (fp == NULL) {
        PRINT_ERR("can't create file(%s), errno = %d\n", path, errno);
        return -1;
    }

    if (fwrite(convertedBuffer, contextBufLen, 1, fp) != 1) {
        PRINT_ERR("can't write file(%s),errno = %d\n", path, errno);
        (void)fclose(fp);
        return -1;
    }

    (void)fclose(fp);

    return 0;
}

static cJSON *CreateWholeSyscapJsonObj(void)
{
    size_t numOfSyscapAll = sizeof(g_arraySyscap) / sizeof(SyscapWithNum);
    cJSON *root =  cJSON_CreateObject();
    for (size_t i = 0; i < numOfSyscapAll; i++) {
        cJSON_AddItemToObject(root, g_arraySyscap[i].str, cJSON_CreateNumber(g_arraySyscap[i].num));
    }
    return root;
}

int32_t CreatePCID(char *inputFile, char *outDirPath)
{
    int32_t ret, sectorOfBits, posOfBits;
    uint32_t i, privateCapSize, osCapSize;
    size_t contextBufLen;
    errno_t nRet = 0;
    char *contextBuffer = NULL;
    char *systemType = NULL;
    cJSON *jsonRootObj = NULL;
    cJSON *jsonSyscapObj = NULL;
    cJSON *jsonOsSyscapObj = NULL;
    cJSON *jsonPriSyscapObj = NULL;
    cJSON *jsonArrayItem = NULL;
    cJSON *osCapIndex = NULL;
    cJSON *allOsSyscapObj = CreateWholeSyscapJsonObj();

    ret = GetFileContext(inputFile, &contextBuffer, &contextBufLen);
    if (ret != 0) {
        PRINT_ERR("GetFileContext failed, input file : %s\n", inputFile);
        return -1;
    }

    jsonRootObj = cJSON_ParseWithLength(contextBuffer, contextBufLen);
    if (jsonRootObj == NULL) {
        PRINT_ERR("cJSON_Parse failed, context buffer is:\n%s\n", contextBuffer);
        ret = -1;
        goto FREE_CONVERT_OUT;
    }

    jsonSyscapObj = cJSON_GetObjectItem(jsonRootObj, "syscap");
    if (jsonSyscapObj == NULL || !cJSON_IsObject(jsonSyscapObj)) {
        PRINT_ERR("get \"syscap\" object failed\n");
        ret = -1;
        goto FREE_CONVERT_OUT;
    }

    jsonOsSyscapObj = cJSON_GetObjectItem(jsonSyscapObj, "os");
    if (jsonOsSyscapObj == NULL || !cJSON_IsArray(jsonOsSyscapObj)) {
        PRINT_ERR("get \"os\" array failed\n");
        ret = -1;
        goto FREE_CONVERT_OUT;
    }
    ret = cJSON_GetArraySize(jsonOsSyscapObj);
    if (ret < 0) {
        PRINT_ERR("get \"os\" array size failed\n");
        ret = -1;
        goto FREE_CONVERT_OUT;
    }
    osCapSize = (uint32_t)ret;

    jsonPriSyscapObj = cJSON_GetObjectItem(jsonSyscapObj, "private");
    if (jsonPriSyscapObj != NULL && cJSON_IsArray(jsonPriSyscapObj)) {
        ret = cJSON_GetArraySize(jsonPriSyscapObj);
        if (ret < 0) {
            PRINT_ERR("get \"private syscap\" array size failed\n");
            ret = -1;
            goto FREE_CONVERT_OUT;
        }
        privateCapSize = (uint32_t)ret;
    } else if (jsonPriSyscapObj == NULL) {
        privateCapSize = 0;
    } else {
        PRINT_ERR("get \"private\" array failed\n");
        ret = -1;
        goto FREE_CONVERT_OUT;
    }

    uint16_t allPriSyscapStrLen = 0;
    for (i = 0; i < privateCapSize; i++) {
        jsonArrayItem = cJSON_GetArrayItem(jsonPriSyscapObj, (int)i);
        allPriSyscapStrLen += (uint16_t)strlen(strchr(jsonArrayItem->valuestring, '.') + 1);
        allPriSyscapStrLen++;  // for separator ','
    }
    if ((allPriSyscapStrLen + 1) > PRIVATE_SYSCAP_SIZE) {
        PRINT_ERR("context of \"pri\" array is too many.\n");
        ret = -1;
        goto FREE_CONVERT_OUT;
    }

    uint16_t pcidLength = sizeof(PCIDMain) + allPriSyscapStrLen + 1;
    PCIDMain *pcidBuffer = (PCIDMain *)malloc(pcidLength);
    if (pcidBuffer == NULL) {
        PRINT_ERR("malloc for pcid buffer failed\n");
        ret = -1;
        goto FREE_CONVERT_OUT;
    }
    (void)memset_s(pcidBuffer, pcidLength, 0, pcidLength);
    
    // process os syscap
    for (i = 0; i < osCapSize; i++) {
        jsonArrayItem = cJSON_GetArrayItem(jsonOsSyscapObj, (int)i);
        osCapIndex = cJSON_GetObjectItem(allOsSyscapObj, jsonArrayItem->valuestring);
        if (osCapIndex == NULL) {
            PRINT_ERR("can't find the syscap: %s, please add it in syscap_define.h.\n", jsonArrayItem->valuestring);
            ret = -1;
            goto FREE_CONVERT_OUT;
        }
        sectorOfBits = (osCapIndex->valueint) / UINT8_BIT;
        posOfBits = (osCapIndex->valueint) % UINT8_BIT;
        if (sectorOfBits >= OS_SYSCAP_BYTES) {
            PRINT_ERR("num of \"os syscap\" is out of 960\n");
            ret = -1;
            goto FREE_PCID_BUFFER_OUT;
        }
        pcidBuffer->osSyscap[sectorOfBits] |= 1 << (posOfBits);
    }

    // process private syscap
    char *priSyscapHead = (char *)(pcidBuffer + 1);
    char *priSyscapStr = NULL;
    for (i = 0; i < privateCapSize; i++) {
        jsonArrayItem = cJSON_GetArrayItem(jsonPriSyscapObj, (int)i);
        priSyscapStr = strchr(jsonArrayItem->valuestring, '.') + 1;
        nRet = strcat_s(priSyscapHead, allPriSyscapStrLen + 1, priSyscapStr);
        nRet += strcat_s(priSyscapHead, allPriSyscapStrLen + 1, ",");
        if (nRet != EOK) {
            PRINT_ERR("strcat_s \"pri\" string is failed\n");
            ret = -1;
            goto FREE_PCID_BUFFER_OUT;
        }
    }

    jsonSyscapObj = cJSON_GetObjectItem(jsonRootObj, "api_version");
    if (jsonSyscapObj == NULL || !cJSON_IsNumber(jsonSyscapObj)) {
        PRINT_ERR("get \"api_version\" failed\n");
        ret = -1;
        goto FREE_PCID_BUFFER_OUT;
    }
    pcidBuffer->apiVersion = HtonsInter((uint16_t)jsonSyscapObj->valueint);
    pcidBuffer->apiVersionType = 0;

    jsonSyscapObj = cJSON_GetObjectItem(jsonRootObj, "system_type");
    if (jsonSyscapObj == NULL || !cJSON_IsString(jsonSyscapObj)) {
        PRINT_ERR("get \"system_type\" failed\n");
        ret = -1;
        goto FREE_PCID_BUFFER_OUT;
    }
    systemType = jsonSyscapObj->valuestring;
    pcidBuffer->systemType = !strcmp(systemType, "mini") ? 0b001 :
                          (!strcmp(systemType, "small") ? 0b010 :
                          (!strcmp(systemType, "standard") ? 0b100 : 0));
    if (pcidBuffer->systemType == 0) {
        PRINT_ERR("\"system_type\" is invaild, systemType = \"%s\"\n", systemType);
        ret = -1;
        goto FREE_PCID_BUFFER_OUT;
    }

    jsonSyscapObj = cJSON_GetObjectItem(jsonRootObj, "manufacturer_id");
    if (jsonSyscapObj == NULL || !cJSON_IsNumber(jsonSyscapObj)) {
        PRINT_ERR("get \"manufacturer_id\" failed\n");
        ret = -1;
        goto FREE_PCID_BUFFER_OUT;
    }
    pcidBuffer->manufacturerID = HtonlInter((uint32_t)jsonSyscapObj->valueint);

    const char pcidFileName[] = "PCID.sc";
    ret = ConvertedContextSaveAsFile(outDirPath, pcidFileName, (char *)pcidBuffer, pcidLength);
    if (ret != 0) {
        PRINT_ERR("ConvertedContextSaveAsFile failed, outDirPath:%s, filename:%s\n", outDirPath, pcidFileName);
        ret = -1;
        goto FREE_PCID_BUFFER_OUT;
    }

FREE_PCID_BUFFER_OUT:
    free(pcidBuffer);
FREE_CONVERT_OUT:
    free(allOsSyscapObj);
    FreeContextBuffer(contextBuffer);
    return ret;
}

int32_t DecodePCID(char *inputFile, char *outDirPath)
{
    int32_t ret;
    errno_t nRet = 0;
    char *contextBuffer = NULL;
    uint8_t osSyscap[OS_SYSCAP_BYTES] = {0};
    uint16_t indexOfSyscap[OS_SYSCAP_BYTES * UINT8_BIT] = {0};
    uint32_t i, j, countOfSyscap = 0;
    size_t contextBufLen;

    ret = GetFileContext(inputFile, &contextBuffer, &contextBufLen);
    if (ret != 0) {
        PRINT_ERR("GetFileContext failed, input file : %s\n", inputFile);
        return -1;
    }

    PCIDMain *pcidMain = (PCIDMain *)contextBuffer;
    
    /* api version */
    if (pcidMain->apiVersionType != 0) {
        PRINT_ERR("Prase file failed, apiVersionType is invaild, input file : %s\n", inputFile);
        ret = -1;
        goto FREE_CONTEXT_OUT;
    }

    /* system type */
    char *systemType = pcidMain->systemType == 0b001 ? "mini" :
                       (pcidMain->systemType == 0b010 ? "small" :
                       (pcidMain->systemType == 0b100 ? "standard" : NULL));
    if (systemType == NULL) {
        PRINT_ERR("prase file failed, systemType is invaild, %u\n", pcidMain->systemType);
        ret = -1;
        goto FREE_CONTEXT_OUT;
    }

    cJSON *capVectorPtr = cJSON_CreateArray();
    if (capVectorPtr == NULL) {
        PRINT_ERR("cJSON_CreateArray failed\n");
        ret = -1;
        goto FREE_CONTEXT_OUT;
    }

    nRet = memcpy_s(osSyscap, OS_SYSCAP_BYTES, (uint8_t *)pcidMain + 8, OS_SYSCAP_BYTES); // 8, bytes of pcid header
    if (nRet != EOK) {
        PRINT_ERR("memcpy_s failed.");
        ret = -1;
        goto FREE_VECTOR_OUT;
    }
    for (i = 0; i < OS_SYSCAP_BYTES; i++) {
        for (j = 0; j < UINT8_BIT; j++) {
            if (osSyscap[i] & (0x01 << j)) {
                indexOfSyscap[countOfSyscap++] = i * UINT8_BIT + j;
            }
        }
    }
    for (i = 0; i < countOfSyscap; i++) {
        for (j = 0; j < sizeof(g_arraySyscap) / sizeof(SyscapWithNum); j++) {
            if (g_arraySyscap[j].num == indexOfSyscap[i]) {
                if (!cJSON_AddItemToArray(capVectorPtr, cJSON_CreateString(g_arraySyscap[j].str))) {
                    printf("cJSON_AddItemToArray or cJSON_CreateString failed\n");
                    ret = -1;
                    goto FREE_VECTOR_OUT;
                }
            }
        }
    }

    cJSON *sysCapObjectPtr = cJSON_CreateObject();
    if (sysCapObjectPtr == NULL) {
        PRINT_ERR("cJSON_CreateObject failed\n");
        ret = -1;
        goto FREE_CONTEXT_OUT;
    }
    if (!cJSON_AddItemToObject(sysCapObjectPtr, "os", capVectorPtr)) {
        PRINT_ERR("cJSON_AddItemToObject failed\n");
        ret = -1;
        goto FREE_VECTOR_OUT;
    }
    // private syscap
    capVectorPtr = cJSON_CreateArray();
    if (capVectorPtr == NULL) {
        PRINT_ERR("cJSON_CreateArray failed\n");
        ret = -1;
        goto FREE_SYSCAP_OUT;
    }

    char *ptrPrivateSyscap = (char *)(pcidMain + 1);
    int privateSyscapLen = (int)(contextBufLen - sizeof(PCIDMain) - 1);
    char priSyscapStr[SINGLE_SYSCAP_LEN] = {0};
    char *tempPriSyscapStr = priSyscapStr;
    char fullPriSyscapStr[SINGLE_SYSCAP_LEN] = {0};
    if ((long)privateSyscapLen < 0) {
        PRINT_ERR("parse private syscap failed.");
        ret = -1;
        goto FREE_VECTOR_OUT;
    } else if (privateSyscapLen == 0) {
        goto SKIP_GET_PRIVATE;
    }

    while (*ptrPrivateSyscap != '\0') {
        if (*ptrPrivateSyscap == ',') {
            *tempPriSyscapStr = '\0';
            ret = sprintf_s(fullPriSyscapStr, SINGLE_SYSCAP_LEN, "SystemCapability.%s", priSyscapStr);
            if (ret == -1) {
                printf("sprintf_s failed\n");
                goto FREE_VECTOR_OUT;
            }
            if (!cJSON_AddItemToArray(capVectorPtr, cJSON_CreateString(fullPriSyscapStr))) {
                printf("cJSON_AddItemToArray or cJSON_CreateString failed\n");
                ret = -1;
                goto FREE_VECTOR_OUT;
            }
            tempPriSyscapStr = priSyscapStr;
            ptrPrivateSyscap++;
            continue;
        }
        *tempPriSyscapStr++ = *ptrPrivateSyscap++;
    }
    if (!cJSON_AddItemToObject(sysCapObjectPtr, "private", capVectorPtr)) {
        PRINT_ERR("cJSON_AddItemToObject failed\n");
        ret = -1;
        goto FREE_VECTOR_OUT;
    }

SKIP_GET_PRIVATE:
    capVectorPtr = NULL;
    // create json root
    cJSON *jsonRootObj = cJSON_CreateObject();
    if (jsonRootObj == NULL) {
        PRINT_ERR("cJSON_CreateObject failed\n");
        ret = -1;
        goto FREE_SYSCAP_OUT;
    }

    if (!cJSON_AddNumberToObject(jsonRootObj, "api_version", NtohsInter(pcidMain->apiVersion))) {
        PRINT_ERR("cJSON_AddNumberToObject failed\n");
        ret = -1;
        goto FREE_ROOT_OUT;
    }
    if (!cJSON_AddNumberToObject(jsonRootObj, "manufacturer_id", NtohlInter(pcidMain->manufacturerID))) {
        PRINT_ERR("cJSON_AddNumberToObject failed\n");
        ret = -1;
        goto FREE_ROOT_OUT;
    }
    if (!cJSON_AddStringToObject(jsonRootObj, "system_type", systemType)) {
        PRINT_ERR("cJSON_AddStringToObject failed\n");
        ret = -1;
        goto FREE_ROOT_OUT;
    }
    if (!cJSON_AddItemToObject(jsonRootObj, "syscap", sysCapObjectPtr)) {
        PRINT_ERR("cJSON_AddItemToObject failed\n");
        ret = -1;
        goto FREE_ROOT_OUT;
    }
    sysCapObjectPtr = NULL;

    char *convertedBuffer = cJSON_Print(jsonRootObj);

    const char outputFileName[] = "PCID.json";
    ret = ConvertedContextSaveAsFile(outDirPath, outputFileName, convertedBuffer, strlen(convertedBuffer));
    if (ret != 0) {
        PRINT_ERR("ConvertedContextSaveAsFile failed, outDirPath:%s, filename:%s\n", outDirPath, outputFileName);
        goto FREE_CONVERT_OUT;
    }

FREE_CONVERT_OUT:
    free(convertedBuffer);
FREE_ROOT_OUT:
    cJSON_Delete(jsonRootObj);
FREE_SYSCAP_OUT:
    cJSON_Delete(sysCapObjectPtr);
FREE_VECTOR_OUT:
    cJSON_Delete(capVectorPtr);
FREE_CONTEXT_OUT:
    FreeContextBuffer(contextBuffer);
    return ret;
}

#define U32_TO_STR_MAX_LEN 11
#define OS_SYSCAP_NUM 30
#define PCID_HEADER 2
static int32_t ParseStringSyscap(char *input, uint32_t *osSyscap, uint32_t osSyscapNum,
                                 uint32_t *header, uint32_t headerLen)
{
    int32_t ret;
    uint32_t tempNum;
    uint32_t i = 0;
    size_t inputLen = strlen(input);

    if (osSyscapNum != OS_SYSCAP_NUM || headerLen != PCID_HEADER) {
        PRINT_ERR("Input osSyscapNum(%u) or headerLen(%u) error.\n", osSyscapNum, headerLen);
        return -1;
    }

    if (sscanf_s(input, "%u,%u,%s", &header[0], &header[1], input, inputLen) != 3) { // 3, return val of "%u,%u,%s"
        PRINT_ERR("Get pcid header failed.\n");
        return -1;
    }

    while ((ret = sscanf_s(input, "%u,%s", &tempNum, input, inputLen)) > 0) {
        osSyscap[i++] = tempNum;
        if (i >= OS_SYSCAP_NUM) {
            break;
        }
    }
    if (ret == -1) {
        PRINT_ERR("sscanf_s failed, i = %u.\n", i);
        return -1;
    }

    if (strlen(input) <= 1) {
        *input = '\0';
    }

    return 0;
}

static int32_t AddHeaderToJsonObj(uint32_t *pcidHeader, uint32_t pcidHeaderLen, cJSON *rootObj)
{
    if (pcidHeaderLen != PCID_HEADER) {
        PRINT_ERR("input pcidHeader(%u) error.\n", pcidHeaderLen);
        return -1;
    }

    PCIDHeader *header = (PCIDHeader *)pcidHeader;
    // trans system type to string
    char *systemType = header->systemType  == 0b001 ? "mini" :
                       (header->systemType == 0b010 ? "small" :
                       (header->systemType == 0b100 ? "standard" : NULL));
    if (systemType == NULL) {
        PRINT_ERR("prase system type failed.\n");
        return -1;
    }

    // add to json
    if (!cJSON_AddNumberToObject(rootObj, "api_version", NtohsInter(header->apiVersion))) {
        PRINT_ERR("add api_version(%u) to json object failed.\n", NtohsInter(header->apiVersion));
        return -1;
    }
    if (!cJSON_AddNumberToObject(rootObj, "manufacturer_id", NtohlInter(header->manufacturerID))) {
        PRINT_ERR("add manufacturer_id(%u) to json object failed\n", NtohlInter(header->manufacturerID));
        return -1;
    }
    if (!cJSON_AddStringToObject(rootObj, "system_type", systemType)) {
        PRINT_ERR("add system_type(%s) to json object failed\n", systemType);
        return -1;
    }
    return 0;
}

static int32_t AddOsSyscapToJsonObj(uint32_t *osSyscapArray, uint32_t osSyscapArrayLen, cJSON *sysCapObj)
{
    cJSON *sysCapArray = cJSON_CreateArray();
    if (sysCapArray == NULL) {
        PRINT_ERR("Create cJSON array failed.\n");
        return -1;
    }

    if (osSyscapArrayLen != OS_SYSCAP_NUM) {
        PRINT_ERR("Input os syscap array len error.\n");
        free(sysCapArray);
        return -1;
    }
    uint8_t *osSysCapArrayUint8 = (uint8_t *)osSyscapArray;

    uint32_t i, j;
    uint32_t osSyscapCount = 0;
    uint16_t index[OS_SYSCAP_BYTES * UINT8_BIT] = {0};
    for (i = 0; i < OS_SYSCAP_BYTES; i++) {
        for (j = 0; j < UINT8_BIT; j++) {
            if (osSysCapArrayUint8[i] & (0x01 << j)) {
                index[osSyscapCount++] = i * UINT8_BIT + j;
            }
        }
    }

    for (i = 0; i < osSyscapCount; i++) {
        for (j = 0; j < sizeof(g_arraySyscap) / sizeof(SyscapWithNum); j++) {
            if (index[i] != g_arraySyscap[j].num) {
                continue;
            }
            if (!cJSON_AddItemToArray(sysCapArray, cJSON_CreateString(g_arraySyscap[j].str))) {
                PRINT_ERR("Add os syscap string to json failed.\n");
                free(sysCapArray);
                return -1;
            }
            break;
        }
    }

    if (!cJSON_AddItemToObject(sysCapObj, "os", sysCapArray)) {
        PRINT_ERR("Add os syscap item to json object failed.\n");
        free(sysCapArray);
        return -1;
    }
    return 0;
}

static int32_t AddPriSyscapToJsonObj(char *priSyscapString, uint32_t priSyscapStringLen, cJSON *sysCapObj)
{
    char *token = NULL;

    cJSON *sysCapArray = cJSON_CreateArray();
    if (sysCapArray == NULL) {
        PRINT_ERR("Create cJSON array failed.\n");
        free(sysCapArray);
        return -1;
    }
    if (priSyscapStringLen == 0) {
        if (!cJSON_AddItemToObject(sysCapObj, "private", sysCapArray)) {
            PRINT_ERR("Add private syscap array to json failed.\n");
            free(sysCapArray);
            return -1;
        }
        return 0;
    }

    token = strtok(priSyscapString, ",");
    while (token != NULL) {
        if (!cJSON_AddItemToArray(sysCapArray, cJSON_CreateString(token))) {
            PRINT_ERR("Add private syscap string to json failed.\n");
            free(sysCapArray);
            return -1;
        }
        token = strtok(NULL, ",");
    }
    if (!cJSON_AddItemToObject(sysCapObj, "private", sysCapArray)) {
        PRINT_ERR("Add private syscap array to json failed.\n");
        free(sysCapArray);
        return -1;
    }
    return 0;
}

int32_t DecodeStringPCIDToJson(char *input, char *outDirPath)
{
    int32_t ret = -1;
    uint32_t osSyscapUintArray[OS_SYSCAP_NUM] = {0};
    uint32_t pcidHeader[PCID_HEADER];
    size_t fileContextLen;
    char *fileContext = NULL;
    char *priSyscapStr = NULL;

    if (GetFileContext(input, &fileContext, &fileContextLen) != 0) {
        PRINT_ERR("GetFileContext failed, input file : %s\n", input);
        goto PARSE_FAILED;
    }
    if (ParseStringSyscap(fileContext, osSyscapUintArray,
                          OS_SYSCAP_NUM, pcidHeader, PCID_HEADER) != 0) {
        PRINT_ERR("Parse string syscap failed.\n");
        goto PARSE_FAILED;
    }
    priSyscapStr = fileContext;
    
    // add to json object
    cJSON *sysCapObj = cJSON_CreateObject();
    cJSON *rootObj = cJSON_CreateObject();
    if (!cJSON_AddItemToObject(rootObj, "syscap", sysCapObj)) {
        PRINT_ERR("Add syscap to json failed.\n");
        goto ADD_JSON_FAILED;
    }
    if (AddHeaderToJsonObj(pcidHeader, PCID_HEADER, rootObj) != 0) {
        PRINT_ERR("Add header to json object failed.\n");
        goto ADD_JSON_FAILED;
    }
    if (AddOsSyscapToJsonObj(osSyscapUintArray, OS_SYSCAP_NUM, sysCapObj) != 0) {
        PRINT_ERR("Add os syscap json object failed.\n");
        goto ADD_JSON_FAILED;
    }
    if (AddPriSyscapToJsonObj(priSyscapStr, (uint32_t)strlen(priSyscapStr), sysCapObj) != 0) {
        PRINT_ERR("Add private syscap json object failed.\n");
        goto ADD_JSON_FAILED;
    }
    // save as json file
    char *jsonBuffer = cJSON_Print(rootObj);
    const char outputFileName[] = "PCID.json";
    if (ConvertedContextSaveAsFile(outDirPath, outputFileName,
                                   jsonBuffer, strlen(jsonBuffer)) != 0) {
        PRINT_ERR("Save as json file failed.\n");
        goto SAVE_FAILED;
    }
    ret = 0;

SAVE_FAILED:
    free(jsonBuffer);
ADD_JSON_FAILED:
    cJSON_Delete(rootObj);
PARSE_FAILED:
    free(fileContext);
    return ret;
}

int32_t EncodePcidscToString(char *inputFile, char *outDirPath)
{
    int32_t ret = 0;
    size_t bufferLen, privateSyscapLen, outputLen;
    uint32_t i, j;
    uint32_t *mainSyscap = NULL;
    uint16_t priSyscapCount = 0;
    char *contextBuffer = NULL;
    char *privateSyscap = NULL;
    char *priSyscapFull = NULL;
    char *output = NULL;
    PCIDMain *pcidMain = NULL;

    ret = GetFileContext(inputFile, &contextBuffer, &bufferLen);
    if (ret != 0) {
        PRINT_ERR("Get pcid file failed, pcid file path: %s\n", inputFile);
        return -1;
    }

    if (bufferLen > 1128) { // 1128, max size of pcid.sc
        PRINT_ERR("Input pcid file too large, pcid file size: %zu\n", bufferLen);
        goto FREE_CONTEXT;
    }

    pcidMain = (PCIDMain *)contextBuffer;
    privateSyscap = (char *)(pcidMain + 1);
    privateSyscapLen = strlen(privateSyscap);

    // process os syscap
    mainSyscap = (uint32_t *)pcidMain;

    // process private syscap
    for (i = 0; i < privateSyscapLen; i++) {
        if (privateSyscap[i] == ',') {
            priSyscapCount++;
        }
    }
    if (priSyscapCount == 0) {
        goto OUT_PUT;
    }
    priSyscapFull = (char *)malloc(priSyscapCount * SINGLE_SYSCAP_LEN);
    if (priSyscapFull == NULL) {
        PRINT_ERR("malloc failed\n");
        goto FREE_PRISYSCAP_FULL;
    }
    (void)memset_s(priSyscapFull, priSyscapCount * SINGLE_SYSCAP_LEN,
                   0, priSyscapCount * SINGLE_SYSCAP_LEN);
    char tempSyscap[SINGLE_SYSCAP_LEN] = {0};
    char *temp = tempSyscap;
    for (i = 0, j = 0; i < privateSyscapLen; i++) {
        if (*privateSyscap == ',') {
            *temp = '\0';
            ret = sprintf_s(priSyscapFull + j * SINGLE_SYSCAP_LEN, SINGLE_SYSCAP_LEN,
                            "SystemCapability.%s", tempSyscap);
            if (ret == -1) {
                PRINT_ERR("sprintf_s failed\n");
                goto FREE_PRISYSCAP_FULL;
            }
            temp = tempSyscap;
            privateSyscap++;
            j++;
            continue;
        }
        *temp++ = *privateSyscap++;
    }
    // output
OUT_PUT:
    // 17, size of "SystemCapability."
    outputLen = U32_TO_STR_MAX_LEN * PCID_OUT_BUFFER + 17 * priSyscapCount + privateSyscapLen + 1;
    output = (char *)malloc(outputLen);
    if (output == NULL) {
        PRINT_ERR("malloc failed\n");
        goto FREE_PRISYSCAP_FULL;
    }
    (void)memset_s(output, outputLen, 0, outputLen);
    ret = sprintf_s(output, outputLen, "%u", mainSyscap[0]);
    if (ret == -1) {
        PRINT_ERR("sprintf_s failed\n");
        goto FREE_OUTPUT;
    }
    for (i = 1; i < PCID_OUT_BUFFER; i++) {
        ret = sprintf_s(output, outputLen, "%s,%u", output, mainSyscap[i]);
        if (ret == -1) {
            PRINT_ERR("sprintf_s failed\n");
            goto FREE_OUTPUT;
        }
    }
    for (i = 0; i < priSyscapCount; i++) {
        ret = sprintf_s(output, outputLen, "%s,%s", output, priSyscapFull + i * SINGLE_SYSCAP_LEN);
        if (ret == -1) {
            PRINT_ERR("sprintf_s failed\n");
            goto FREE_OUTPUT;
        }
    }
    // save as file
    const char outputFileName[] = "PCID.txt";
    ret = ConvertedContextSaveAsFile(outDirPath, outputFileName, output, strlen(output));
    if (ret != 0) {
        PRINT_ERR("ConvertedContextSaveAsFile failed, outDirPath:%s, filename:%s\n", outDirPath, outputFileName);
        goto FREE_OUTPUT;
    }

FREE_OUTPUT:
    free(output);
FREE_PRISYSCAP_FULL:
    free(priSyscapFull);
FREE_CONTEXT:
    free(contextBuffer);
    return ret;
}