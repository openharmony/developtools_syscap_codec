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

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <securec.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <securec.h>
#include "syscap_define.h"
#include "syscap_interface.h"

#define PCID_OUT_BUFFER 32
#define OS_SYSCAP_BYTES 120
#define BITS_OF_BYTE 8
#define PCID_MAIN_LEN 128
#define PATH_MAX 4096

#define PRINT_ERR(...) \
    do { \
        printf("ERROR: in file %s at line %d -> ", __FILE__, __LINE__); \
        printf(__VA_ARGS__); \
    } while (0)

static char *inputFile = "/system/etc/PCID.sc";

static void FreeContextBuffer(char *contextBuffer)
{
    (void)free(contextBuffer);
}

static int32_t GetFileContext(char **contextBufPtr, uint32_t *bufferLen)
{
    int32_t ret;
    FILE *fp = NULL;
    struct stat statBuf;
    char *contextBuffer = NULL;

    ret = stat(inputFile, &statBuf);
    if (ret != 0) {
        PRINT_ERR("get file(%s) st_mode failed, errno = %d\n", inputFile, errno);
        return -1;
    }
    if (!(statBuf.st_mode & S_IRUSR)) {
        PRINT_ERR("don't have permission to read the file(%s)\n", inputFile);
        return -1;
    }
    contextBuffer = (char *)malloc(statBuf.st_size + 1);
    if (contextBuffer == NULL) {
        PRINT_ERR("malloc buffer failed, size = %d, errno = %d\n", (int32_t)statBuf.st_size + 1, errno);
        return -1;
    }

    fp = fopen(inputFile, "rb");
    if (fp == NULL) {
        PRINT_ERR("open file(%s) failed, errno = %d\n", inputFile, errno);
        FreeContextBuffer(contextBuffer);
        return -1;
    }
    ret = fread(contextBuffer, statBuf.st_size, 1, fp);
    if (ret != 1) {
        PRINT_ERR("read file(%s) failed, errno = %d\n", inputFile, errno);
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

bool EncodeOsSyscap(char output[MAX_SYSCAP_STR_LEN], int length)
{
    int32_t ret;
    int32_t res;
    char *contextBuffer = NULL;
    uint32_t bufferLen;

    ret = GetFileContext(&contextBuffer, &bufferLen);
    if (ret != 0) {
        PRINT_ERR("GetFileContext failed, input file : /system/etc/PCID.sc\n");
        return false;
    }

    res = memcpy_s(output, PCID_MAIN_LEN, contextBuffer, PCID_MAIN_LEN);
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

    ret = GetFileContext(&contextBuffer, &bufferLen);
    if (ret != 0) {
        PRINT_ERR("GetFileContext failed, input file : /system/etc/PCID.sc\n");
        return false;
    }
    
    *outputLen = bufferLen - PCID_MAIN_LEN - 1;
    outputStr = (char *)malloc(*outputLen);
    if (outputStr == NULL) {
        PRINT_ERR("malloc buffer failed, size = %d, errno = %d\n", *outputLen, errno);
        *outputLen = 0;
        return false;
    }
    (void)memset_s(outputStr, *outputLen, 0, *outputLen);

    ret = strncpy_s(outputStr, *outputLen, contextBuffer + PCID_MAIN_LEN, *outputLen - 1);
    if (ret != 0) {
        PRINT_ERR("strcpy_s failed.");
        FreeContextBuffer(contextBuffer);
        free(outputStr);
        *outputLen = 0;
        return false;
    }

    FreeContextBuffer(contextBuffer);
    *output = outputStr;
    return true;
}

bool DecodeOsSyscap(char input[128], char (**output)[128], int *outputCnt)
{
    errno_t nRet = 0;
    uint16_t indexOfSyscap[BITS_OF_BYTE * OS_SYSCAP_BYTES] = {0};
    uint16_t countOfSyscap = 0;
    uint16_t i, j;

    uint8_t *osSyscap = (uint8_t *)(input + 8); // 8, int[2] of pcid header

    for (i = 0; i < OS_SYSCAP_BYTES; i++) {
        for (j = 0; j < BITS_OF_BYTE; j++) {
            if (osSyscap[i] & (0x01 << j)) {
                indexOfSyscap[countOfSyscap++] = i * BITS_OF_BYTE + j;
            }
        }
    }

    *outputCnt = countOfSyscap;
    char (*strSyscap)[MAX_SYSCAP_STR_LEN] = NULL;
    strSyscap = (char (*)[MAX_SYSCAP_STR_LEN])malloc(countOfSyscap * MAX_SYSCAP_STR_LEN);
    if (strSyscap == NULL) {
        PRINT_ERR("malloc failed.");
        *outputCnt = 0;
        return false;
    }
    (void)memset_s(strSyscap, countOfSyscap * MAX_SYSCAP_STR_LEN, \
                   0, countOfSyscap * MAX_SYSCAP_STR_LEN);
    *output = strSyscap;

    for (i = 0; i < countOfSyscap; i++) {
        for (j = 0; j < sizeof(arraySyscap) / sizeof(SyscapWithNum); j++) {
            if (arraySyscap[j].num == indexOfSyscap[i]) {
                nRet = strcpy_s(*strSyscap, MAX_SYSCAP_STR_LEN, arraySyscap[j].syscapStr);
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

bool DecodePrivateSyscap(char *input, char (**output)[128], int *outputCnt)
{
    char (*outputArray)[MAX_SYSCAP_STR_LEN] = NULL;
    char *inputPos = input;
    int bufferLen, ret;
    int syscapCnt = 0;

    while (*inputPos != '\0') {
        if (*inputPos == ',') {
            syscapCnt++;
        }
        inputPos++;
    }
    inputPos = input;

    bufferLen = MAX_SYSCAP_STR_LEN * syscapCnt;
    outputArray = (char (*)[MAX_SYSCAP_STR_LEN])malloc(bufferLen);
    if (outputArray == NULL) {
        PRINT_ERR("malloc buffer failed, size = %d, errno = %d\n", bufferLen, errno);
        *outputCnt = 0;
        return false;
    }
    (void)memset_s(outputArray, bufferLen, 0, bufferLen);

    *output = outputArray;
    char buffer[MAX_SYSCAP_STR_LEN - 17] = {0}; // 17. size of "SystemCapability."
    char *bufferPos = buffer;
    while (*inputPos != '\0') {
        if (*inputPos == ',') {
            *bufferPos = '\0';
            ret = sprintf_s(*outputArray, MAX_SYSCAP_STR_LEN, "SystemCapability.%s", buffer);
            if (ret == -1) {
                PRINT_ERR("sprintf_s failed\n");
                *outputCnt = 0;
                free(outputArray);
                outputArray = NULL;
                return false;
            }
            bufferPos = buffer;
            outputArray++;
            inputPos++;
            continue;
        }
        *bufferPos++ = *inputPos++;
    }

    *outputCnt = syscapCnt;
    return true;
}