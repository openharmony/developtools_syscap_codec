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

#ifndef _SYSCAP_INTERFACE_H
#define _SYSCAP_INTERFACE_H

#include <stdbool.h>
#include <stdint.h>

#define MAX_MISS_SYSCAP 512
#define SINGLE_SYSCAP_LEN 256
#define PCID_MAIN_BYTES 128
#define E_OK 0
#define E_APIVERSION 1
#define E_SYSCAP 2

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

typedef struct CompareErrorMessage {
    char *syscap[MAX_MISS_SYSCAP];
    uint16_t missSyscapNum;
    uint16_t targetApiVersion;
} CompareError;

bool EncodeOsSyscap(char *output, int len);
bool DecodeOsSyscap(char input[PCID_MAIN_BYTES], char (**output)[SINGLE_SYSCAP_LEN], int *outputCnt);
bool EncodePrivateSyscap(char **output, int *outputLen);
bool DecodePrivateSyscap(char *input, char (**output)[SINGLE_SYSCAP_LEN], int *outputCnt);
char *DecodeRpcidToStringFormat(char *inputFile);
int32_t ComparePcidString(char *pcidString, char *rpcidString, CompareError *result);
int32_t FreeCompareError(CompareError *result);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* _SYSCAP_INTERFACE_H */