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

#ifndef SINGLE_SYSCAP_LEN
#define SINGLE_SYSCAP_LEN (256 + 17)
#endif // SINGLE_SYSCAP_LEN
#define MAX_MISS_SYSCAP 512
#define PCID_MAIN_BYTES 128
#define PCID_MAIN_INTS  32

#define E_EORROR (-1)
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
bool DecodeOsSyscap(const char input[PCID_MAIN_BYTES], char (**output)[SINGLE_SYSCAP_LEN], int *outputCnt);
bool EncodePrivateSyscap(char **output, int *outputLen);
bool DecodePrivateSyscap(char *input, char (**output)[SINGLE_SYSCAP_LEN], int *outputCnt);
char *DecodeRpcidToStringFormat(const char *inputFile);
/*
 * params:
 *      pcidString, input string format pcid.
 *      rpcidString, input string format rpcid.
 *      result, output comparison results.
 * retval:
 *      E_EORROR, compare failed.
 *      E_OK, compare successful and meet the requirements.
 *      E_APIVERSION, compare successful but api version too low.
 *      E_SYSCAP, compare successful but missing some syscaps.
 *      E_APIVERSION | E_SYSCAP, none of api version and syscap
 *                               meet the requirements.
 * notes:
 *      when return E_APIVERSION, the value of result.targetApiVersion
 *                                is the require api version.
 *      when return E_SYSCAP, the value of result.missSyscapNum is the missing syscaps's numbers.
 *                            result.syscap[] is the array of points to syscap strings.
 *      free variable result by function FreeCompareError.
 */
int32_t ComparePcidString(const char *pcidString, const char *rpcidString, CompareError *result);
int32_t FreeCompareError(CompareError *result);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* _SYSCAP_INTERFACE_H */