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

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

typedef struct ProductCompatibilityIDHead {
    uint16_t apiVersion : 15;
    uint16_t apiVersionType : 1;
    uint16_t systemType : 3;
    uint16_t reserved : 13;
    uint32_t manufacturerID;
} PCIDHead; // to do


bool EncodeOsSyscap(int output[32]);
bool DecodeOsSyscap(int input[32], char **output, int *outputCnt, int** outputLen);
bool EncodePrivateSyscap(char *output, int *outputLen);
bool DecodePrivateSyscap(char *input, int inputLen, char *output, int *outputCnt, int **outputLen);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* _SYSCAP_INTERFACE_H */