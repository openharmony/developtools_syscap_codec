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
#include "syscap_interface.h"

#define PCID_OUT_BUFFER 32
#define MAX_SYSCAP_STR_LEN 128

#define PRINT_ERR(...) \
    do { \
        printf("ERROR: in file %s at line %d -> ", __FILE__, __LINE__); \
        printf(__VA_ARGS__); \
    } while (0)

bool EncodeOsSyscap(int output[32])
{
    uint8_t *outputArray = (uint8_t *)malloc(sizeof(int) * PCID_OUT_BUFFER);
    if (outputArray == NULL) {
        PRINT_ERR("malloc failed.");
        return false;
    }
    (void)memset_s(outputArray, sizeof(int) * PCID_OUT_BUFFER, 0, sizeof(int) * PCID_OUT_BUFFER);

    uint16_t countBytes = PCID_OUT_BUFFER * sizeof(int);
    for (uint16_t i = 0; i < countBytes; i++) {
        outputArray[i] |= 0XFF;
    }
    int ret = memcpy_s(output, sizeof(int) * PCID_OUT_BUFFER, outputArray, sizeof(int) * PCID_OUT_BUFFER);
    if (ret != 0) {
        PRINT_ERR("memcpy_s failed.");
        free(outputArray);
        return false;
    }
    free(outputArray);
    return true;
}

bool EncodePrivateSyscap(char *output, int *outputLen)
{
    static char syscapStr[MAX_SYSCAP_STR_LEN] = "Systemcapability.Ai.AiEngine";
    int ret = strcpy_s(output, MAX_SYSCAP_STR_LEN, syscapStr);
    if (ret != 0) {
        PRINT_ERR("strcpy_s failed.");
        return false;
    }
    *outputLen = strlen(syscapStr);

    return true;
}