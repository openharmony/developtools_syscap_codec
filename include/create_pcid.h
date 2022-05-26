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

#ifndef _CREATE_PCID_H
#define _CREATE_PCID_H

#include <stdint.h>

#define MAX_OS_SYSCAP_NUM 960
#define TYPE_FILE 1
#define TYPE_STRING 2

typedef struct ProductCompatibilityID {
    uint16_t apiVersion : 15;
    uint16_t apiVersionType : 1;
    uint16_t systemType : 3;
    uint16_t reserved : 13;
    uint32_t manufacturerID;
    uint8_t osSyscap[MAX_OS_SYSCAP_NUM / 8];
} PCIDMain;

int32_t CreatePCID(char *inputFile, char *outDirPath);
int32_t DecodePCID(char *inputFile, char *outDirPath);
int32_t DecodeStringPCID(char *input, char *outDirPath, int type);
#endif