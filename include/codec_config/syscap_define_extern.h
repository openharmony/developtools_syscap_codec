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

#ifndef SYSCAP_DEFINE_EXTERN_H
#define SYSCAP_DEFINE_EXTERN_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

#ifndef SYSCAP_DEFINE_H
#define SINGLE_SYSCAP_LEN (256 + 17)

typedef struct SystemCapabilityWithNum {
    char str[SINGLE_SYSCAP_LEN];
    uint16_t num;
} SyscapWithNum;

#endif

/*
 * New SyscapNum must be added last and
 * don't delete anyone, just comment after it.
 */
typedef enum SystemCapabilityNumExtern {
    SYSCAP_EXTERN_BEGIN = 500,
    ENUM_SYSCAP_AAA,
    ENUM_SYSCAP_BBB,
    ENUM_SYSCAP_CCC,
    // Add before here
    SYSCAP_EXTERN_NUM_MAX = 960
} SyscapNumExtern;


/* Sort by SyscapNum */
const static SyscapWithNum g_arraySyscapExtern[] = {
    {"SystemCapability.AAA.AAAA", ENUM_SYSCAP_AAA},
    {"SystemCapability.BBB.BBBB", ENUM_SYSCAP_BBB},
    {"SystemCapability.CCC.CCCC", ENUM_SYSCAP_CCC},
};

uint32_t g_arraySyscapExternNum = sizeof(g_arraySyscapExtern) / sizeof(SyscapWithNum);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif  // SYSCAP_DEFINE_EXTERN_H
