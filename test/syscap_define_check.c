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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "syscap_define.h"

int CheckSortBySyscapNum(void)
{
    int size = (int)sizeof(g_arraySyscap) / sizeof(SyscapWithNum);
    int flag = 0;

    for (int i = 0; i < size; i++) {
        if (g_arraySyscap[i].num != i) {
            printf("[ERROR][syscap_define.h]: %s -> num(%u) should be %d.\n",
                g_arraySyscap[i].str, g_arraySyscap[i].num, i);
            flag++;
        }
    }
    return flag;
}

int CheckSyscapNumOrder(void)
{
    if (COMMUNICATION_NETMANAGER_VPN != 227) { // 227, special number
        printf("[ERROR][syscap_define.h]: "
            "enum value 'COMMUNICATION_NETMANAGER_VPN' should be 227. "
            "Please don't change original SyscapNum's enum value order, "
            "and add the new enum value at the end.\n");
        return 1;
    }
    return 0;
}

int main(void)
{
    if (CheckSyscapNumOrder() != 0) {
        return -1;
    }
    if (CheckSortBySyscapNum() != 0) {
        return -1;
    }
    return 0;
}