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

int main(void)
{
    size_t size = sizeof(g_arraySyscap) / sizeof(SyscapWithNum);
    size_t flag = 0;

    for (size_t i = 0; i < size; i++) {
        if (g_arraySyscap[i].num != i) {
            printf("[Error][syscap_define.h]: %s -> num(%u) should be %lu.\n",
                g_arraySyscap[i].str, g_arraySyscap[i].num, i);
            flag++;
        }
    }
    if (flag == 0) {
        return 0;
    } else {
        return -1;
    }
}