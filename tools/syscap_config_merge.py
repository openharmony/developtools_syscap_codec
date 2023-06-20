#! /usr/bin/python3
# -*- coding: utf-8 -*-
# Copyright (c) 2023 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

'''
注意：
1. 扩展syscap头文件的枚举定义，须在开始位置标记最小值，且必须大于等于500。
'''
import argparse

LICENCE = '''/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
 
'''

BEFORE_ENUM = '''#ifndef SYSCAP_DEFINE_H
#define SYSCAP_DEFINE_H

#include <stdint.h>

#define SINGLE_SYSCAP_LEN (256 + 17)
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

typedef struct SystemCapabilityWithNum {
    char str[SINGLE_SYSCAP_LEN];
    uint16_t num;
} SyscapWithNum;

/*
 * New SyscapNum must be added last and
 * don't delete anyone, just comment after it.
 */
'''

AFTER_STRUCT = '''
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif  // SYSCAP_DEFINE_H
'''


def gen_define_enum(enum:list):
    header = 'typedef enum SystemCapabilityNum {\n'
    tail = '} SyscapNum;\n\n'
    trunk = ''.join(enum)
    return header + trunk + tail


def gen_define_array(stru:list):
    header = 'const static SyscapWithNum g_arraySyscap[] = {\n'
    tail = '};\n\n'
    trunk = ''.join(stru)
    return header + trunk + tail


def read_syscap(path):
    syscap_enum = []
    op_flag = False
    with open(path, 'r') as fb:
        f = fb.readlines()
    for line in f:
        if line.startswith('typedef enum '):
            op_flag = True
            continue
        elif op_flag and line.startswith('}'):
            break
        if op_flag:
            syscap_enum.append(line)

    syscap_stru = []
    op_flag = False
    for line in f:
        if line.startswith('const static SyscapWithNum '):
            op_flag = True
            continue
        elif op_flag and line.startswith('}'):
            op_flag = False
            break
        if op_flag:
            syscap_stru.append(line)

    return syscap_enum, syscap_stru
            

def merge_define(base, extern):
    base_enmu, base_stru = read_syscap(base)
    ext_enmu, ext_stru = read_syscap(extern)
    
    if '500' in base_enmu[-1] and '500,' in ext_enmu[0]:
        res_enmu = base_enmu[:-1] + ext_enmu
    else:
        res_enmu = base_enmu + ext_enmu
    
    res_stru = base_stru + ext_stru
    return res_enmu, res_stru


def assemble_header_file(fenum, fstru):
    enum, stru = merge_define(fenum, fstru)
    enum_def = gen_define_enum(enum)
    stru_def = gen_define_array(stru)
    return LICENCE + BEFORE_ENUM + enum_def + stru_def + AFTER_STRUCT


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base',
                        help='base syscap config header.')
    parser.add_argument('--extern',
                        help='extern syscap config header.')
    parser.add_argument('--output',
                        help='output app file')
    arguments = parser.parse_args()
    return arguments


if __name__ == '__main__':
    args = parse_args()
    base_file = args.base
    extern_file = args.extern
    output_file = args.output
    
    full = assemble_header_file(base_file, extern_file)
    with open(output_file, 'w') as out:
        out.writelines(full)

