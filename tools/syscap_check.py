#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2022 Huawei Device Co., Ltd.
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

import os
import json
import re
import argparse
from prettytable import PrettyTable, ALL


def get_args():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument(
        "-p",
        "--project_path",
        default=r"./",
        type=str,
        help="root path of project. default: ./",
    )
    parser.add_argument(
        "-t",
        "--check_target",
        type=str,
        choices=["component_codec", "component_sdk", "sdk_codec"],
        required=True,
        help="the target to be compared",
    )
    parser.add_argument(
        "-b",
        "--bundles",
        nargs="*",
        type=str,
        help="option take effect only when the check_target is component_codec. allow multiple json file. "
             "default: all bundle.json file",
    )
    args = parser.parse_args()
    return args


def list_to_multiline(target_list: list):
    return str(target_list).lstrip("[").rstrip("]").replace(", ", "\n")


def convert_set_to_sorted_list(target_set) -> list:
    return sorted(list(target_set))


def add_dict_as_table_row(f_table: PrettyTable, d_dict: dict, out_converter=list_to_multiline) -> None:
    s_keys = convert_set_to_sorted_list(d_dict.keys())
    for i, k in enumerate(s_keys):
        f_table.add_row([i + 1, k, out_converter(convert_set_to_sorted_list(d_dict.get(k)))])


def bundle_syscap_post_handler(syscap: str) -> str:
    return syscap.split('=')[0].strip()


def read_value_from_json(filepath: str,
                         key_hierarchy: tuple,
                         result_dict: dict,
                         post_handler=None
                         ) -> None:
    if os.path.exists(filepath) is False:
        print('error: file "{}" not exist.'.format(filepath))
        return
    if not os.path.isfile(filepath):
        print('error: "{}" is not a file.')
        return
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
        for key in key_hierarchy:
            try:
                data = data[key]
            except KeyError:
                return
            finally:
                pass
    data = [post_handler(x) for x in data if len(x) != 0 and not x.isspace()]
    if len(data) != 0:
        result_dict[filepath] = data


def collect_syscap_from_codec(filepath: str, pattern: str = r'{"(.*)"') -> tuple:
    """
    从syscap_define.h收集syscap
    :param filepath: 文件的路径
    :param pattern: 匹配syscap的规则
    :return: syscap_define.h中声明的syscap集合
    """
    array_syscap_set = set()
    array_syscap_dict = dict()
    ptrn = re.compile(pattern)
    with open(filepath, "r") as f:
        content = f.read()
        array_syscap_set.update(re.findall(ptrn, content))
    array_syscap_dict[filepath] = list()
    for v in array_syscap_set:
        array_syscap_dict.get(filepath).append(v)
    return array_syscap_set, array_syscap_dict


def collect_syscap_from_component(project_path: str,
                                  black_dirs: tuple,
                                  key_heirarchy: tuple,
                                  bundles: list = None,
                                  ) -> tuple:
    """
    从部件的bundle.json中收集syscap
    :param project_path: 项目根路径
    :param black_dirs: 根路径下的一级目录的黑名单，不扫描这些bundle.json下面的内容
    :param key_heirarchy: bundle.json中syscap所在的key的元组
    :param bundles: 指定的bundle.json
    :return: syscap_set，文件名和其syscap list组成的dict
    """
    result_dict = dict()
    if bundles is None:
        search_dir_list = [
            os.path.join(project_path, x)
            for x in os.listdir(project_path)
            if os.path.isdir(os.path.join(project_path, x)) and x not in black_dirs
        ]
        for folder in search_dir_list:
            output = os.popen("find {} -name bundle.json".format(folder))
            for line in output:
                line = line.strip()
                read_value_from_json(line, key_heirarchy, result_dict, post_handler=bundle_syscap_post_handler)
    else:
        for bundle in bundles:
            read_value_from_json(bundle, key_heirarchy, result_dict, post_handler=bundle_syscap_post_handler)
    result_set = set()
    for v in result_dict.values():
        result_set.update(v)
    return result_set, result_dict


def sdk_syscap_post_handler(syscap: str) -> str:
    return syscap.strip().lstrip("*").lstrip().lstrip("*@syscap").strip()


def collect_syscap_from_sdk(ts_path: str,
                            pattern: str = r"\* *@syscap +((?i)SystemCapability\..*)",
                            post_handler=None
                            ) -> tuple:
    """
    从sdk下的*.d.ts中收集syscap
    :param ts_path: ts文件的所在路径
    :param pattern: 匹配syscap的pattern
    :param post_handler: 对匹配到的syscap进行后置处理
    :return: syscap_set，和由文件名、syscap list组成的dict
    """
    ts_list = list()
    for item in os.listdir(ts_path):
        file_path = os.path.join(ts_path, item)
        if file_path.endswith(".d.ts") and os.path.isfile(file_path):
            ts_list.append(file_path)
    syscap_dict = dict()
    ptrn = re.compile(pattern)
    for ts in ts_list:
        with open(ts, 'r') as f:
            content = f.read()
            sub_syscap_list = re.findall(ptrn, content)
            sub_syscap_set = set()
            for syscap in sub_syscap_list:
                sub_syscap_set.add(post_handler(syscap))
            syscap_dict[ts] = sub_syscap_set
    syscap_set = set()
    for v in syscap_dict.values():
        syscap_set.update(v)
    return syscap_set, syscap_dict


def find_files_containes_value(value_set: set, file_values_dict: dict) -> dict:
    """
    查看包含指定值的文件
    :param value_set: 指定值
    :param file_values_dict: 文件和值组成的dict
    :return: 值和文件组成的dict
    """
    value_files_dict = dict()
    for v in value_set:
        filename_set = set()
        for file in file_values_dict.keys():
            if v in file_values_dict[file]:
                filename_set.add(file)
        if 0 != len(filename_set):
            value_files_dict[v] = filename_set
    return value_files_dict


def mutual_diff(a_set: set, b_set: set) -> tuple:
    return a_set.difference(b_set), b_set.difference(a_set)


def print_inconsistent(diff_set: set, a_name: str, b_name: str, table: PrettyTable,
                       value_file_dict: dict) -> None:
    table.clear()
    if len(diff_set) != 0:
        table.field_names = ["index", "SysCap only in {}".format(a_name), "Files"]
        add_dict_as_table_row(table, value_file_dict)
    elif len(diff_set) == 0:
        table.field_names = ["All SysCap in {} have been Covered by {}".format(a_name, b_name)]
    print(table)
    print()


def print_consistent(a_diff_b_set: set, b_diff_a_set: set, table: PrettyTable, a_name: str, b_name: str) -> bool:
    if len(a_diff_b_set) == 0 and len(b_diff_a_set) == 0:
        table.field_names = ["{} and {} are Consistent".format(a_name, b_name)]
        print(table)
        print()
        return True
    return False


def print_check_result(a_diff_b_set: set,
                       b_diff_a_set: set,
                       a_name: str,
                       b_name: str,
                       a_value_file_dict: dict,
                       b_value_file_dict: dict,
                       ) -> None:
    f_table = PrettyTable()
    f_table.hrules = ALL
    consistent_flag = print_consistent(a_diff_b_set, b_diff_a_set, f_table, a_name, b_name)
    if not consistent_flag:
        print_inconsistent(a_diff_b_set, a_name, b_name, f_table, a_value_file_dict)
        print_inconsistent(b_diff_a_set, b_name, a_name, f_table, b_value_file_dict)


def check_component_and_codec(project_path, syscap_define_path: str, component_black_dirs: tuple,
                              bundle_key_heirarchy: tuple, bundles=None):
    component_syscap_set, component_syscap_dict = collect_syscap_from_component(
        project_path, black_dirs=component_black_dirs, key_heirarchy=bundle_key_heirarchy, bundles=bundles
    )
    array_syscap_set, array_syscap_dict = collect_syscap_from_codec(syscap_define_path)
    component_diff_array, array_diff_component = mutual_diff(component_syscap_set, array_syscap_set)
    value_component_dict = find_files_containes_value(
        component_diff_array, component_syscap_dict
    )
    value_h_dict = find_files_containes_value(array_diff_component, array_syscap_dict)
    print_check_result(component_diff_array, array_diff_component, a_name="Component", b_name="Codec",
                       a_value_file_dict=value_component_dict, b_value_file_dict=value_h_dict)


def check_component_and_sdk(project_path, component_black_dirs: tuple, component_key_heirarchy: tuple, sdk_path: str):
    component_syscap_set, component_syscap_dict = collect_syscap_from_component(
        project_path, black_dirs=component_black_dirs, key_heirarchy=component_key_heirarchy
    )
    ts_syscap_set, ts_syscap_dict = collect_syscap_from_sdk(ts_path=sdk_path,
                                                            post_handler=sdk_syscap_post_handler)
    component_diff_ts, ts_diff_component = mutual_diff(component_syscap_set, ts_syscap_set)
    value_ts_dict = find_files_containes_value(ts_diff_component, ts_syscap_dict)
    value_component_dict = find_files_containes_value(
        component_diff_ts, component_syscap_dict
    )
    print_check_result(component_diff_ts, ts_diff_component, a_name="Component", b_name="SDK",
                       a_value_file_dict=value_component_dict, b_value_file_dict=value_ts_dict)


def check_sdk_and_codec(syscap_define_path: str, sdk_path: str) -> None:
    ts_syscap_set, ts_syscap_dict = collect_syscap_from_sdk(ts_path=sdk_path,
                                                            post_handler=sdk_syscap_post_handler)
    array_syscap_set, array_syscap_dict = collect_syscap_from_codec(syscap_define_path)
    ts_diff_array, array_diff_ts = mutual_diff(ts_syscap_set, array_syscap_set)
    value_ts_dict = find_files_containes_value(ts_diff_array, ts_syscap_dict)
    value_h_dict = find_files_containes_value(array_diff_ts, array_syscap_dict)
    print_check_result(ts_diff_array, array_diff_ts, a_name="SDK", b_name="Codec", a_value_file_dict=value_ts_dict,
                       b_value_file_dict=value_h_dict)


def main():
    args = get_args()
    project_path = args.project_path
    check_target = args.check_target
    bundles = args.bundles
    syscap_define_path = os.path.join(project_path, "developtools", "syscap_codec", "include", "syscap_define.h")
    ts_path = os.path.join(project_path, "interface", "sdk-js", "api")
    component_black_dirs = ("out",)
    bundle_syscap_heirarchy = ("component", "syscap")
    if (bundles is not None or (bundles is not None and len(bundles) != 0)) and check_target != "component_codec":
        print("error: --bundles could only be used with -t component_codec")
        return
    if "component_sdk" == check_target:
        check_component_and_sdk(project_path, component_black_dirs, bundle_syscap_heirarchy, sdk_path=ts_path)
    elif "sdk_codec" == check_target:
        check_sdk_and_codec(syscap_define_path=syscap_define_path, sdk_path=ts_path)
    elif "component_codec" == check_target:
        if bundles is not None and len(bundles) == 0:
            print(r"error: '--bundles' parameter is specified, but has no value")
        else:
            check_component_and_codec(project_path, syscap_define_path, component_black_dirs=component_black_dirs,
                                      bundle_key_heirarchy=bundle_syscap_heirarchy, bundles=bundles)


if __name__ == "__main__":
    main()

