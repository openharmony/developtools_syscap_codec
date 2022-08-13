#!/usr/bin/env python
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

table = PrettyTable()
table.hrules = ALL


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
        help="this option will take effect only when the check_target is component_codec. allow multiple json file. default: all bundle.json file",
    )
    args = parser.parse_args()
    return args


def list_to_multiline(l):
    return str(l).lstrip("[").rstrip("]").replace(", ", "\n")


def add_dict_as_table_row(f_table, d_dict):
    s_keys = sorted(list(d_dict.keys()))
    for k in s_keys:
        f_table.add_row([k, list_to_multiline(sorted(list(d_dict.get(k))))])


def read_value_from_json(filepath, key_hierarchy, result_dict):
    """
    :param result_dict: result_dict
    :param key_hierarchy: key_hierarchy list
    :param filepath: fullpath of file
    :return: result_dict, {filepath:value_list}
    """
    if os.path.exists(filepath) is False:
        print('error: file "{}" not exists.'.format(filepath))
        return result_dict
    if os.path.isfile(filepath) is False:
        print('error: "{}" is not a file.')
        return result_dict
    with open(filepath, "r") as f:
        data = json.load(f)
        for key in key_hierarchy:
            try:
                data = data[key]
            except KeyError:
                print(
                    'warning: can\'t find the key:"{}" in file "{}"'.format(
                        key, filepath
                    )
                )
                return result_dict
        data = [x for x in data if len(x) != 0 and x.isspace() == False]
        if len(data) != 0:
            result_dict[filepath] = data
    return result_dict


def collect_syscap_from_codec(filepath):
    arraySyscap_set = set()
    pattern = r'{"(.*)"'
    with open(filepath, "r") as f:
        for line in f:
            syscap = re.search(pattern, line.strip())
            if syscap is not None:
                arraySyscap_set.add(syscap.group(0).lstrip("{").strip('"'))
    return arraySyscap_set


def collect_syscap_from_component(project_path, bundles=None):
    result_dict = dict()
    key_heirarchy = ["component", "syscap"]
    if bundles is None:
        subsystem_list = [
            x
            for x in os.listdir(project_path)
            if os.path.isdir(os.path.join(project_path, x)) and x != "out"
        ]
        for ss in subsystem_list:
            output = os.popen(
                "find {} -name bundle.json".format(os.path.join(project_path, ss))
            )
            for line in output:
                try:
                    read_value_from_json(line.strip(), key_heirarchy, result_dict)
                except Exception as e:
                    print(e.with_traceback())
    else:
        for b in bundles:
            try:
                result_dict = read_value_from_json(b, key_heirarchy, result_dict)
            except Exception as e:
                print(e.with_traceback())
    result_set = set()
    for v in result_dict.values():
        result_set.update(v)
    return result_set, result_dict


def collect_syscap_from_sdk(project_path):
    full_path = os.path.join(project_path, "interface", "sdk-js", "api")
    ts_list = [
        os.path.join(full_path, x) for x in os.listdir(full_path) if x.endswith(".d.ts")
    ]
    syscap_dict = dict()
    pattern = r"\* *@syscap +(.*)"
    syscap_set = set()
    for ts in ts_list:
        with open(ts, "r") as f:
            sub_set = set()
            for line in f:
                syscap = re.search(pattern, line)
                if syscap is not None:
                    ss = syscap.group(0).strip().lstrip("\* @syscap ").strip()
                    sub_set.add(ss)
        syscap_dict[ts] = sub_set
    for v in syscap_dict.values():
        syscap_set.update(v)
    return syscap_set, syscap_dict


def find_files_containes_value(value_set, file_values_dict):
    value_files_dict = dict()
    for v in value_set:
        filename_set = set()
        for file in file_values_dict.keys():
            if v in file_values_dict[file]:
                filename_set.add(file)
        if 0 != len(filename_set):
            value_files_dict[v] = filename_set
    return value_files_dict


def check_component_and_codec(project_path, bundles=None):
    if bundles is not None and len(bundles) > 0:
        component_syscap_set, component_syscap_dict = collect_syscap_from_component(
            project_path, bundles
        )
    else:
        component_syscap_set, component_syscap_dict = collect_syscap_from_component(
            project_path
        )
    arraySyscap_set = collect_syscap_from_codec(
        os.path.join(
            project_path, "developtools", "syscap_codec", "include", "syscap_define.h"
        )
    )
    component_diff_array = component_syscap_set.difference(arraySyscap_set)
    value_files_dict = find_files_containes_value(
        component_diff_array, component_syscap_dict
    )
    array_diff_component = arraySyscap_set.difference(component_syscap_set)
    if 0 == len(component_diff_array) and 0 == len(array_diff_component):
        table.clear()
        table.field_names = ["Component and Codec are Consistent"]
        print(table)
        return
    if 0 != len(component_diff_array):
        table.field_names = ["Syscap Only in Component", "Files"]
        add_dict_as_table_row(table, value_files_dict)
    elif 0 == len(component_diff_array):
        table.field_names = ["All Syscap in Component have been Covered by Codec"]
    print("\n")
    print(table)
    table.clear()
    if 0 != len(array_diff_component):
        table.field_names = ["SysCap Only in Codec"]
        table.add_row([list_to_multiline(sorted(list(array_diff_component)))])
    elif 0 == len(array_diff_component):
        table.field_names = ["All SysCap in Codec have been Covered by Component"]
    print("\n")
    print(table)


def check_component_and_sdk(project_path):
    component_syscap_set, component_syscap_dict = collect_syscap_from_component(
        project_path
    )
    ts_syscap_set, ts_syscap_dict = collect_syscap_from_sdk(project_path)
    ts_diff_component = ts_syscap_set.difference(component_syscap_set)
    value_ts_dict = find_files_containes_value(ts_diff_component, ts_syscap_dict)
    component_diff_ts = component_syscap_set.difference(ts_syscap_set)
    value_component_dict = find_files_containes_value(
        component_diff_ts, component_syscap_dict
    )
    if 0 == len(ts_diff_component) and 0 == len(component_diff_ts):
        table.clear()
        table.field_names = ["SDK and Component are Consistent"]
        print(table)
        return
    table.clear()
    if 0 != len(component_diff_ts):
        table.field_names = ["SysCap Only in Component", "Files"]
        add_dict_as_table_row(table, value_component_dict)
    elif 0 == len(component_diff_ts):
        table.field_names = ["SysCap in Component have been Covered by SDK"]
    print("\n")
    print(table)
    table.clear()
    if 0 != len(ts_diff_component):
        table.field_names = ["SysCap Only in SDK", "Files"]
        add_dict_as_table_row(table, value_ts_dict)
    elif 0 == len(ts_diff_component):
        table.field_names = ["All SysCap in SDK have been Covered by Component"]
    print("\n")
    print(table)


def check_sdk_and_codec(project_path):
    ts_syscap_set, ts_syscap_dict = collect_syscap_from_sdk(project_path)
    arraySyscap_set = collect_syscap_from_codec(
        os.path.join(
            project_path, "developtools", "syscap_codec", "include", "syscap_define.h"
        )
    )
    ts_diff_array = ts_syscap_set.difference(arraySyscap_set)
    value_ts_dict = find_files_containes_value(ts_diff_array, ts_syscap_dict)
    array_diff_ts = arraySyscap_set.difference(ts_syscap_set)
    if 0 == len(ts_diff_array) and 0 == len(array_diff_ts):
        table.clear()
        table.field_names = ["SDK and Codec are Consistent"]
        print(table)
        return
    table.clear()
    if 0 != len(ts_diff_array):
        table.field_names = ["SysCap Only in SDK", "Files"]
        add_dict_as_table_row(table, value_ts_dict)
    elif 0 == len(ts_diff_array):
        table.field_names = ["SysCap in SDK have been Covered by Codec"]
    print("\n")
    print(table)
    table.clear()
    if 0 != len(array_diff_ts):
        table.field_names = ["SysCap Only in Codec"]
        table.add_row([list_to_multiline(sorted(list(array_diff_ts)))])
    elif 0 == len(array_diff_ts):
        table.field_names = ["SysCap in Codec have been Covered by SDK"]
    print("\n")
    print(table)


def main():
    args = get_args()
    project_path = args.project_path
    check_target = args.check_target
    bundles = args.bundles
    if "component_codec" == check_target:
        if bundles is None:
            check_component_and_codec(project_path)
        else:
            if 0 == len(bundles):
                print(r"error: '--bundles' parameter is specified, but has no value")
            else:
                check_component_and_codec(project_path, bundles)
    elif "component_sdk" == check_target:
        check_component_and_sdk(project_path)
    elif "sdk_codec" == check_target:
        check_sdk_and_codec(project_path)


if __name__ == "__main__":
    main()
