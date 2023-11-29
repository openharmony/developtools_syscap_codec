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
import logging
import os
import json
import argparse

logging.basicConfig(level=logging.INFO)


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
        "-o",
        "--output_path",
        default=r"./",
        type=str,
        help="path of output file. default: ./",
    )
    parser.add_argument(
        "-e",
        "--error_output",
        action='store_true',
        help="output error_list or not. default not",
    )
    args = parser.parse_args()
    return args


def dict_to_json(output_path: str, syscaps_dict: dict, error_output: bool, error_dict: dict):
    logging.info("start generate syscap json...")
    filename = os.path.join(output_path, 'component_list_syscap.json')
    f = open(filename, 'w', encoding='utf-8')
    json.dump(syscaps_dict, f)
    logging.info("end...")
    f.close()
    if error_output:
        logging.info("start generate error json......")
        filename = os.path.join(output_path, 'error_dict.json')
        error_f = open(filename, 'w', encoding='utf-8')
        json.dump(error_dict, error_f)
        logging.info("end...")
        error_f.close()


def check_syscap(syscap_str: str):
    syscap = syscap_str.split(' = ')
    if syscap[-1].lower() == 'false':
        return False
    else:
        return syscap[0]


def read_json_file(bundle_json_path: str) -> tuple:
    bundle_data = dict()
    bundle_syscap_list = list()
    error_list = dict()
    try:
        f = open(bundle_json_path, 'r', encoding='utf-8')
        bundle_data = json.load(f)
        f.close()
    except FileNotFoundError as e:
        error_list[bundle_json_path] = str(e)
    except Exception as e:
        error_list[bundle_json_path] = str(e)
    if bundle_data:
        component_data = bundle_data.get("component")
        component_syscaps_list = component_data.get("syscap")
        if component_syscaps_list:
            for i in component_syscaps_list:
                i = check_syscap(i)
                if i:
                    bundle_syscap_list.append(i)
    return bundle_syscap_list, error_list


def get_all_components_path(components_file_path: str):
    try:
        f = open(components_file_path, 'r', encoding='utf-8')
        path_dict = json.load(f)
        f.close()
        return path_dict
    except FileNotFoundError:
        logging.error(r"ERROR:PATH ERROR")
        return {}


def path_component_to_bundle(path: str) -> str:
    bundle_json_path = os.path.join(path, 'bundle.json')
    return bundle_json_path


def handle_bundle_json_file(component_path_list: list) -> tuple:
    logging.info("start collect syscap path...")
    syscap_list = list()
    error_dict = dict()
    for path in component_path_list:
        bundle_json_path = path_component_to_bundle(path)
        bundle_syscap_list, error_list = read_json_file(bundle_json_path)
        syscap_list.extend(bundle_syscap_list)
        error_dict.update(error_list)

    return {"SysCaps": syscap_list}, error_dict


def format_component_path(component_path: str):
    sep_list = ['\\', '/']
    sep_list.remove(os.sep)
    component_path = component_path.replace(sep_list[0], os.sep)
    return component_path


def traversal_path(path_dict: dict, project_path: str) -> list:
    component_path_list = list()
    for _, v in path_dict.items():
        component_path = os.path.join(project_path, v)
        component_path = format_component_path(component_path)
        component_path_list.append(component_path)
    return component_path_list


def collect_all_syscap(components_path: str, project_path: str) -> tuple:
    """
    从各部件收集syscap并返回字典
    :param components_path: 必选部件json文件的路径
    :param project_path: 项目根路径
    :return: 所有典型品类syscap字典
    """
    components_path_dict = get_all_components_path(components_path)
    if components_path_dict:
        logging.info("start collect component path...")
        component_path_list = traversal_path(components_path_dict, project_path)
        syscap_dict, error_dict = handle_bundle_json_file(component_path_list)
        return syscap_dict, error_dict
    else:
        return 0, 0


def components_path_handler(project_path):
    components_path = os.path.join(project_path, "out", "rk3568", "build_configs", "parts_info",
                                   "parts_path_info.json")
    return components_path


def main():
    args = get_args()
    project_path = args.project_path
    output_path = args.output_path
    error_output = args.error_output
    components_path = components_path_handler(project_path)
    syscap_dict, error_dict = collect_all_syscap(components_path, project_path)
    if syscap_dict:
        dict_to_json(output_path, syscap_dict, error_output, error_dict)


if __name__ == "__main__":
    main()
