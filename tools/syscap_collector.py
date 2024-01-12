#!/usr/bin/env python3
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
import logging
import os
import json
import argparse
import stat


def get_args():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument(
        "-p",
        "--project_path",
        default=r"",
        type=str,
        help="root path of project. default: ./",
    )
    args = parser.parse_args()
    return args


def dict_to_json(output_path: str, syscaps_dict: dict):
    """
    output diff product syscaps json to output path
    :param output_path:
    :param syscaps_dict:
    :return:
    """
    print("start generate syscap json...")
    flags = os.O_WRONLY | os.O_CREAT
    modes = stat.S_IWUSR | stat.S_IRUSR
    for product_name, syscaps_list in syscaps_dict.items():
        filename = os.path.join(output_path, f'{product_name}.json')
        with os.fdopen(os.open(filename, flags, modes), 'w') as f:
            json.dump({'SysCaps': syscaps_list}, f)
    print("end...")


def check_syscap(syscap_str: str):
    syscap = syscap_str.split(' = ')
    if syscap[-1].lower() == 'false':
        return False
    else:
        return syscap[0]


def bundle_syscap_list_handler(bundle_syscap_list: list, component_syscaps_list: list):
    """
    check syscap
    :param bundle_syscap_list:
    :param component_syscaps_list:
    :return:
    """
    for component_syscap in component_syscaps_list:
        component_syscap = check_syscap(component_syscap)
        if component_syscap:
            bundle_syscap_list.append(component_syscap)
    return bundle_syscap_list


def read_json_file(bundle_json_path: str):
    bundle_syscap_list = list()
    error_list = dict()
    try:
        with open(bundle_json_path, 'r', encoding='utf-8') as f:
            bundle_data = json.load(f)
            component_data = bundle_data.get("component")
            component_syscaps_list = component_data.get("syscap")
            if component_syscaps_list:
                bundle_syscap_list = bundle_syscap_list_handler(bundle_syscap_list, component_syscaps_list)
    except FileNotFoundError as e:
        error_list[bundle_json_path] = str(e)
    except Exception as e:
        error_list[bundle_json_path] = str(e)
    return bundle_syscap_list, error_list


def get_all_components_path(components_file_path: str):
    try:
        with open(components_file_path, 'r', encoding='utf-8') as f:
            path_dict = json.load(f)
        return path_dict
    except FileNotFoundError:
        logging.error(r"PATH ERROR")
        return {}


def path_component_to_bundle(path: str) -> str:
    bundle_json_path = os.path.join(path, 'bundle.json')
    return bundle_json_path


def handle_bundle_json_file(component_path_dict: dict):
    """
    from product required part bundle.json to all products parts list
    :param component_path_dict:
    :return: all products parts list
    """
    print("start collect syscap path...")
    syscap_dict = dict()
    errors_list = list()
    for product_name, path_list in component_path_dict.items():
        bundles_list = list()
        for path in path_list:
            bundle_json_path = path_component_to_bundle(path)
            bundle_syscap_list, error_list = read_json_file(bundle_json_path)
            bundles_list.extend(bundle_syscap_list)
            errors_list.extend(error_list)
        syscap_dict.update({product_name: bundles_list})
    return syscap_dict, errors_list


def format_component_path(component_path: str):
    sep_list = ['\\', '/']
    sep_list.remove(os.sep)
    component_path = component_path.replace(sep_list[0], os.sep)
    return component_path


def traversal_path(parts_path_info: dict, project_path: str, product_define_dict):
    component_path_dict = dict()
    for product_name, component_name_list in product_define_dict.items():
        component_paths = list()
        for component_name in component_name_list:
            component_relpath = parts_path_info.get(component_name)
            if component_relpath:
                component_path = os.path.join(project_path, component_relpath)
                component_path = format_component_path(component_path)
                component_paths.append(component_path)
            else:
                logging.error(f'can\'t find component_name : {component_name}')
        component_path_dict.update({product_name: component_paths})
    return component_path_dict


def collect_all_product_component_syscap_dict(parts_path_info: dict, project_path: str, product_define_dict):
    """
    get all syscap to dict
    :param parts_path_info:
    :param project_path:
    :param product_define_dict:
    :return:
    """
    if parts_path_info:
        print("start collect component path...")
        component_path_dict = traversal_path(parts_path_info, project_path, product_define_dict)
        syscap_dict, errors_list = handle_bundle_json_file(component_path_dict)
        return syscap_dict, errors_list
    else:
        return 0, 0


def get_subsystem_info(subsystem_config_file, source_root_dir):
    """
    get subsystem name and subsystem path from oh/build/subsystem_config.json
    :param subsystem_config_file: subsystem_config_file path
    :param source_root_dir: oh project path
    :return: subsystem name and subsystem path
    """
    subsystem_configs = scan(subsystem_config_file, source_root_dir)
    _all_components_path = []
    for _, value in subsystem_configs.get('subsystem').items():
        for i in value.get('build_files'):
            _all_components_path.append(i)
    return subsystem_configs.get('subsystem')


def _check_path_prefix(paths):
    allow_path_prefix = ['vendor', 'device']
    result = list(
        filter(lambda x: x is False,
               map(lambda p: p.split('/')[0] in allow_path_prefix, paths)))
    return len(result) <= 1


def traversal_files(subsystem_path, _files):
    for item in os.scandir(subsystem_path):
        if is_symlik(item.path):
            continue
        elif item.is_file() and item.name == 'ohos.build':
            _files.append(item.path)
        elif item.is_file() and item.name == 'bundle.json':
            _files.append(item.path)
        elif item.is_dir():
            traversal_files(item, _files)
    return _files


def get_file_type(file_path):
    if os.path.islink(file_path):
        return 'symlink'
    elif os.path.isfile(file_path):
        return 'file'
    elif os.path.isdir(file_path):
        return 'directory'
    else:
        return 'unknown'


def is_symlik(file_path):
    file_type = get_file_type(file_path)
    if file_type == 'symlink':
        link_target = os.readlink(file_path)
        return link_target != file_type
    return False


def _scan_build_file(subsystem_path):
    _files = []
    _bundle_files = []
    try:
        _files = traversal_files(subsystem_path, _files)
    except FileNotFoundError:
        print(f"read file {subsystem_path} failed.")
    return _files


def scan(subsystem_config_file, source_root_dir):
    subsystem_infos = _read_config(subsystem_config_file)
    _default_subsystem = {"build": "build"}
    subsystem_infos.update(_default_subsystem)
    no_src_subsystem = {}
    _build_configs = {}
    for key, val in subsystem_infos.items():
        _all_build_config_files = []
        if not isinstance(val, list):
            val = [val]
        else:
            if not _check_path_prefix(val):
                raise Exception("subsystem '{}' path configuration is incorrect.".format(key), "2013")
        _info = {'path': val}
        for _path in val:
            _subsystem_path = os.path.join(source_root_dir, _path)
            _build_config_files = _scan_build_file(_subsystem_path)
            _all_build_config_files.extend(_build_config_files)
        if _all_build_config_files:
            _info['build_files'] = _all_build_config_files
            _build_configs[key] = _info
        else:
            no_src_subsystem[key] = val

    scan_result = {
        'source_path': source_root_dir,
        'subsystem': _build_configs,
    }
    print('subsystem config scan completed')
    return scan_result


def _read_config(subsystem_config_file):
    if not os.path.exists(subsystem_config_file):
        raise Exception("config file '{}' doesn't exist.".format(subsystem_config_file), "2013")
    subsystem_config = _read_json_file(subsystem_config_file)
    if subsystem_config is None:
        raise Exception("read file '{}' failed.".format(subsystem_config_file), "2013")

    subsystem_info = {}
    for key, val in subsystem_config.items():
        if 'path' not in val:
            raise Exception("subsystem '{}' not config path.".format(key), "2013")
        subsystem_info[key] = val.get('path')
    return subsystem_info


def read_build_file(ohos_build_file):
    if not os.path.exists(ohos_build_file):
        raise Exception("config file '{}' doesn't exist.".format(ohos_build_file), "2014")
    subsystem_config = _read_json_file(ohos_build_file)
    if not subsystem_config:
        raise Exception("read file '{}' failed.".format(ohos_build_file), "2014")
    return subsystem_config


class BundlePartObj(object):
    def __init__(self, bundle_config_file):
        self._build_config_file = bundle_config_file
        self._loading_config()

    def _loading_config(self):
        if not os.path.exists(self._build_config_file):
            raise Exception("file '{}' doesn't exist.".format(
                self._build_config_file), "2011")
        self.bundle_info = _read_json_file(self._build_config_file)
        if not self.bundle_info:
            raise Exception("read file '{}' failed.".format(
                self._build_config_file), "2011")

    def to_ohos_build(self):
        _component_info = self.bundle_info.get('component')
        _subsystem_name = _component_info.get('subsystem')
        _part_name = _component_info.get('name')
        _bundle_build = _component_info.get('build')
        _ohos_build_info = dict()
        _ohos_build_info['subsystem'] = _subsystem_name
        _part_info = {}
        module_list = []
        if _component_info.get('build').__contains__('sub_component'):
            _part_info['module_list'] = _component_info.get('build').get(
                'sub_component')
        elif _component_info.get('build').__contains__('modules'):
            _part_info['module_list'] = _component_info.get(
                'build').get('modules')
        elif _component_info.get('build').__contains__('group_type'):
            _module_groups = _component_info.get('build').get('group_type')
            for _group_type, _module_list in _module_groups.items():
                _key = '{}:{}'.format(_subsystem_name, _part_name)
            _part_info['module_list'] = module_list
        if 'inner_kits' in _bundle_build:
            _part_info['inner_kits'] = _bundle_build.get('inner_kits')
        elif 'inner_api' in _bundle_build:
            _part_info['inner_kits'] = _bundle_build.get('inner_api')
        if 'features' in _component_info:
            _part_info['feature_list'] = _component_info.get('features')
        if 'syscap' in _component_info:
            _part_info['system_capabilities'] = _component_info.get('syscap')
        if 'hisysevent_config' in _component_info:
            _part_info['hisysevent_config'] = _component_info.get(
                'hisysevent_config')
        _part_info['part_deps'] = _component_info.get('deps', {})
        _part_info['part_deps']['build_config_file'] = self._build_config_file
        _ohos_build_info['parts'] = {_part_name: _part_info}
        return _ohos_build_info


class LoadBuildConfig(object):
    """load build config file and parse configuration info."""

    def __init__(self, source_root_dir, subsystem_build_info, subsystem_name):
        self._source_root_dir = source_root_dir
        self._build_info = subsystem_build_info
        self._is_load = False
        self._parts_variants = {}
        self._part_list = {}
        self._part_targets_label = {}
        self._subsystem_name = subsystem_name
        self._parts_info_dict = {}
        self._phony_targets = {}
        self._parts_path_dict = {}
        self._part_hisysevent_config = {}
        self._parts_module_list = {}
        self._parts_deps = {}

    def _merge_build_config(self):
        _build_files = self._build_info.get('build_files')
        is_thirdparty_subsystem = False
        if _build_files[0].startswith(self._source_root_dir + 'third_party'):
            is_thirdparty_subsystem = True
        subsystem_name = None
        parts_info = {}
        parts_path_dict = {}
        for _build_file in _build_files:
            if _build_file.endswith('bundle.json'):
                bundle_part_obj = BundlePartObj(_build_file)
                _parts_config = bundle_part_obj.to_ohos_build()
            else:
                _parts_config = read_build_file(_build_file)
            _subsystem_name = _parts_config.get('subsystem')
            if not is_thirdparty_subsystem and subsystem_name and _subsystem_name != subsystem_name:
                raise Exception(
                    "subsystem name config incorrect in '{}'.".format(
                        _build_file), "2014")
            subsystem_name = _subsystem_name
            _curr_parts_info = _parts_config.get('parts')
            for _pname in _curr_parts_info.keys():
                parts_path_dict[_pname] = os.path.relpath(
                    os.path.dirname(_build_file), self._source_root_dir)
            parts_info.update(_curr_parts_info)
        subsystem_config = dict()
        subsystem_config['subsystem'] = subsystem_name
        subsystem_config['parts'] = parts_info
        return subsystem_config, parts_path_dict

    def parse(self):
        """parse part info from build config file."""
        if self._is_load:
            return
        subsystem_config, parts_path_dict = self._merge_build_config()
        parts_config = subsystem_config.get('parts')
        self._parts_module_list.update(parts_config)
        self._parts_path_dict = parts_path_dict
        self._is_load = True

    def parts_path_info(self):
        """parts to path info."""
        self.parse()
        return self._parts_path_dict

    def parts_info_filter(self, save_part):
        if save_part is None:
            raise Exception
        self._parts_info_dict = {
            key: value for key, value in self._parts_info_dict.items() if key in save_part}


def get_parts_info(source_root_dir, subsystem_info, build_xts=False):
    """
    get parts path info from subsystem info
    :param source_root_dir: oh project path
    :param subsystem_info:
    :param build_xts:
    :return: parts path info
    """
    _phony_target = {}
    _parts_path_info = {}
    _parts_hisysevent_config = {}
    _parts_modules_info = {}
    _parts_deps = {}
    for subsystem_name, build_config_info in subsystem_info.items():
        if not len(build_config_info.get("build_files")):
            continue
        build_loader = LoadBuildConfig(source_root_dir, build_config_info, subsystem_name)
        if subsystem_name == 'xts' and build_xts is False:
            xts_device_attest_name = ['device_attest_lite', 'device_attest']
            build_loader.parse()
            build_loader.parts_info_filter(xts_device_attest_name)
        _parts_path_info.update(build_loader.parts_path_info())
    return _parts_path_info


def _read_json_file(input_file):
    if not os.path.exists(input_file):
        print("file '{}' doesn't exist.".format(input_file))
        return {}
    try:
        with open(input_file, 'r') as input_f:
            data = json.load(input_f)
        return data
    except json.decoder.JSONDecodeError:
        print("The file '{}' format is incorrect.".format(input_file))
        raise
    except Exception:
        print("read file '{}' failed.".format(input_file))
        raise


def get_product_define_path(source_root_dir):
    return os.path.join(source_root_dir, 'productdefine', 'common', 'inherit')


def components_list_handler(product_file_json):
    components_list = list()
    for subsystems in product_file_json.get('subsystems'):
        for components in subsystems.get('components'):
            components_list.append(components.get('component'))

    return components_list


def product_component_handler(product_file, product_file_path):
    all_components_dict = dict()
    components_list = list()
    try:
        with open(product_file_path, 'r', encoding='utf-8') as f:
            product_file_json = json.load(f)
            components_list = components_list_handler(product_file_json)
    except FileNotFoundError:
        print(f"read file {product_file_path} failed.")
    all_components_dict.update({product_file.split('.')[0]: components_list})
    return all_components_dict


def collect_all_product_component(product_file_dict: dict):
    all_components_dict = dict()
    for product_file, product_file_path in product_file_dict.items():
        product_components_dict = product_component_handler(product_file, product_file_path)
        all_components_dict.update(product_components_dict)
    return all_components_dict


def get_product_define_dict(source_root_dir):
    product_define_path = get_product_define_path(source_root_dir)
    product_file_dict = dict()
    for file in os.scandir(product_define_path):
        if file.name.split('.')[-1] == 'json':
            product_file_dict.update({file.name: os.path.join(product_define_path, file.name)})
    product_define_dict = collect_all_product_component(product_file_dict)
    return product_define_dict


def output_path_handler(project_path):
    output_path = os.path.join(project_path, 'interface', 'sdk-js', 'api', 'device-define-common')
    folder = os.path.exists(output_path)
    # 多线程创建文件夹问题
    if not folder:
        os.makedirs(output_path, exist_ok=True)
    return output_path


def project_path_handler(project_path):
    if not project_path:
        project_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    return project_path


def main():
    logging.basicConfig(level=logging.INFO)
    args = get_args()
    project_path = args.project_path
    project_path = project_path_handler(project_path)
    output_path = output_path_handler(project_path)
    subsystem_config_file = os.path.join(project_path, 'build', 'subsystem_config.json')
    product_define_dict = get_product_define_dict(project_path)
    _subsystem_info = get_subsystem_info(subsystem_config_file, project_path)
    _parts_path_info = get_parts_info(project_path, _subsystem_info)
    syscap_dict, errors_list = collect_all_product_component_syscap_dict(_parts_path_info, project_path,
                                                                         product_define_dict)
    if syscap_dict:
        dict_to_json(output_path, syscap_dict)


if __name__ == "__main__":
    main()
