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

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <limits.h>
#include "syscap_tool.h"

extern char *optarg;

int main(int argc, char **argv)
{
    int32_t ret, optIndex;
    char curpath[PATH_MAX] = {0};
    int32_t rpcid = 0;
    int32_t pcid = 0;
    int32_t encode = 0;
    int32_t decode = 0;
    int32_t help = 0;
    char *inputfile = NULL;
    char *outputpath = getcwd(curpath, sizeof(curpath));

    while (1) {
        static struct option long_options[] = {
            {"help",   no_argument,       0,  'h' },
            {"RPCID",  no_argument,       0,  'R' },
            {"PCID",   no_argument,       0,  'P' },
            {"encode", no_argument,       0,  'e' },
            {"decode", no_argument,       0,  'd' },
            {"input",  required_argument, 0,  'i' },
            {"output", required_argument, 0,  'o' },
            {0,        0,                 0,  0 }
        };

        int32_t flag = getopt_long(argc, argv, "hRPedi:o:", long_options, &optIndex);
        if (flag == -1) {
            break;
        }
        switch (flag) {
            case 'e':
                encode = 1;
                break;
            case 'd':
                decode = 1;
                break;
            case 'R':
                rpcid = 1;
                break;
            case 'P':
                pcid = 1;
                break;
            case 'i':
                inputfile = optarg;
                break;
            case 'o':
                outputpath = optarg;
                break;
            case 'h':
            default:
                help = 1;
        }
    }

    if (rpcid && !pcid && encode && !decode && inputfile && !help) {
        ret = RPCIDEncode(inputfile, outputpath);
    } else if (rpcid && !pcid && !encode && decode && inputfile && !help) {
        ret = RPCIDDecode(inputfile, outputpath);
    } else if (!rpcid && pcid && encode && !decode && inputfile && !help) {
        ret = PCIDEncode(inputfile, outputpath);
    } else if (!rpcid && pcid && !encode && decode && inputfile && !help) {
        ret = PCIDDecode(inputfile, outputpath);
    } else {
        printf("syscap_tool -R/P -e/d -i filepath [-o outpath]\n");
        printf("-h, --help : how to use\n");
        printf("-R, --RPCID : encode or decode RPCID\n");
        printf("-P, --PCID : encode or decode PCID\n");
        printf("-e, --encode : to encode\n");
        printf("-d, --encode : to decode\n");
        printf("-i filepath, --input filepath : input file\n");
        printf("-o outpath, --input outpath : output path\n");
        exit(0);
    }

    if (ret != 0) {
        printf("ERROR: in file %s at line %d -> ", __FILE__, __LINE__);
        printf("input file(%s) prase failed\n", inputfile);
    }

    return 0;
}