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

#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <limits.h>
#include <sys/types.h>
#include <wait.h>
#include "syscap_tool.h"
#include "create_pcid.h"

char *g_testFilePcid = "{\n  \"api_version\": 0,\n  \"manufacturer_id\": 0,\n  \"product\": \"rk3568\",\n" \
    "  \"syscap\": {\n    \"os\": [\n      \"SystemCapability.Account.AppAccount\",\n" \
    "      \"SystemCapability.Account.OsAccount\"\n    ]\n  },\n" \
    "  \"system_type\": \"standard\"\n}";
char *g_testFileRpcid = "{\n  \"api_version\": 7,\n  \"syscap\":	[\n    \"SystemCapability.hiviewdfx.hilog\",\n" \
    "    \"SystemCapability.communication.softbus\",\n    \"SystemCapability.hisicon.flashlight\"\n  ]\n}";

int32_t PrepareTestFile(char *fileName, char *fileContext)
{
    int32_t ret;
    FILE *fp = fopen(fileName, "wb");
    if (fp == NULL) {
        return -1;
    }
    size_t len = fwrite(fileContext, 1, strlen(fileContext), fp);
    if (len != strlen(fileContext)) {
        (void)fclose(fp);
        return -1;
    }
    ret = fclose(fp);
    if (ret != 0) {
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int32_t status;

    char *pcidFileName = "SystemCapability.json";
    char *rpcidFileName = "rpcid.json";
    printf("###start syscap tool test###\n");

    (void)unlink(pcidFileName);
    (void)unlink(rpcidFileName);
    (void)unlink("./rk3568.sc");
    (void)unlink("./newPCID.sc");
    (void)unlink("./rpcid.sc");
    (void)unlink("./rk3568.json");

    pid_t pid = fork();
    if (pid == 0) {
        printf("prepare test file...\n");
        int32_t passCnt = 0;
        int32_t ret = PrepareTestFile(pcidFileName, g_testFilePcid);
        if (ret != 0) {
            printf("  error: prepare pcid file failed\n");
            exit(passCnt);
        }
        ret = PrepareTestFile(rpcidFileName, g_testFileRpcid);
        if (ret != 0) {
            printf("  error: prepare rpcid file failed\n");
            exit(passCnt);
        }
        printf("1.test rpcid.json encode to rpcid.sc\n");
        ret = RPCIDEncode(rpcidFileName, "./");
        if (ret != 0) {
            printf("  error: rpcid.json encode failed\n");
            exit(passCnt);
        }
        passCnt++;
        printf("pass\n");
        printf("2.test rpcid.sc decode to rpcid.json\n");
        ret = RPCIDDecode("rpcid.sc", "./");
        if (ret != 0) {
            printf("  error: rpcid.sc decode failed\n");
            exit(passCnt);
        }
        passCnt++;
        printf("pass\n");
        printf("3.test pcid.json encode to pcid.sc\n");
        ret = PCIDEncode(pcidFileName, "./");
        if (ret != 0) {
            printf("  error: pcid.json encode failed\n");
            exit(passCnt);
        }
        passCnt++;
        printf("pass\n");
        printf("4.test pcid.sc decode to pcid.json\n");
        ret = PCIDDecode("./rk3568.sc", "./");
        if (ret != 0) {
            printf("  error: pcid.sc decode failed\n");
            exit(passCnt);
        }
        passCnt++;
        printf("pass\n");
        printf("5.test pcid.json encode to new PCID.sc\n");
        ret = CreatePCID("./newPCID.sc", "./");
        if (ret != 0) {
            printf("  error: new pcid.sc encode failed\n");
            exit(passCnt);
        }
        passCnt++;
        printf("pass\n");
        printf("6.test new pcid.sc decode to pcid.json\n");
        ret = PCIDDecode("./newPCID.sc", "./");
        if (ret != 0) {
            printf("  error: new pcid.sc decode failed\n");
            exit(passCnt);
        }
        passCnt++;
        printf("pass\n");
        exit(passCnt);
    }
    (void)wait(&status);
    printf("summary: total 4  passed %d\n", WEXITSTATUS(status));
    (void)unlink(pcidFileName);
    (void)unlink(rpcidFileName);
    (void)unlink("./rk3568.sc");
    (void)unlink("./newPCID.sc");
    (void)unlink("./rpcid.sc");
    (void)unlink("./rk3568.json");

    return 0;
}