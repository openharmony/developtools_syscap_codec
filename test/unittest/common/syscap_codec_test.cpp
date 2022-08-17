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

#include <gtest/gtest.h>
#include <cstdlib>
#include "syscap_interface.h"
#include "syscap_codec_test.h"

using namespace testing::ext;
using namespace std;

namespace Syscap {
void SyscapCodecTest::SetUpTestCase() {}
void SyscapCodecTest::TearDownTestCase() {}
void SyscapCodecTest::SetUp() {}
void SyscapCodecTest::TearDown() {}

/*
 * @tc.name: EncodeOsSyscap
 * @tc.desc: Check the OsSyscap Coding.
 * @tc.type: FUNC
 */
HWTEST_F(SyscapCodecTest, EncodeOsSyscap, TestSize.Level1)
{
    int pcidLen = PCID_MAIN_BYTES;
    char OsInput[SINGLE_SYSCAP_LEN] = {0};
    EXPECT_TRUE(EncodeOsSyscap(OsInput, pcidLen));
}

/*
 * @tc.name: EncodePrivateSyscap
 * @tc.desc: Check the PrivateSyscap Coding.
 * @tc.type: FUNC
 */
HWTEST_F(SyscapCodecTest, EncodePrivateSyscap, TestSize.Level1)
{
    char *charPriInput = nullptr;
    int priOutLen;
    EXPECT_TRUE(EncodePrivateSyscap(&charPriInput, &priOutLen));
    // Currently, private syscap is null.
    EXPECT_EQ(*charPriInput, '\0');
    EXPECT_EQ(priOutLen, 0);
    free(charPriInput);
}

/*
 * @tc.name: DecodeOsSyscap
 * @tc.desc: Check the OsSyscap Decoding.
 * @tc.type: FUNC
 */
HWTEST_F(SyscapCodecTest, DecodeOsSyscap, TestSize.Level1)
{
    int osSyscap[32] = {1, 3, 3};
    char (*osOutput)[SINGLE_SYSCAP_LEN] = nullptr;
    int decodeOsCnt;
    char expectOsOutput001[] = "SystemCapability.Account.AppAccount";
    char expectOsOutput002[] = "SystemCapability.Account.OsAccount";
    EXPECT_TRUE(DecodeOsSyscap((char *)osSyscap, &osOutput, &decodeOsCnt));
    char (*tmpOsOutput)[SINGLE_SYSCAP_LEN] = osOutput;
    EXPECT_STREQ(*tmpOsOutput, expectOsOutput001);
    EXPECT_STREQ(*(tmpOsOutput + 1), expectOsOutput002);
    EXPECT_EQ(decodeOsCnt, 2);
    free(osOutput);
}

/*
 * @tc.name: DecodePrivateSyscap
 * @tc.desc: Check the null PrivateSyscap Decoding.
 * @tc.type: FUNC
 */
HWTEST_F(SyscapCodecTest, DecodePrivateSyscap, TestSize.Level1)
{
    char (*priOutput)[SINGLE_SYSCAP_LEN] = nullptr;
    char priSyscap[] = "Device.syscap1GEDR,Device.syscap2WREGW,Vendor.syscap3RGD,Vendor.syscap4RWEG,Vendor.syscap5REWGWE,";
    int decodePriCnt;
    char expectPriOutput001[] = "SystemCapability.Device.syscap1GEDR";
    char expectPriOutput002[] = "SystemCapability.Device.syscap2WREGW";
    char expectPriOutput003[] = "SystemCapability.Vendor.syscap3RGD";
    char expectPriOutput004[] = "SystemCapability.Vendor.syscap4RWEG";
    char expectPriOutput005[] = "SystemCapability.Vendor.syscap5REWGWE";
    EXPECT_TRUE(DecodePrivateSyscap(priSyscap, &priOutput, &decodePriCnt));
    char (*tmpPtiOutput)[SINGLE_SYSCAP_LEN] = priOutput;
    EXPECT_STREQ(*tmpPtiOutput++, expectPriOutput001);
    EXPECT_STREQ(*tmpPtiOutput++, expectPriOutput002);
    EXPECT_STREQ(*tmpPtiOutput++, expectPriOutput003);
    EXPECT_STREQ(*tmpPtiOutput++, expectPriOutput004);
    EXPECT_STREQ(*tmpPtiOutput, expectPriOutput005);
    EXPECT_EQ(decodePriCnt, 5);
    free(priOutput);
}

/*
 * @tc.name: DecodePrivateSyscap1
 * @tc.desc: Check the PrivateSyscap Decoding.
 * @tc.type: FUNC
 */
HWTEST_F(SyscapCodecTest, DecodePrivateSyscap1, TestSize.Level1)
{
    char *charPriInput = nullptr;
    char (*priOutput)[SINGLE_SYSCAP_LEN] = nullptr;
    int priOutLen;
    int decodePriCnt;

    EXPECT_TRUE(EncodePrivateSyscap(&charPriInput, &priOutLen));
    if (priOutLen == 0) {
        EXPECT_TRUE(DecodePrivateSyscap(charPriInput, &priOutput, &decodePriCnt));
        EXPECT_EQ((void *)priOutput, (void *)nullptr);
        EXPECT_EQ(decodePriCnt, 0);
        free(priOutput);
    }
    free(charPriInput);
}

/*
 * @tc.name: ComparePcidString
 * @tc.desc: Check the DecodeRpcidToStringFormat Decoding.
 * @tc.type: FUNC
 */
HWTEST_F(SyscapCodecTest, ComparePcidString, TestSize.Level1)
{
    CompareError result = {{0}, 0, 0};
    const char pcidString[] = "263168,0,3473408,0,0,0,1634,0,0,0,0,0,0,0,0,0,0,"\
                              "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,SystemCapability.vendor.xxxxx3,"\
                              "SystemCapability.device.xxxxx4";
    const char rpcidString[] = "33588992,1766370052,65536,276824064,0,0,0,0,0,0,"\
                               "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"\
                               "SystemCapability.vendor.xxxxx1,SystemCapability.device.xxxxx2";
    const char expect[][256] = {"SystemCapability.HiviewDFX.HiLogLite",
                                "SystemCapability.HiviewDFX.Hiview.FaultLogger",
                                "SystemCapability.vendor.xxxxx1",
                                "SystemCapability.device.xxxxx2"};
    int32_t ret = ComparePcidString(pcidString, rpcidString, &result);
    EXPECT_EQ(ret, 3);
    EXPECT_EQ(result.targetApiVersion, 7);
    EXPECT_EQ(result.missSyscapNum, 4);
    for (int i = 0; i < result.missSyscapNum; i++) {
        EXPECT_STREQ(result.syscap[i], expect[i]);
    }
    (void)FreeCompareError(&result);
    EXPECT_EQ(result.targetApiVersion, 0);
    EXPECT_EQ(result.missSyscapNum, 0);
    for (int i = 0; i < MAX_MISS_SYSCAP; i++) {
        EXPECT_EQ((void *)result.syscap[i], (void *)nullptr);
    }
}
} // namespace Syscap
