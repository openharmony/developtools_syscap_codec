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

#include"syscap_codec_test.h"

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
    char *OsInput = NULL;
    EXPECT_TRUE(EncodeOsSyscap(&OsInput));
    free(OsInput);
}

/*
 * @tc.name: EncodePrivateSyscap
 * @tc.desc: Check the PrivateSyscap Coding.
 * @tc.type: FUNC
 */
HWTEST_F(SyscapCodecTest, EncodePrivateSyscap, TestSize.Level1)
{
    char *charPriInput = NULL;
    int priOutLen;
    EXPECT_TRUE(EncodePrivateSyscap(&charPriInput, &priOutLen));
    free(charPriInput);
}

/*
 * @tc.name: DecodeOsSyscap
 * @tc.desc: Check the OsSyscap Decoding.
 * @tc.type: FUNC
 */
HWTEST_F(SyscapCodecTest, DecodeOsSyscap, TestSize.Level1)
{
    char (*osOutput)[128] = NULL;
    int decodeOsCnt;
    char expectOsOutput001[] = "SystemCapability.Account.AppAccount";
    char expectOsOutput002[] = "SystemCapability.Account.OsAccount";
    EXPECT_TRUE(DecodeOsSyscap(osSyscap, &osOutput, &decodeOsCnt));
    char (*tmpOsOutput)[128] = osOutput;
    EXPECT_STREQ(*tmpOsOutput, expectOsOutput001);
    EXPECT_STREQ(*(tmpOsOutput + 1), expectOsOutput002);
    EXPECT_EQ(decodeOsCnt, 2);
    free(osOutput);
}

/*
 * @tc.name: DecodePrivateSyscap
 * @tc.desc: Check the PrivateSyscap Decoding.
 * @tc.type: FUNC
 */
HWTEST_F(SyscapCodecTest, DecodePrivateSyscap, TestSize.Level1)
{
    char (*priOutput)[128] = NULL;
    int decodePriCnt;
    char expectPriOutput001[] = "SystemCapability.Device.syscap1GEDR";
    char expectPriOutput002[] = "SystemCapability.Device.syscap2WREGW";
    char expectPriOutput003[] = "SystemCapability.Vendor.syscap3RGD";
    char expectPriOutput004[] = "SystemCapability.Vendor.syscap4RWEG";
    char expectPriOutput005[] = "SystemCapability.Vendor.syscap5REWGWE";
    EXPECT_TRUE(DecodePrivateSyscap(priSyscap, &priOutput, &decodePriCnt));
    char (*tmpPtiOutput)[128] = priOutput;
    EXPECT_STREQ(*tmpPtiOutput++, expectPriOutput001);
    EXPECT_STREQ(*tmpPtiOutput++, expectPriOutput002);
    EXPECT_STREQ(*tmpPtiOutput++, expectPriOutput003);
    EXPECT_STREQ(*tmpPtiOutput++, expectPriOutput004);
    EXPECT_STREQ(*tmpPtiOutput, expectPriOutput005);
    EXPECT_EQ(decodePriCnt, 5);
    free(priOutput);
}
} // namespace Syscap
