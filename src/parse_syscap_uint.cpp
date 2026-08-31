/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "parse_syscap_uint.h"

#include <charconv>
#include <cstring>
#include <system_error>

static bool ParseSyscapUintRange(const char *first, const char *last, uint32_t *out)
{
    if (first == nullptr || last == nullptr || out == nullptr || first == last) {
        return false;
    }
    if (*first < '0' || *first > '9') {
        return false;
    }
    uint32_t value = 0;
    auto result = std::from_chars(first, last, value, 10);
    if (result.ec != std::errc() || result.ptr != last) {
        return false;
    }
    *out = value;
    return true;
}

extern "C" bool ParseSyscapUint(const char *text, uint32_t *out)
{
    if (text == nullptr || out == nullptr || *text == '\0') {
        return false;
    }
    return ParseSyscapUintRange(text, text + std::strlen(text), out);
}

extern "C" bool ParseSyscapCsvUint(const char **cursor, uint32_t *out)
{
    if (cursor == nullptr || *cursor == nullptr || out == nullptr) {
        return false;
    }
    const char *p = *cursor;
    if (*p == '\0') {
        return false;
    }
    const char *comma = std::strchr(p, ',');
    const char *fieldEnd = (comma != nullptr) ? comma : (p + std::strlen(p));
    if (!ParseSyscapUintRange(p, fieldEnd, out)) {
        return false;
    }
    *cursor = (comma != nullptr) ? (comma + 1) : fieldEnd;
    return true;
}
