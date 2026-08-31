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

#ifndef PARSE_SYSCAP_UINT_H
#define PARSE_SYSCAP_UINT_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Parse a whole-token decimal uint32 from untrusted PCID/RPCID CSV text.
 * Reject empty, signs, whitespace, overflow, and leftover junk such as "12abc".
 */
bool ParseSyscapUint(const char *text, uint32_t *out);

/*
 * Parse the next comma-separated decimal uint32 at *cursor.
 * On success, *cursor advances past the field and a following comma if present.
 * Reject leftover inside the field (e.g. "12abc" or "12abc,3").
 */
bool ParseSyscapCsvUint(const char **cursor, uint32_t *out);

#ifdef __cplusplus
}
#endif

#endif /* PARSE_SYSCAP_UINT_H */
