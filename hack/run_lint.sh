#!/usr/bin/env bash

# Copyright 2020 Cornelius Weig
#
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

set -euo pipefail

HACK=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LINT_BIN="${HACK}/../.bin/golangci-lint"

if ! [[ -x "$LINT_BIN" ]] || ! "$LINT_BIN" version --short 2>/dev/null | grep -q '^2\.14\.0'; then
   echo 'Installing golangci-lint'
   "${HACK}"/install_golangci-lint.sh -b "${HACK}/../.bin" v2.14.0
fi

format_diff=$("$LINT_BIN" fmt --no-config --enable goimports --diff)
if [[ -n "$format_diff" ]]; then
   printf '%s\n' "$format_diff"
   exit 1
fi

"$LINT_BIN" run \
		--timeout 10m \
		--config "${HACK}/../.golangci.yml" \
		--disable errcheck \
		--enable goconst,gocritic,gosec,misspell,unconvert,unparam,staticcheck
