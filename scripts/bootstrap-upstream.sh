#!/usr/bin/env bash
# Recreate the pinned upstream checkout used as the behavioral specification.
set -euo pipefail
cd "$(dirname "$0")/.."
repository="$(sed -n 's/^repository=//p' UPSTREAM.lock)"
commit="$(sed -n 's/^commit=//p' UPSTREAM.lock)"
if [[ ! -d upstream/.git ]]; then
  git clone --filter=blob:none "$repository" upstream
fi
git -C upstream fetch --tags --quiet
git -C upstream checkout --quiet "$commit"
test "$(git -C upstream rev-parse HEAD)" = "$commit"
echo "upstream pinned at $commit"
