#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

# Output LDFlAGS for a given environment. LDFLAGS are applied to all go binary
# builds.
#
# Args: env
function ldflags() {
  local GIT_VERSION=$(git describe --tags --always --dirty)
  local GIT_COMMIT=$(git rev-parse HEAD)

  local GIT_TREESTATE="clean"
  if [[ $(git diff --stat) != '' ]]; then
    GIT_TREESTATE="dirty"
  fi

  local DATE_FMT="+%Y-%m-%dT%H:%M:%SZ"
  local BUILD_DATE=$(date "$DATE_FMT")
  local SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
  if [ $SOURCE_DATE_EPOCH ]
  then
      local BUILD_DATE=$(date -u -d "@$SOURCE_DATE_EPOCH" "$DATE_FMT" 2>/dev/null || date -u -r "$SOURCE_DATE_EPOCH" "$DATE_FMT" 2>/dev/null || date -u "$DATE_FMT")
  fi

  echo "-buildid= -X main.GitVersion=${GIT_VERSION} \
        -X main.gitCommit=${GIT_COMMIT} \
        -X main.gitTreeState=${GIT_TREESTATE} \
        -X main.buildDate=${BUILD_DATE}"
}
