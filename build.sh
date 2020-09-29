#!/bin/bash

# get latest tag
TAG=$(git describe --tags $(git rev-list --tags --max-count=1))

# get current commit hash for tag
commit=$(git rev-parse HEAD)

# if there are none, start tags at 0.0.0
if [ -z "$TAG" ]; then
  TAG=0.0.0
fi

export TZ=Asia/Shanghai
export CGO_ENABLED=0

LDFLAGS="\
-X \"main.VERSION=${TAG}\" \
-X \"main.COMMIT=$(git rev-parse HEAD)\" \
-X \"main.GOVERSION=$(go version)\" \
-X \"main.COMPILE_AT=$(date +'%F %H:%M:%S')\" \
"

go build --ldflags "${LDFLAGS}" -o build/prsdata .
