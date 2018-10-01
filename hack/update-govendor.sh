#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname ${BASH_SOURCE})
REPO_ROOT="${SCRIPT_ROOT}/.."

cd $REPO_ROOT
govendor update \
        github.com/howeyc/gopass \
        software.sslmate.com/src/go-pkcs12 \
        software.sslmate.com/src/go-pkcs12/internal/rc2 \
        gopkg.in/ini.v1

