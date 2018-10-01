#!/bin/bash

RUN_COMMAND="docker run -t --rm \
          -e VCERT_TPP_URL \
          -e VCERT_TPP_USER \
          -e VCERT_TPP_PASSWORD \
          -e VCERT_TPP_ZONE \
          -e VCERT_CLOUD_URL \
          -e VCERT_CLOUD_APIKEY \
          -e VCERT_CLOUD_ZONE vcert.auto cucumber --fail-fast --no-color"

set -e

if [ x$1 != x ]; then
    echo One-feature run
    $RUN_COMMAND $1
elif which parallel; then
    echo Parallel...
    FEATURES=""
    for F in `find features/ -type f -name '*.feature'`; do
        FEATURES="$FEATURES $F"
    done
    parallel -j 20 $RUN_COMMAND -- $FEATURES
else
    echo Sequential...
    for F in `find features/ -type f -name '*.feature'`; do
        $RUN_COMMAND $F
    done
fi
