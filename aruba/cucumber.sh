#!/bin/bash
echo "Using token $TPP_ACCESS_TOKEN"
RUN_COMMAND="docker run -t --rm \
          -e TPP_URL \
          -e TPP_USER \
          -e TPP_PASSWORD \
          -e TPP_ACCESS_TOKEN \
          -e TPP_ZONE \
          -e TPP_ZONE_ECDSA \
          -e CLOUD_URL \
          -e CLOUD_APIKEY \
          -e CLOUD_ZONE \
          -e TPP_IP \
          -e TPP_CN \
          -e FILE_PATH vcert.auto"

set -ex

if [ x$1 != x ]; then
    echo One-feature run
    export FILE_PATH=$1
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
    hostname;
    $RUN_COMMAND
fi
