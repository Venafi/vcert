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
          -e TPP_CN"

if [ -n "$1" ] && [ -n "$2" ] ; then
  export PLATFORM=$2
  RUN_COMMAND="${RUN_COMMAND} \
  -e PLATFORM"
elif [ -n "$1" ] && [ ! -n "$2" ]; then
  export PLATFORM=$1
  RUN_COMMAND="${RUN_COMMAND} \
  -e PLATFORM"
fi

RUN_COMMAND="${RUN_COMMAND} \
-e FILE_PATH vcert.auto"

set -ex
# which has been replaced with command -v. This is because which is not as portable as command -v
# when it comes to locating executables, especially in non-interactive shells.
PARALLEL_PATH=$(command -v parallel)

# only if second parameter is passed we assume the first one is the file path
if [ x$1 != x ] && [ -n "$2" ]; then
    echo One-feature run
    export FILE_PATH=$1
    $RUN_COMMAND $1
# if "GNU parallel" is installed and Parallel is enabled (you must export the PARALLEL_SET env variable,
# so it can reach at the shell execution)
# This will create a heavy load of certificates in parallel. TPP is not able to handle those yet.
elif [ $PARALLEL_PATH != "" ] && [ $PARALLEL_SET == "true" ]; then
    echo Parallel...
    # here we are are invoking parallel
    which parallel
    FEATURES=""
    for F in `find features/ -type f -name '*.feature'`; do
        FEATURES="$FEATURES $F"
    done
    parallel -j 20 $RUN_COMMAND ::: $FEATURES
else
    echo Sequential...
    hostname;
    $RUN_COMMAND
fi
