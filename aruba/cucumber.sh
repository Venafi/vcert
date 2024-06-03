#!/bin/bash
set -ex
echo "Using token $TPP_ACCESS_TOKEN"

RUN_COMMAND="docker run -t --rm \
          -e TPP_URL \
          -e TPP_USER \
          -e TPP_TRUST_BUNDLE \
          -e TPP_PASSWORD \
          -e TPP_ACCESS_TOKEN \
          -e TPP_ZONE \
          -e TPP_ZONE_ECDSA \
          -e CLOUD_URL \
          -e CLOUD_APIKEY \
          -e CLOUD_ZONE \
          -e VAAS_ZONE_EC \
          -e TPP_IP \
          -e TPP_CN \
          -e OKTA_CLIENT_ID \
          -e OKTA_CLIENT_ID_PASS \
          -e OKTA_AUTH_SERVER \
          -e OKTA_CLIENT_SECRET \
          -e IDP_ACCESS_TOKEN \
          -e OKTA_CREDS_USR \
          -e OKTA_CREDS_PSW \
          -e OKTA_SCOPE \
          -e FIREFLY_ZONE \
          -e FIREFLY_URL \
          -e FIREFLY_CA_BUNDLE \
          -e GCP_AUTH_PATH \
          -e GCP_PROJECT \
          -e GCP_REGION \
          -e GCP_PROVIDER_NAME \
          -e GCP_KEYSTORE_NAME \
          -e GCP_KEYSTORE_ID"

# Use getopts to handle command-line options
while getopts "a:b:" opt; do
  case "$opt" in
    a) FEATURE="$OPTARG";;
    b) PLATFORM="$OPTARG";;
    \?) echo "Invalid option -$OPTARG" >&2
        exit 1;;
  esac
done

if [ "$PLATFORM" != "" ] ; then
  export TAGS="--tags @$PLATFORM"
  RUN_COMMAND="${RUN_COMMAND} \
  -e TAGS"
fi

RUN_COMMAND="${RUN_COMMAND} \
-e FILE_PATH vcert.auto"

# which has been replaced with command -v. This is because which is not as portable as command -v
# when it comes to locating executables, especially in non-interactive shells.
PARALLEL_PATH=""
if [ "$(command -v parallel)" ]; then
PARALLEL_PATH=$(command -v parallel)
fi

if [ "$FEATURE" != "" ]; then
    echo One-feature run
    export FILE_PATH=$FEATURE
    $RUN_COMMAND "$FEATURE"
# if "GNU parallel" is installed and Parallel is enabled (you must export the PARALLEL_SET env variable,
# so it can reach at the shell execution)
# This will create a heavy load of certificates in parallel. TPP is not able to handle those yet.
elif [ "$PARALLEL_PATH" != "" ] && [ "$PARALLEL_SET" == "true" ]; then
    echo Parallel...
    # here we are are invoking parallel
    which parallel
    FEATURES=""
    for F in `find features/ -type f -name '*.feature'`; do
        FEATURES="$FEATURES $F"
    done
    parallel -j 20 "$RUN_COMMAND" ::: "$FEATURES"
else
    echo Sequential...
    hostname;
    $RUN_COMMAND
fi
