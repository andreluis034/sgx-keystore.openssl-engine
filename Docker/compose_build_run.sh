#!/bin/sh

set -e
docker build --target aesm -t sgx_aesm -f ./Dockerfile .

docker build --target keystore --build-arg -t sgx_keystore -f ./Dockerfile .

docker build --target apache --build-arg -t sgx_apache -f ./Dockerfile .


# Create a temporary directory on the host that is mounted
# into both the AESM and sample containers at /var/run/aesmd
# so that the AESM socket is visible to the sample container
# in the expected location. It is critical that /tmp/aesmd is
# world writable as the UIDs may shift in the container.

mkdir -p -m 777 /tmp/aesmd /tmp/sgxkeystored
chmod -R -f 777 /tmp/aesmd /tmp/sgxkeystored || sudo chmod -R -f 777 /tmp/aesmd /tmp/sgxkeystored || true
docker-compose --verbose up