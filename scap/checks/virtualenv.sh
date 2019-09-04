#!/usr/bin/env bash
# Create/update a python virtualenv using the wheel binaries
set -o errexit
set -o nounset
set -o pipefail

VENV=/srv/deployment/homer/venv
DEPLOY_DIR=/srv/deployment/homer/deploy
WHEEL_DIR=${DEPLOY_DIR}/artifacts
REQUIREMENTS=${DEPLOY_DIR}/frozen-requirements.txt
DISTRO=$(lsb_release -sc)
PIP=${VENV}/bin/pip

# Ensure that the virtual environment exists
mkdir -p $VENV
virtualenv --python python3 $VENV || /bin/true

# Extract the wheels
(cd ${WHEEL_DIR} && tar --owner=$UID -zxvf "artifacts.${DISTRO}.tar.gz")
# Install or upgrade all requirements from wheel cache
$PIP install \
    --no-index \
    --find-links ${WHEEL_DIR} \
    --upgrade \
    --force-reinstall \
    --requirement $REQUIREMENTS
