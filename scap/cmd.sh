#!/bin/bash

set -eu

BASE_PATH="/srv/deployment/homer"
export VENV="${BASE_PATH}/venv"
export DEPLOY_PATH="${BASE_PATH}/deploy"

(cd "${DEPLOY_PATH}" && make -f Makefile.deploy deploy)

