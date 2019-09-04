#!/usr/bin/env bash
# Helper to refresh the frozen requirements file
# This is supposed to be run inside a docker container via
# the Makefile.build file
set -o errexit
set -o nounset
set -o pipefail

BASE=/deploy
BUILD=${BASE}/build
REQUIREMENTS=${BASE}/requirements.txt
REQUIREMENTS_FIXED=${BASE}/frozen-requirements.txt

pip3 install -r "$REQUIREMENTS"
pip3 freeze --local --requirement "$REQUIREMENTS_FIXED" > "$REQUIREMENTS_FIXED"
# https://github.com/pypa/pip/issues/4668
sed -i '/pkg-resources==0.0.0/d' "$REQUIREMENTS_FIXED"
echo "${REQUIREMENTS_FIXED} updated, please commit it to git."
