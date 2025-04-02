#!/usr/bin/env bash

# Helper to refresh the frozen requirements file.
# This is supposed to be run inside a docker container via the Makefile.build file

set -o errexit
set -o nounset
set -o pipefail

DISTRO=${1:-bullseye}
FROZEN_REQUIREMENTS=/deploy/frozen-requirements-${DISTRO}.txt
VENV="/deploy/build/venv-${DISTRO}"
PIP="${VENV}/bin/pip3"

function exit_trap() {
    # Reset the original submodule .git file
    rm -rf .git
    mv .git.orig .git
}

trap 'exit_trap' EXIT

# Pip doesn't work well with git submodules, we need to trick it that it has a full .git directory
mv .git .git.orig
cp -a ../.git/modules/src .git
sed -i '/worktree =/d' .git/config

virtualenv "$VENV"
$PIP install --upgrade pip setuptools setuptools_scm importlib_metadata
$PIP install "."
$PIP freeze --local --all > "${FROZEN_REQUIREMENTS}"

# https://github.com/pypa/pip/issues/4668
sed -i '/pkg[-_]resources==0\.0\.0/d' "${FROZEN_REQUIREMENTS}"
# Remove homer as it was added by pip but is not needed
sed -i '/^homer==/d' "${FROZEN_REQUIREMENTS}"
sed -i '/^homer @/d' "${FROZEN_REQUIREMENTS}"

echo "${FROZEN_REQUIREMENTS} updated, please commit it to git."
