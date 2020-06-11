#!/usr/bin/env bash

# Helper to refresh the frozen requirements file.
# This is supposed to be run inside a docker container via the Makefile.build file

set -o errexit
set -o nounset
set -o pipefail

FROZEN_REQUIREMENTS=/deploy/frozen-requirements-${1}.txt

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

pip3 install "."
pip3 freeze --local > "${FROZEN_REQUIREMENTS}"

# https://github.com/pypa/pip/issues/4668
sed -i '/pkg-resources==0.0.0/d' "${FROZEN_REQUIREMENTS}"
# Remove homer as it was added by pip but is not needed
sed -i '/homer==/d' "${FROZEN_REQUIREMENTS}"

echo "${FROZEN_REQUIREMENTS} updated, please commit it to git."
