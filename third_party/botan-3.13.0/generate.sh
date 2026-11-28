#!/usr/bin/env bash
# Copyright (c) 2026 TULPAR project team
# SPDX-License-Identifier: GPL-2.0-only
#
# Regenerates the Botan 3.13.0 amalgamation in this folder (RSD-CRY-01e; docs/design/crypto.md,
# Section 5.1). Nothing in this folder is edited by hand: a change means rerunning this script.
set -euo pipefail

TAG=3.13.0
COMMIT=2a81eef56c96c237e590c27f9a75e60317c9c700
MODULES=ml_dsa,ml_kem,aes,gcm,sha2_64,hmac,hkdf,hmac_drbg

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$TAG" https://github.com/randombit/botan.git "$WORK/src"
ACTUAL="$(git -C "$WORK/src" rev-parse HEAD)"
if [ "$ACTUAL" != "$COMMIT" ]; then
    echo "tag $TAG resolves to $ACTUAL, expected $COMMIT" >&2
    exit 1
fi

mkdir "$WORK/out"
cd "$WORK/out"
python3 -I "$WORK/src/configure.py" --amalgamation --minimized-build --enable-modules="$MODULES" \
    --cc=gcc --os=linux --cpu=x86_64 --disable-shared-library --without-documentation \
    --with-build-dir=. > configure.log 2>&1 || { cat configure.log >&2; exit 1; }
grep "Loading modules:" configure.log | sed 's/^ *INFO: //'

cp botan_all.h botan_all.cpp "$HERE/"
cp "$WORK/src/license.txt" "$HERE/license.txt"
cd "$HERE"
sha256sum botan_all.h botan_all.cpp
