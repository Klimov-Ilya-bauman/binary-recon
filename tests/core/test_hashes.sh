#!/usr/bin/env bash
# C++ core: проверка совпадения наших хешей с системными md5sum/sha256sum.
set -euo pipefail

CORE="${CORE:-$(pwd)/core/build/core}"

if [ ! -x "$CORE" ]; then
    echo "SKIP: core binary not found at $CORE"
    exit 0
fi

for FILE in /bin/ls /bin/bash; do
    [ -f "$FILE" ] || continue

    OUR_MD5=$("$CORE" "$FILE" --json | jq -r .md5)
    SYS_MD5=$(md5sum "$FILE" | awk '{print $1}')
    OUR_SHA=$("$CORE" "$FILE" --json | jq -r .sha256)
    SYS_SHA=$(sha256sum "$FILE" | awk '{print $1}')

    if [ "$OUR_MD5" != "$SYS_MD5" ]; then
        echo "FAIL: MD5 mismatch on $FILE"
        echo "  ours: $OUR_MD5"
        echo "  sys:  $SYS_MD5"
        exit 1
    fi
    if [ "$OUR_SHA" != "$SYS_SHA" ]; then
        echo "FAIL: SHA256 mismatch on $FILE"
        exit 1
    fi
    echo "PASS: $FILE  MD5+SHA256 match system tools"
done

echo "All C++ hash tests passed."
