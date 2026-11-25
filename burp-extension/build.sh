#!/usr/bin/env bash
# Build the ptreport Burp extension into dist/ptreport-burp.jar (needs JDK 17+, no Gradle).
# The Montoya API is only needed to compile; Burp provides it at runtime, so it is not bundled.
set -euo pipefail
cd "$(dirname "$0")"

MONTOYA_VERSION="2026.7"
MONTOYA_SHA256="cb852b7b883290fcc1d21b13d80fa10f5b13a0f57335d710d2b1e5956ecb2a94"
MONTOYA_URL="https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/${MONTOYA_VERSION}/montoya-api-${MONTOYA_VERSION}.jar"
LIB="build/lib/montoya-api-${MONTOYA_VERSION}.jar"

command -v javac >/dev/null || { echo "javac not found: install a JDK 17 or newer" >&2; exit 1; }
mkdir -p build/lib build/classes dist

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

if [ ! -f "$LIB" ] || [ "$(sha256 "$LIB")" != "$MONTOYA_SHA256" ]; then
  echo "Downloading Montoya API ${MONTOYA_VERSION} ..."
  curl -fsSL --proto '=https' -o "$LIB.tmp" "$MONTOYA_URL"
  if [ "$(sha256 "$LIB.tmp")" != "$MONTOYA_SHA256" ]; then
    rm -f "$LIB.tmp"; echo "Checksum mismatch for montoya-api-${MONTOYA_VERSION}.jar" >&2; exit 1
  fi
  mv "$LIB.tmp" "$LIB"
fi

rm -rf build/classes && mkdir -p build/classes
javac --release 17 -Xlint:all,-serial -Werror -encoding UTF-8 -cp "$LIB" -d build/classes $(find src/main/java -name '*.java')
jar --create --file dist/ptreport-burp.jar -C build/classes .
echo "Built $(pwd)/dist/ptreport-burp.jar"
