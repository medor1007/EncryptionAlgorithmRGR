#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${BUILD_DIR:-$PROJECT_DIR/build}"
PREFIX="${PREFIX:-/usr/local}"
APP_DIR="${APP_DIR:-$PREFIX/lib/encryption_rgr}"
BIN_DIR="${BIN_DIR:-$PREFIX/bin}"

if [[ "${EUID}" -ne 0 ]]; then
    printf 'Для установки требуются права администратора. Запустите: sudo %s\n' "$0" >&2
    exit 1
fi

if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
    printf 'Каталог %s отсутствует в PATH текущего окружения.\n' "$BIN_DIR" >&2
    exit 1
fi

if [[ ! -x "$BUILD_DIR/encryption_rgr" || ! -f "$BUILD_DIR/modules/libcipher_hill.so" || \
      ! -f "$BUILD_DIR/modules/libcipher_elgamal.so" ]]; then
    printf 'Сначала соберите проект командой: cmake -S . -B build && cmake --build build\n' >&2
    exit 1
fi

install -d -m 0755 "$APP_DIR/modules" "$BIN_DIR"
install -m 0755 "$BUILD_DIR/encryption_rgr" "$APP_DIR/encryption_rgr"
install -m 0755 "$BUILD_DIR/modules/libcipher_hill.so" "$APP_DIR/modules/libcipher_hill.so"
install -m 0755 "$BUILD_DIR/modules/libcipher_elgamal.so" "$APP_DIR/modules/libcipher_elgamal.so"
printf '#!/usr/bin/env bash\nexec "%s/encryption_rgr" "$@"\n' "$APP_DIR" > "$BIN_DIR/encryption_rgr"
chmod 0755 "$BIN_DIR/encryption_rgr"
printf 'Программа установлена. Запуск: encryption_rgr --help\n'
