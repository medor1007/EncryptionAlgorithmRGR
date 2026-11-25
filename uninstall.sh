#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
APP_DIR="${APP_DIR:-$PREFIX/lib/encryption_rgr}"
BIN_DIR="${BIN_DIR:-$PREFIX/bin}"

if [[ "${EUID}" -ne 0 ]]; then
    printf 'Для удаления требуются права администратора. Запустите: sudo %s\n' "$0" >&2
    exit 1
fi

rm -f -- "$BIN_DIR/encryption_rgr"
rm -rf -- "$APP_DIR"
printf 'Программа удалена. Пользовательские файлы и ключи в домашнем каталоге не затронуты.\n'
