#!/bin/bash

BIN=$(dirname "$([[ $0 == /* ]] && echo "$0" || echo "$PWD/${0#./}")")
source "${BIN}/util.sh"

export GOBIN="${BIN}/.."
export GOOS=linux

APP_VERSION_VAR="vtb.ru/pkcs11-util/internal/cli/command.appVersion"
PKCS11_HOST_LIB_VAR="vtb.ru/pkcs11-util/internal/cli/command.DefaultLib"
VERSION=1.0.0-dev

PKCS11_HOST_LIB=/usr/lib64/libsofthsm2.so

if [[ $1 == "list" ]]; then
  bash $0 "555" $* -s "$__HSM_SLOT__" -p "$__HSM_PIN__"
  exit 0
fi

[[ $1 == "555" ]] && shift

[ -z $1 ] && exit 0

go run \
    -ldflags="-X "${APP_VERSION_VAR}=${VERSION}" -X "${PKCS11_HOST_LIB_VAR}=${PKCS11_HOST_LIB}" -s -w" \
    -mod vendor \
    ../cmd/hsmc/*.go \
    $*
