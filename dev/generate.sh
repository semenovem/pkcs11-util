#!/bin/bash

BIN=$(dirname "$([[ $0 == /* ]] && echo "$0" || echo "$PWD/${0#./}")")
source "${BIN}/util.sh"

bash "${BIN}/run.sh" generate \
    -s "$__HSM_SLOT__" -p "$__HSM_PIN__" \
    -publicLabel "$__LAB_PUB__" \
    -privateLabel "$__LAB_PRV__" \
    -type ecdsa -curve P384 \
    -verify=true -sign=true
