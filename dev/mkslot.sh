#!/bin/bash

BIN=$(dirname "$([[ $0 == /* ]] && echo "$0" || echo "$PWD/${0#./}")")
source "${BIN}/util.sh"

softhsm2-util --init-token --slot 0 \
  --label "$__HSM_SLOT__" \
  --pin "$__HSM_PIN__" \
  --so-pin 1212

[ $? -ne 0 ] && exit 1

softhsm2-util --init-token --slot 1 \
  --label "${__HSM_SLOT__}--2" \
  --pin "$__HSM_PIN__" \
  --so-pin 1212

[ $? -ne 0 ] && exit 1

exit 0
