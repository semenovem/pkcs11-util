#!/bin/bash

BIN=$(dirname "$([[ $0 == /* ]] && echo "$0" || echo "$PWD/${0#./}")")
source "${BIN}/util.sh"

bash "${BIN}/run.sh" destroy \
  -s "$__HSM_SLOT__" -p "$__HSM_PIN__" -lib "$__HSM_LIB__" -confirm=false $*
