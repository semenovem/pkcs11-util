#!/bin/bash

BIN=$(dirname "$([[ $0 == /* ]] && echo "$0" || echo "$PWD/${0#./}")")
source "${BIN}/util.sh"

bash "${BIN}/run.sh" certificateRequest \
    -s "$__HSM_SLOT__" -p "$__HSM_PIN__" \
    -publicLabel "$__LAB_PUB__" \
    -privateLabel "$__LAB_PRV__" \
    -out /tmp/client.csr \
    -signature ECDSAWithSHA384 \
    -CN *.inet.vtb.ru \
    -dns afscapp101lv.inet.vtb.ru,afscapp102lv.inet.vtb.ru \
    -ip 172.16.225.163,172.16.225.164
