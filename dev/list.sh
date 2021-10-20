#!/bin/bash

BIN=$(dirname "$([[ $0 == /* ]] && echo "$0" || echo "$PWD/${0#./}")")
source "${BIN}/util.sh"

bash "${BIN}/run.sh" list
