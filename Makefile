PROJECTNAME=$(shell basename "$(PWD)")
BASE_DIR:=$(shell pwd)
PKGS :=$(shell go list ./...)

PROPS_FILE:=project.properties
PROPS:=version
APP_NAME_VAR:=vtb.ru/pkcs11-util/internal/cli/command.appVersion

BIN_DIR := $(BASE_DIR)/.bin
CMD_DIR := $(BASE_DIR)/cmd

IMAGE=hsmc-build
IMAGE_VERSION=1.0.0

.PHONY: all
all: help

## test: Runs unit tests
.PHONY: test
test:
	@echo "Executing unit tests..."
	@GOBIN=$(BIN_DIR); go test $(PKGS)

## build: builds the HSM command line tool
.PHONY: build
build: test
	echo "Building hsmc..."
	@GOBIN=$(BIN_DIR) GOOS=linux \
        go build \
          -ldflags="-X $(APP_NAME_VAR)=$(VERSION) -s -w" \
          -mod vendor \
          -o $(BIN_DIR)/hsmc \
          cmd/hsmc/*.go

## docker: builds the HSM command line tool in the container
.PHONY: docker
docker:
	docker build . -t $(IMAGE):$(IMAGE_VERSION)

## export: exports the HSM command line tool from the container
.PHONY: export
export:
	$(eval cid:=`docker create $(IMAGE):$(IMAGE_VERSION)`)
	@mkdir -p $(DEST)
	@echo $(cid)
	@docker cp $(cid):/src/.bin/ $(DEST_DIR)
	@docker rm -v $(cid)

## help: Prints help
.PHONY: help
help: Makefile
	@echo "Choose a command in "$(PROJECTNAME)":"
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'

define GET_PROPERTY
$(2):=`cat $(PROPS_FILE)|grep $(1)|sed 's/.*=\s*//'`
endef

$(foreach prop, $(PROPS),  $(eval $(call GET_PROPERTY,$(prop),$(shell echo $(prop) | tr a-z A-Z))))
