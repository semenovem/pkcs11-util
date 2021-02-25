PROJECTNAME=$(shell basename "$(PWD)")

include project.properties

BASE_DIR:=$(shell pwd)
PKGS :=$(shell go list ./...)

APP_VERSION_VAR:=vtb.ru/pkcs11-util/internal/cli/command.appVersion
PKCS11_HOST_LIB_VAR:=vtb.ru/pkcs11-util/internal/cli/command.DefaultLib

BIN_DIR := $(BASE_DIR)/.bin
CMD_DIR := $(BASE_DIR)/cmd
DEST_DIR := ./

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
	@echo "Building hsmc..."
	@echo "VERSION=$(VERSION)"
	@echo "PKCS11_HOST_LIB=$(PKCS11_HOST_LIB)"
	@GOBIN=$(BIN_DIR) GOOS=linux \
        go build \
          -ldflags="-X $(APP_VERSION_VAR)=$(VERSION) -X $(PKCS11_HOST_LIB_VAR)=$(PKCS11_HOST_LIB) -s -w" \
          -mod vendor \
          -o $(BIN_DIR)/hsmc \
          cmd/hsmc/*.go

## docker: builds the HSM command line tool in container
.PHONY: docker
docker:
	docker build  --build-arg PKCS11_HOST_LIB=$(PKCS11_HOST_LIB) . -t $(IMAGE):$(IMAGE_VERSION)

## export: exports the HSM command line tool from container
.PHONY: export
export:
	$(eval cid:=`docker create $(IMAGE):$(IMAGE_VERSION)`)
	@mkdir -p $(DEST_DIR)
	@echo $(cid)
	@docker cp $(cid):/src/.bin/hsmc $(DEST_DIR)
	@chmod +x $(DEST_DIR)/hsmc
	@docker rm -v $(cid)

## help: Prints help
.PHONY: help
help: Makefile
	@echo "Choose a command in "$(PROJECTNAME)":"
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
