PROJECTNAME=$(shell basename "$(PWD)")

include project.properties

BASE_DIR:=$(shell pwd)
PKGS :=$(shell go list ./...)

APP_NAME_VAR:=vtb.ru/pkcs11-util/internal/cli/command.appVersion

BIN_DIR := $(BASE_DIR)/.bin
CMD_DIR := $(BASE_DIR)/cmd

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

## docker: builds the HSM command line tool in container
.PHONY: docker
docker:
	docker build . -t $(IMAGE):$(IMAGE_VERSION)

## export: exports the HSM command line tool from container
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
