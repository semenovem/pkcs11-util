IMG := "pkcs11-util-dev:0.0-dev"

# -----------------
# commands
# -----------------
.PHONY: help
help: Makefile
	@echo "Choose a command in:"
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'


## docker builds the HSM command line tool in container
.PHONY: docker
docker:
	docker build . -t $(IMG) -f Dockerfile

## dev - старт контейнера для разработки
.PHONY: dev
dev:
	@docker run -it --rm \
		--name pkcs11-util-dev \
		-w /app/dev \
		-v $(PWD)/..:/app:ro \
		$(IMG) bash

## hsmc - собрать утилиту hsmc из текущего кода
.PHONY: hsmc
hsmc:
	@make -C ../ DEST_DIR=/tmp PKCS11_HOST_LIB=/usr/lib64/libsofthsm2.so build
