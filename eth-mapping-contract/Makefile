ROOT_DIR 		:= $(abspath .)
BIN_DIR			:= bin

TARGET = contract/main.go
BASEFLAGS = -gc=custom -scheduler=none -panic=trap -no-debug -target=wasm-unknown
TESTNETFLAGS = -ldflags="-X 'main.NetworkMode=testnet'"

TINYJSON		:= tinyjson
TINYJSON_FLAGS 	:= -snake_case -no_std_marshalers
CONTRACTS_DIR	:= contract

TINYGO_IMAGE := tinygo/tinygo:0.39.0
WORKDIR      := /work

TINYGO_CMD = tinygo

ifdef USE_DOCKER
    TINYGO_CMD = docker run --rm \
        -u $(shell id -u):$(shell id -g) \
        -v $(CURDIR):$(WORKDIR) \
        -w $(WORKDIR) \
        $(TINYGO_IMAGE) \
        tinygo
endif

NETWORK ?= testnet
FILTER ?= .

RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
ifneq ($(RUN_ARGS),)
  ifeq ($(firstword $(MAKECMDGOALS)),test)
    FILTER := $(firstword $(RUN_ARGS))
  else
    NETWORK := $(firstword $(RUN_ARGS))
  endif
endif
$(eval $(RUN_ARGS):;@:)

CFLAGS = $(BASEFLAGS) $(call netflags,$(NETWORK))

netflags = \
	$(if $(filter testnet,$1),$(TESTNETFLAGS), \
	$(if $(filter mainnet,$1),, \
	$(error Unknown NETWORK: $1)))

all: dev

dev:
	@echo "Building $@ with $(NETWORK) flags"
	$(TINYGO_CMD) build $(CFLAGS) -o $(BIN_DIR)/$@.wasm $(TARGET)

testnet: NETWORK ?= testnet
testnet:
	@echo "Building $@ with $(NETWORK) flags"
	$(TINYGO_CMD) build $(CFLAGS) -o $(BIN_DIR)/$@.wasm $(TARGET)

mainnet: NETWORK ?= mainnet
mainnet:
	@echo "Building $@ with $(NETWORK) flags"
	$(TINYGO_CMD) build $(CFLAGS) -o $(BIN_DIR)/$@.wasm $(TARGET)

strip:
	@for file in $(BIN_DIR)/*.wasm; do \
		case "$$file" in \
			*"-stripped.wasm") \
				continue ;; \
			*) \
				base=$${file%.wasm}; \
				wasm-tools strip -o "$${base}-stripped.wasm" "$$file"; \
				echo "Stripped $$file -> $${base}-stripped.wasm" ;; \
		esac; \
	done

test:
	cd tests/current && go test -v -run "$(FILTER)"

clean:
	rm -rf $(BIN_DIR)/*.wasm
