CMD_CLANG ?= clang
CMD_GO ?= go
CMD_RM ?= rm
CMD_BPFTOOL ?= bpftool
ASSETS_PATH ?= user/assets

DEBUG_PRINT ?=
ARCH = arm64
LINUX_ARCH = arm64
ifeq ($(DEBUG),1)
DEBUG_PRINT := -DDEBUG_PRINT
endif

.PHONY: all
all: ebpf genbtf assets build
	@echo $(shell date)


.PHONY: clean
clean:
	$(CMD_RM) -f user/bytecode/*.d
	$(CMD_RM) -f user/bytecode/*.o
	$(CMD_RM) -f assets/ebpf_probe.go
	$(CMD_RM) -f bin/stackplz

.PHONY: ebpf
ebpf:
	clang \
	-D__TARGET_ARCH_$(LINUX_ARCH) \
	--target=bpf \
	-c \
	-nostdlibinc \
	-no-canonical-prefixes \
	-O2 \
	$(DEBUG_PRINT)	\
	-I       external/libbpf/src \
	-I       src \
	-g \
	-MD -MF user/assets/stack.d \
	-o user/assets/stack.o \
	src/stack.c

.PHONY: genbtf
genbtf:
	cd ${ASSETS_PATH} && ./$(CMD_BPFTOOL) gen min_core_btf a12-5.10-arm64.btf a12-5.10-arm64_min.btf stack.o

.PHONY: assets
assets:
	$(CMD_GO) run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -o "assets/ebpf_probe.go" $(wildcard ./user/assets/*.o ./user/assets/a12-5.10-arm64_min.btf ./preload_libs/*.so ./user/config/*.json)

.PHONY: build
build:
	GOARCH=arm64 GOOS=android CGO_ENABLED=1 CC=aarch64-linux-android29-clang $(CMD_GO) build -ldflags "-w -s -extldflags '-Wl,--hash-style=sysv'" -o bin/stackplz .