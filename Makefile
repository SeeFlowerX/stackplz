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
all: ebpf_stack ebpf_syscall ebpf_perf_mmap genbtf assets build
	@echo $(shell date)


.PHONY: clean
clean:
	$(CMD_RM) -f user/assets/*.d
	$(CMD_RM) -f user/assets/*.o
	# $(CMD_RM) -f assets/ebpf_probe.go
	$(CMD_RM) -f bin/stackplz

.PHONY: ebpf_stack
ebpf_stack:
	clang \
	-D__TARGET_ARCH_$(LINUX_ARCH) \
	-D__MODULE_STACK \
	--target=bpf \
	-c \
	-nostdlibinc \
	-no-canonical-prefixes \
	-O2 \
	$(DEBUG_PRINT)	\
	-I       libbpf/src \
	-I       src \
	-g \
	-o user/assets/stack.o \
	src/stack.c

.PHONY: ebpf_syscall
ebpf_syscall:
	clang \
	-D__TARGET_ARCH_$(LINUX_ARCH) \
	-D__MODULE_SYSCALL \
	--target=bpf \
	-c \
	-nostdlibinc \
	-no-canonical-prefixes \
	-O2 \
	$(DEBUG_PRINT)	\
	-I       libbpf/src \
	-I       src \
	-g \
	-o user/assets/syscall.o \
	src/syscall.c

.PHONY: ebpf_perf_mmap
ebpf_perf_mmap:
	clang \
	-D__TARGET_ARCH_$(LINUX_ARCH) \
	--target=bpf \
	-c \
	-nostdlibinc \
	-no-canonical-prefixes \
	-O2 \
	$(DEBUG_PRINT)	\
	-I       libbpf/src \
	-I       src \
	-g \
	-o user/assets/perf_mmap.o \
	src/perf_mmap.c

.PHONY: genbtf
genbtf:
	cd ${ASSETS_PATH} && ./$(CMD_BPFTOOL) gen min_core_btf rock5b-5.10-f9d1b1529-arm64.btf rock5b-5.10-arm64_min.btf stack.o syscall.o
	cd ${ASSETS_PATH} && ./$(CMD_BPFTOOL) gen min_core_btf a12-5.10-arm64.btf a12-5.10-arm64_min.btf stack.o syscall.o

.PHONY: assets
assets:
	$(CMD_GO) run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -o "assets/ebpf_probe.go" $(wildcard ./user/config/config_syscall_*.json ./user/assets/*.o ./user/assets/*_min.btf ./preload_libs/*.so)

.PHONY: build
build:
	GOARCH=arm64 GOOS=android CGO_ENABLED=1 CC=aarch64-linux-android29-clang $(CMD_GO) build -ldflags "-w -s -extldflags '-Wl,--hash-style=sysv'" -o bin/stackplz .