TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy
CFLAGS := -DCKB_C_STDLIB_PRINTF -nostartfiles -O3 -Ideps/molecule -I deps/ckb-c-std-lib -I deps/ckb-c-std-lib/libc -I c -I build -Wall -Werror -Wno-nonnull-compare -Wno-unused-function -g
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
MOLC := moleculec
MOLC_VERSION := 0.4.1
PROTOCOL_HEADER := c/protocol.h
PROTOCOL_SCHEMA := c/blockchain.mol
PROTOCOL_VERSION := d75e4c56ffa40e17fd2fe477da3f98c5578edcd1
PROTOCOL_URL := https://raw.githubusercontent.com/nervosnetwork/ckb/${PROTOCOL_VERSION}/util/types/schemas/blockchain.mol

# docker pull nervos/ckb-riscv-gnu-toolchain:bionic-20190702
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:7b168b4b109a0f741078a71b7c4dddaf1d283a5244608f7851f5714fbad273ba

all: specs/cells/dckb specs/cells/deposit_lock specs/cells/always_success

all-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

specs/cells/always_success: c/always_success.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $(subst specs/cells,build,$@.debug)
	$(OBJCOPY) --strip-debug --strip-all $@

specs/cells/dckb: c/dckb.c ${PROTOCOL_HEADER} c/common.h c/dao_utils.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $(subst specs/cells,build,$@.debug)
	$(OBJCOPY) --strip-debug --strip-all $@

specs/cells/deposit_lock: c/deposit_lock.c ${PROTOCOL_HEADER} c/common.h c/dao_utils.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $(subst specs/cells,build,$@.debug)
	$(OBJCOPY) --strip-debug --strip-all $@

generate-protocol: check-moleculec-version ${PROTOCOL_HEADER}

check-moleculec-version:
	test "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" = ${MOLC_VERSION}

${PROTOCOL_HEADER}: ${PROTOCOL_SCHEMA}
	${MOLC} --language c --schema-file $< > $@

${PROTOCOL_SCHEMA}:
	curl -L -o $@ ${PROTOCOL_URL}

install-tools:
	if [ ! -x "$$(command -v "${MOLC}")" ] \
			|| [ "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" != "${MOLC_VERSION}" ]; then \
		cargo install --force --version "${MOLC_VERSION}" "${MOLC}"; \
	fi

clean:
	rm -rf specs/cells/always_success
	rm -rf specs/cells/dckb
	rm -rf specs/cells/deposit_lock
	rm -rf build/*.debug
	cargo clean

dist: clean all

fmt:
	clang-format -i -style=Google $(wildcard *.h */*.h *.c */*.c)
	git diff --exit-code

.PHONY: all all-via-docker dist clean fmt
