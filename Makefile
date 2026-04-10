ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
__TECHNO_PROJECT_FILE:=${ROOT_DIR}/.technoproj

RELEASE_BIN:=${ROOT_DIR}/../aloecrypt_plugin/target/wasm32-wasip1/release/aloecrypt_plugin.wasm
DEBUG_BIN:=${ROOT_DIR}/../aloecrypt_plugin/target/wasm32-wasip1/debug/aloecrypt_plugin.wasm
BUILD_CMD:=cargo build --target=wasm32-wasip1
QF:=RUSTFLAGS="-Awarnings"

-include ${ROOT_DIR}/script/version.mk
-include ${ROOT_DIR}/script/python.mk

echo:
	@echo VERSION: ${__VERSION_FULL}
	@echo TAG: ${__TAG}

build: inc_build
	mkdir -p ${ROOT_DIR}/aloecrypt/.bin
	(cd ../aloecrypt_plugin && ${BUILD_CMD} --profile=release)
	wasm-opt --enable-bulk-memory --enable-mutable-globals --enable-sign-ext -Oz ${RELEASE_BIN} -o ${ROOT_DIR}/aloecrypt/.bin/aloecrypt_plugin.wasm

dbg_build:
	mkdir -p ${ROOT_DIR}/aloecrypt/.bin
	(cd ../aloecrypt_plugin && ${BUILD_CMD})
	cp ${DEBUG_BIN} ${ROOT_DIR}/aloecrypt/.bin/aloecrypt_plugin.wasm