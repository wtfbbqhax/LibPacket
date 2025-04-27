.DEFAULT_GOAL := build

# Makefile rules to build the libpacket source code
.PHONY: build 
build:
	cmake -B build -G Ninja . \
		  -D CMAKE_BUILD_TYPE:STRING=Release \
		  -D CMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE
	cmake --build build

.PHONY: install
install: build
	cmake --install build

.PHONY: clean
clean:
	rm -rf build/

.PHONY: test
test: install
	make -C tests/


