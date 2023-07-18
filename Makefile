.PHONY: build clean install test uninstall

build:
	cmake -B build -G Ninja . \
		  -D CMAKE_BUILD_TYPE:STRING=Debug \
		  -D CMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE
	cmake --build build

clean:
	rm -rf build/

install: build
	cmake --install build

test: install
	make -C tests/

uninstall:
	rm -f /usr/local/include/packet.h
	rm -rf /usr/local/include/packet/
	rm -f /usr/local/lib/libpacket.so.*
	rm -f /usr/local/lib/libpacket.so
