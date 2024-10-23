.DEFAULT_GOAL := build

# Makefile rules to build the libpacket source code
.PHONY: build 
build:
	cmake -B build -G Ninja . \
		  -D CMAKE_BUILD_TYPE:STRING=Debug \
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

.PHONY: uninstall
uninstall:
	rm -f /usr/local/include/packet.h
	rm -rf /usr/local/include/packet/
	rm -f /usr/local/lib/libpacket.so.*
	rm -f /usr/local/lib/libpacket.so

# Makefile rules to build the libpacket development environment.
#
# If you have a working Docker environment, you can use and contribute to this
# code base.
IMAGE_NAME=wtfbbqhax/libpacket
CONTAINER_NAME=wtfbbqhax-libpacket-0

.PHONY: container 
container:
	docker build . -f Containerfile -t $(IMAGE_NAME)

.PHONY: start
start:
	docker run \
		--name $(CONTAINER_NAME) \
		--rm -td \
		-v "$(PWD)":/volume/libpacket \
		$(IMAGE_NAME)

.PHONY: kill 
kill:
	docker kill $(CONTAINER_NAME)

.PHONY: attach
attach:
	docker exec -ti $(CONTAINER_NAME) sh

