.PHONY: test build clean

test: build
	make -C build test

build: 
	cmake -B build .
	cmake --build build

clean:
	rm -rf build/
