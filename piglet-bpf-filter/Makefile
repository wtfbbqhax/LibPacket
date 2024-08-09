#!/usr/bin/env bash

piglet-bpf-filter: piglet-bpf-filter.cc daq_print.cc daq_print.h
	c++ -ggdb -std=c++14 -lstdc++ $^ -lpcap -ldaq -lpacket -o $@ 

clean:
	rm piglet-bpf-filter
