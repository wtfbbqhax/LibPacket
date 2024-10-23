#!/usr/bin/env bash

dnshog: dns_hog.cc daq_print.cc daq_print.h
	c++ -ggdb -std=c++14 -lstdc++ $^ -lpcap -ldaq -lpacket -o $@ 

clean:
	rm piglet-bpf-filter
