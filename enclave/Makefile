all: enclave

enclave: enclave.cpp host.cpp utee.cpp trustlib.h trustlib_enclave.h utee.h 
	g++ enclave.cpp host.cpp utee.cpp -o ../trustlib_enclave -no-pie -g -L.. -static -lrt  -Wl,--whole-archive -lpthread -Wl,--no-whole-archive -falign-functions=4096 -Wall -Wextra
	
