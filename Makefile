CFLAGS=-g -Wall -Wextra

all: attack signer verifier enclave

	
attack: framework.cpp enclave/utee.cpp enclave/trustlib.h enclave/trustlib_enclave.h enclave/utee.h enclave
	g++ -o attack framework.cpp enclave/utee.cpp -Ienclave ${CFLAGS} -lrt -lpthread 
	
verifier: verifier.cpp enclave/utee.cpp enclave/trustlib.h enclave/trustlib_enclave.h enclave/utee.h enclave
	g++ -o verifier verifier.cpp enclave/utee.cpp ${CFLAGS} -Ienclave -lrt -lpthread -static

signer: signer.cpp enclave/utee.cpp enclave/trustlib.h enclave/trustlib_enclave.h enclave/utee.h enclave
	g++ signer.cpp enclave/utee.cpp -o signer ${CFLAGS} -Ienclave -lrt -lpthread -static
	
run:
	./attack

enclave:
	make -C enclave
	
clean:
	rm -f *.o *.so attack verifier signer
