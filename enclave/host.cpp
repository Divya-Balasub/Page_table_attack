#include <iostream>
#include "utee.h"
#include "trustlib.h"

/**
 * The sign ECALL
 *
 * This function is called, when the sign ECALL is called. 
 * It takes the data of the ECALL and forwards it to the enclave function trustlib_sign()
 * All other 6 parameters of the ECALL are not needed and thus ignored.
 * 
 * @param data A trustlib_signed_data_t message to sign
 * @return always 0
 */
uint64_t ecall_sign(uint64_t p1, uint64_t p2, uint64_t p3, uint64_t p4, uint64_t p5, uint64_t p6, uint64_t len, void* data) {
    UNUSED(p1);
    UNUSED(p2);
    UNUSED(p3);
    UNUSED(p4);
    UNUSED(p5);
    UNUSED(p6);
    UNUSED(len);
    trustlib_sign((trustlib_signed_data_t*)data);
    return 0;
}

/**
 * The verify ECALL
 * 
 * This function is called, when the verify ECALL is called. 
 * It takes the data of the ECALL and forwards it to the enclave function trustlib_verify()
 * All other 6 parameters of the ECALL are not needed and thus ignored.
 * 
 * @param data A trustlib_signed_data_t message to verify
 * @return 1 if the signature verification was successful, 0 otherwise
 */
uint64_t ecall_verify(uint64_t p1, uint64_t p2, uint64_t p3, uint64_t p4, uint64_t p5, uint64_t p6, uint64_t len, void* data) {
    UNUSED(p1);
    UNUSED(p2);
    UNUSED(p3);
    UNUSED(p4);
    UNUSED(p5);
    UNUSED(p6);
    UNUSED(len);
    return trustlib_verify((trustlib_signed_data_t*)data);
}

/**
 * Host application for the trustlib enclave
 * 
 * The function initializes the enclave with the file name of this binary as name, 
 * registers the two ECALLs for signing and verifying, and starts the enclave. 
 * 
 */
int main(int argc, char* argv[]) {
    UNUSED(argc);
    std::cout << "[*] Starting enclave" << std::endl;
    if(utee_enclave_init(argv[0])) {
        std::cout << "[!] Failed to initialize enclave" << std::endl;
        return -1;
    }
    if(utee_register_ecall(ecall_sign) == -1) {
        std::cout << "[!] Failed to register sign ECALL" << std::endl;
        return -2;
    }
    if(utee_register_ecall(ecall_verify) == -1) {
        std::cout << "[!] Failed to register verify ECALL" << std::endl;
        return -3;
    }
    if(utee_enclave_start()) {
        std::cout << "[!] Failed to start enclave" << std::endl;
        return -4;
    }
    utee_cleanup();
    std::cout << "[*] Enclave exited" << std::endl;
}
