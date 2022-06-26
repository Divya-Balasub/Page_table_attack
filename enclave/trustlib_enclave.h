#ifndef _TRUSTLIB_ENCLAVE_H_
#define _TRUSTLIB_ENCLAVE_H_

#include "trustlib.h"

/** ECALL number to sign a message */
#define TRUSTLIB_ECALL_SIGN   1
/** ECALL number to verify a message */
#define TRUSTLIB_ECALL_VERIFY 2

/**
 * Sign a message
 * 
 * This functions sends an ECALL to the enclave to sign a message. 
 * Only messages that have TRUSTLIB_UNTRUSTED as issuer will be signed. 
 * The corresponding enclave function for this call is trustlib_sign()
 * Only the fields "data.issuer" and "data.message" have to be specified 
 * in the parameter. After the function returns, the fields "param" and
 * "signature" are populated.
 * 
 * @param data The message and issuer of the data to sign. 
 */
void trustlib_sign_enclave(trustlib_signed_data_t* data) {
    utee_msg_t* msg = (utee_msg_t*)calloc(sizeof(trustlib_signed_data_t) + sizeof(utee_msg_t), 1);
    msg->call = TRUSTLIB_ECALL_SIGN;
    msg->len = sizeof(trustlib_signed_data_t);
    memcpy(msg->data, data, msg->len);
    utee_ecall(msg);
    memcpy(data, msg->data, msg->len);
    free(msg);
}

/**
 * Verify a signed message
 * 
 * This function sends an ECALL to the enclave to verify a signed message.
 * The corresponding enclave function for this call is trustlib_verify()
 * The function returns whether the signature is valid. 
 * 
 * @param data The message for which the signature should be verified
 * @return 1 if the signature is correct, 0 otherwise
 */
int trustlib_verify_enclave(trustlib_signed_data_t* data) {
    utee_msg_t* msg = (utee_msg_t*)calloc(sizeof(trustlib_signed_data_t) + sizeof(utee_msg_t), 1);
    msg->call = TRUSTLIB_ECALL_VERIFY;
    msg->len = sizeof(trustlib_signed_data_t);
    memcpy(msg->data, data, msg->len);
    uint64_t result = utee_ecall(msg);
    free(msg);
    return result;
}

/**
 * Load and initialize the enclave
 * 
 * This function has to be called before trustlib_verify_enclave() or trustlib_sign_enclave()
 * can be called. It loads the enclave and connects to it. 
 * 
 * @return -1 on failure, otherwise the process ID (PID) of the enclave
 */
int trustlib_init() {
    return utee_enclave_load("trustlib_enclave");
} 

#endif
