#ifndef _TRUSTLIB_H_
#define _TRUSTLIB_H_
#include "utee.h"
#include <stdlib.h>
#include <memory.h>

/** Message type for the signed message */
typedef enum {
    /** A trusted message can only be signed by an official authority, not by this enclave */
    TRUSTLIB_TRUSTED,
    /** Untrusted messages can be signed by this enclave */
    TRUSTLIB_UNTRUSTED
} trustlib_issuer_t;

/** Message format, containing the issuer (trusted/untrusted) and the message */
typedef struct __attribute__((packed)) {
    /** Message issuer - can be trusted or untrusted */
    trustlib_issuer_t issuer;
    /** An arbitrary message that is signed */
    char message[24];
} trustlib_sign_data_t;

/** Public key of the signature */
typedef struct {
    /** Public key part n of the RSA signature */
    char n[512];
    /** Public key part e of the RSA signature */
    char e[512];
} trustlib_sign_param_t;

/** Signed message */
typedef struct {
    /** The message and issuer */
    trustlib_sign_data_t data;
    /** The public key used to sign the message */
    trustlib_sign_param_t param;
    /** The signature over the data */
    char signature[257];
} trustlib_signed_data_t;

/**
 * Enclave function to sign a message
 * 
 * If the message issuer is TRUSTLIB_UNTRUSTED, this function signs the message. 
 * The signature and public key for the signature are stored in hex-encoded in 
 * the provided data structure. 
 * 
 * @param data Message to sign
 */
extern void trustlib_sign(trustlib_signed_data_t* data);

/**
 * Enclave function to verify a signed message
 * 
 * The function verifies whether the provided data is correctly signed.
 * Messages signed with trustlib_sign() can be verified with this function.
 * 
 * @param data Message for which the signature should be verified
 * @return 1 if the signature is valid, 0 otherwise
 */
extern int trustlib_verify(trustlib_signed_data_t* data);

#endif
