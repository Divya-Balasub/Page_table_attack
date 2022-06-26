#include <stdio.h>
#include <string.h>
#include "trustlib_enclave.h"
#include "framework.h"

/**
 * Sign a message and save signed message
 * 
 * The program takes a message, signs the message with TRUSTLIB_UNTRUSTED
 * as issuer, and stores the signed message in the given file.
 * The actual signature is done by the trustlib enclave. 
 */
int main(int argc, char* argv[]) {
    if(argc != 3) {
        fprintf(stderr, "Usage: %s <message> <output file>\n", argv[0]);
        return 1;
    }

    // copy message to a trustlib_signed_data_t struct
    trustlib_signed_data_t message;
    memset(&message, 0, sizeof(message));
    message.data.issuer = TRUSTLIB_UNTRUSTED;
    memset(message.data.message, 0, sizeof(message.data.message));
    strncpy(message.data.message, argv[1], sizeof(message.data.message) - 1);
    
    // initialize the enclave, and let the enclave sign the message
    if(trustlib_init() == -1) {
        fprintf(stderr, TAG_FAIL "Failed to initialize the enclave\n");
        return 2;
    }
    printf(TAG_INFO "Please wait, message is signed. This can take multiple seconds.\n");
    trustlib_sign_enclave(&message);
    printf(TAG_OK "Message signed!\n");
    
    // store the signed message
    FILE* f = fopen(argv[2], "wb");
    if(!f) {
        fprintf(stderr, TAG_FAIL "Could not open file '%s'\n", argv[2]);
        return 3;
    }
    if(fwrite(&message, sizeof(message), 1, f) != 1) {
        fprintf(stderr, TAG_FAIL "Could not write to file '%s'\n", argv[2]);
        return 4;
    }
    fclose(f);
    
    return 0;    
}
