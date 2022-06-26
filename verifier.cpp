#include <stdio.h>
#include <string.h>
#include "trustlib_enclave.h"
#include "framework.h"

/**
 * Check the signature of a file, and print the message
 * 
 * This tool loads a signed message and verifies the signature. 
 * If the signature is correct, the message is displayed. 
 * The formatting of the displayed message depends on whether
 * the issuer is trusted or untrusted.
 */
int main(int argc, char* argv[]) {
    if(argc != 2) {
        fprintf(stderr, "Usage: %s <message file>\n", argv[0]);
        return 1;
    }

    // load signed message from file
    trustlib_signed_data_t message;
    FILE* f = fopen(argv[1], "rb");
    if(!f) {
        fprintf(stderr, TAG_FAIL "Could not open file '%s'\n", argv[1]);
        return 2;
    }
    if(fread(&message, sizeof(message), 1, f) != 1) {
        fprintf(stderr, TAG_FAIL "Could not read from file '%s'\n", argv[1]);
        return 3;
    }
    fclose(f);
    
    // initialize enclave
    if(trustlib_init() == -1) {
        fprintf(stderr, TAG_FAIL "Failed to initialize the enclave\n");
        return 2;
    }
    
    if(trustlib_verify_enclave(&message)) {
        printf(TAG_OK "Signature verified!\n\n");
        
        if(message.data.issuer == TRUSTLIB_TRUSTED) {
            printf("           ______________________________________        \n");
            printf("  ________|                                      |_______\n");
            printf("  \\       |             " COLOR_GREEN "[ OFFICIAL ]" COLOR_RESET "             |      /\n");
            printf("   \\      |   " COLOR_YELLOW "%-30s" COLOR_RESET "     |     / \n", message.data.message);
            printf("   /      |______________________________________|     \\ \n");
            printf("  /__________)                                (_________\\\n\n");
        } else {
            printf(COLOR_RED "UNTRUSTED UNTRUSTED UNTRUSTED UNTRUSTED UNTRUSTED UNTRUSTED\n");
            printf("-----------------------------------------------------------\n" COLOR_RESET);
            printf(COLOR_MAGENTA "%s\n" COLOR_RESET, message.data.message);
            printf(COLOR_RED "-----------------------------------------------------------\n");
            printf("UNTRUSTED UNTRUSTED UNTRUSTED UNTRUSTED UNTRUSTED UNTRUSTED\n" COLOR_RESET);
        }
    } else {
        printf(TAG_FAIL "Signature check failed!\n");
        return 1;
    }
    
    
    return 0;    
}
