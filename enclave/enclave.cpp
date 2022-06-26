#include <string>
#include <cstring>
#include <fstream>
#include <iostream>

#include "InfInt.h"
#include "trustlib.h"

static InfInt n, e, d;

// -----------------------------------------------------------------------
static char hexchar(int v) {
    if(v >= 0 && v <= 9) return v + '0';
    if(v >= 10 && v <= 15) return v + 'a' - 10;
    return 0;
}

// -----------------------------------------------------------------------
static int unhexchar(char v) {
    if(v >= '0' && v <= '9') return v - '0';
    if(v >= 'a' && v <= 'f') return v - 'a' + 10;
    if(v >= 'A' && v <= 'F') return v - 'A' + 10;
    return 0;
}

// -----------------------------------------------------------------------
static void hexlify(InfInt C, char* result) {
    char buffer[1024];
    buffer[1023] = 0;
    int ptr = 1022;
    while(C > 0) {
        buffer[ptr--] = hexchar((C % 16).toInt());
        C /= 16;
        if(ptr < 0) return;
    }
    strcpy(result, buffer + ptr + 1);
}

// -----------------------------------------------------------------------
static InfInt unhexlify(char* hex) {
    InfInt r = 0;
    while(*hex) {
        r *= 16;
        r += unhexchar(*hex);
        hex++;
    }
    return r;
}

// -----------------------------------------------------------------------
static InfInt do_sign(InfInt M, InfInt exp) {
    
    
    // C = (M ^ exp) % n
    InfInt C = 1;
    while(exp > 0) {
        if((exp % 2).toInt()) {
            C.multiply(M);
        }
        M.square();
        exp /= 2;
        
        C.reduce(n); // C % n;
        M.reduce(n); // M % n;
    }
    
    return C;
}

// -----------------------------------------------------------------------
static InfInt data2int(const char* msg, int len) {
    InfInt M = 0;
    while(len--) {
        M = (M * 256) + *msg;
        msg++;
    }
    return M;
}


// -----------------------------------------------------------------------
static void trustlib_init() {
    std::ifstream params("key.params");
    std::string s_n, s_d, s_e;
    params >> s_n >> s_e >> s_d;
    n = s_n;
    e = s_e;
    d = s_d;
}

// -----------------------------------------------------------------------
void trustlib_sign(trustlib_signed_data_t* data) {
    if(n == 0) trustlib_init();
    
    char data_to_sign[sizeof(trustlib_sign_data_t)];
    memcpy(data_to_sign, (void*)&(data->data), sizeof(trustlib_sign_data_t));
    if(((trustlib_sign_data_t*)data_to_sign)->issuer == TRUSTLIB_TRUSTED) {
        fprintf(stderr, "You are not allowed to sign trusted messages!\n");
        return;
    }
    InfInt M = data2int(data_to_sign, sizeof(trustlib_sign_data_t)); 
    
    InfInt C = do_sign(M, d);
    
    hexlify(C, data->signature);
    hexlify(n, data->param.n);
    hexlify(e, data->param.e);
}

// -----------------------------------------------------------------------
int trustlib_verify(trustlib_signed_data_t* data) {
    if(n == 0) trustlib_init();
    
    char signed_data[sizeof(trustlib_sign_data_t)];
    memcpy(signed_data, (void*)&(data->data), sizeof(trustlib_sign_data_t));
    
    InfInt C = unhexlify(data->signature);
    
    InfInt M = do_sign(C, e);
    
    InfInt origM = data2int(signed_data, sizeof(trustlib_sign_data_t));
    
    return (M == origM);
}

