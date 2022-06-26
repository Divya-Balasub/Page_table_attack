#include <iostream>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/prctl.h>
#include <assert.h>
#include <dirent.h>

#include "utee.h"


static utee_call_t ecall[UTEE_MAX_ECALLS], ocall[UTEE_MAX_OCALLS];
static unsigned int utee_ecalls = 1, utee_ocalls = 1;

static utee_msg_t* msg_ecall;
static utee_msg_t* msg_ocall;
static utee_msg_t* msg_signal;

static char enclave_name[UTEE_MAX_ENCLAVE_NAME];
static char sandbox_ecall_key[UTEE_MAX_ENCLAVE_NAME + 8], 
            sandbox_ocall_key[UTEE_MAX_ENCLAVE_NAME + 8], 
            sandbox_signal_key[UTEE_MAX_ENCLAVE_NAME + 8];

static int has_signal_handler;

static pid_t utee_enclave_pid;

// ---------------------------------------------------------------------------
static pid_t utee_proc_find(const char* name) {
    DIR* dir;
    struct dirent* ent;
    char buf[512];

    long  pid;
    char pname[100] = {0,};
    char state;
    FILE *fp=NULL; 

    if(!(dir = opendir("/proc"))) {
        fprintf(stderr, "[utee] Can't open /proc");
        return -1;
    }

    while((ent = readdir(dir)) != NULL) {
        long lpid = atol(ent->d_name);
        if(lpid < 0) {
            continue;
        }
        snprintf(buf, sizeof(buf), "/proc/%ld/stat", lpid);
        fp = fopen(buf, "r");

        if(fp) {
            if((fscanf(fp, "%ld (%[^)]) %c", &pid, pname, &state)) != 3) {
                printf("fscanf failed \n");
                fclose(fp);
                closedir(dir);
                return -1; 
            }
            if(!strcmp(pname, name)) {
                fclose(fp);
                closedir(dir);
                return (pid_t)lpid;
            }
            fclose(fp);
        }
    }

    closedir(dir);
    return -1;
}

// ---------------------------------------------------------------------------
int utee_enclave_init(const char* name) {
    assert(name && "Enclave name must be provided");
    strncpy(enclave_name, name, sizeof(enclave_name) - 1);
    snprintf(sandbox_ecall_key, sizeof(sandbox_ecall_key) - 1, "%s_ecall", name);
    snprintf(sandbox_ocall_key, sizeof(sandbox_ocall_key) - 1, "%s_ocall", name);
    snprintf(sandbox_signal_key, sizeof(sandbox_signal_key) - 1, "%s_signal", name);

    int s_e = shm_open(sandbox_ecall_key, O_CREAT | O_RDWR, 0644);
    int s_o = shm_open(sandbox_ocall_key, O_CREAT | O_RDWR, 0644);
    int s_f = shm_open(sandbox_signal_key, O_CREAT | O_RDWR, 0644);
    
    if(s_e == -1 || s_o == -1 || s_f == -1) {
        fprintf(stderr, "[utee] Could not init enclave: failed to open shared memory\n");
        return 1;
    }
    ftruncate(s_e, UTEE_MAX_MESSAGE_SIZE);
    ftruncate(s_o, UTEE_MAX_MESSAGE_SIZE);
    ftruncate(s_f, UTEE_MAX_MESSAGE_SIZE);
    msg_ecall = (utee_msg_t*)mmap(NULL, UTEE_MAX_MESSAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, s_e, 0);
    msg_ocall = (utee_msg_t*)mmap(NULL, UTEE_MAX_MESSAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, s_o, 0);
    msg_signal = (utee_msg_t*)mmap(NULL, UTEE_MAX_MESSAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, s_f, 0);

    if(!msg_ecall || !msg_ocall || !msg_signal) {
        fprintf(stderr, "[utee] Could not init enclave: failed to map shared memory\n");
        return 1;
    }

    msg_ecall->call = -1;
    msg_ocall->call = -1;
    msg_signal->call = -1;

    sem_init(&(msg_ecall->calls), 1, 0);
    sem_init(&(msg_ecall->results), 1, 0);
    sem_init(&(msg_ocall->calls), 1, 0);
    sem_init(&(msg_ocall->results), 1, 0);
    sem_init(&(msg_signal->calls), 1, 0);
    sem_init(&(msg_signal->results), 1, 0);

    return 0;
}

// ---------------------------------------------------------------------------
void utee_cleanup() {
    msg_ecall->call = 0;
    sem_post(&(msg_ecall->calls));
    sem_wait(&(msg_ecall->results));
    shm_unlink(sandbox_ecall_key);
    shm_unlink(sandbox_ocall_key);
    shm_unlink(sandbox_signal_key);
}

// ---------------------------------------------------------------------------
static void utee_signal(int signum, siginfo_t* info, void* context) {
    UNUSED(signum);
    UNUSED(context);
    assert(info && "Could not get signal info");
    msg_signal->call = signum;
    msg_signal->param[0] = ((size_t)(info->si_addr)) & ~0xfff;
    sem_post(&(msg_signal->calls));
    sem_wait(&(msg_signal->results));
    if(msg_signal->result != 0) exit(msg_signal->result);
}

// ---------------------------------------------------------------------------
int utee_enclave_start() {
    if(!msg_ecall || !msg_ocall || !msg_signal) {
        fprintf(stderr, "[utee] Could not map shared memory, did you initialize the enclave?\n");
        return 1;
    }
    
    // setup signal handler
    struct sigaction sa;
    sigfillset(&sa.sa_mask);
    sa.sa_sigaction = utee_signal;
    sa.sa_flags = SA_RESTART | SA_SIGINFO;
    for(int sig = 1; sig < 32; sig++) {
        if(sig != SIGHUP) sigaction(sig, &sa, 0);
    }
    
    // handle ecalls
    while(1) {
        sem_wait(&(msg_ecall->calls));
        if(msg_ecall->call < utee_ecalls) {
            msg_ecall->result = ecall[msg_ecall->call](msg_ecall->param[0], msg_ecall->param[1], msg_ecall->param[2], msg_ecall->param[3], msg_ecall->param[4], msg_ecall->param[5], msg_ecall->len, msg_ecall->data);
        }
        sem_post(&(msg_ecall->results));
        if(msg_ecall->call == 0) {
            break;
        }
    }
    return 0;
}


// ---------------------------------------------------------------------------
int utee_enclave_connect(const char* name) {
    char ecall_key[UTEE_MAX_ENCLAVE_NAME + 8], ocall_key[UTEE_MAX_ENCLAVE_NAME + 8], signal_key[UTEE_MAX_ENCLAVE_NAME + 8];
    snprintf(ecall_key, sizeof(ecall_key) - 1, "%s_ecall", name);
    snprintf(ocall_key, sizeof(ocall_key) - 1, "%s_ocall", name);
    snprintf(signal_key, sizeof(signal_key) - 1, "%s_signal", name);
    
    int s_e = shm_open(ecall_key, O_RDWR, 0644);
    if(s_e == -1) {
        return 1;
    }
    int s_o = shm_open(ocall_key, O_RDWR, 0644);
    if(s_o == -1) {
        return 1;
    }
    int s_f = shm_open(signal_key, O_RDWR, 0644);
    if(s_f == -1) {
        return 1;
    }    
    msg_ecall = (utee_msg_t*)mmap(NULL, UTEE_MAX_MESSAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, s_e, 0);
    msg_ocall = (utee_msg_t*)mmap(NULL, UTEE_MAX_MESSAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, s_o, 0);
    msg_signal = (utee_msg_t*)mmap(NULL, UTEE_MAX_MESSAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, s_f, 0);
    if(!msg_ecall || !msg_ocall || !msg_signal) {
        fprintf(stderr, "[utee] Failed to connect to enclave: could not map shared memory\n");
        return 1;
    }

    sleep(1);
    return 0;
}


// ---------------------------------------------------------------------------
int utee_enclave_load(const char* filename) {
    assert(filename && "Filename of the enclave is required");
    FILE* f = fopen(filename, "rb");
    if(!f) {
        fprintf(stderr, "[utee] Could not open enclave '%s'\n", filename);
        return -1;
    }
    fclose(f);
    
    utee_enclave_pid = utee_proc_find(filename);
    // if enclave is not running, start it
    if(utee_enclave_pid == -1) {
        utee_enclave_pid = fork();
        assert(utee_enclave_pid != 1 && "Fork failed");
        if(utee_enclave_pid == 0) {
            prctl(PR_SET_PDEATHSIG, SIGHUP);
            char* argv[] = { (char*)filename, NULL };
            execv(argv[0], argv);
            fprintf(stderr, "[utee] Failed to start enclave\n");
            return -1;
        }
    }
    
    int fail_ctr = 0;
    while(fail_ctr < UTEE_MAX_CONNECTION_RETRY) {
        int fail = utee_enclave_connect(filename);
        if(!fail) {
            if(utee_ocalls > 1) {
                utee_start_ocall_handler();
            }
            return utee_enclave_pid;
        }
        fail_ctr++;
        sleep(1);
    }
    fprintf(stderr, "[utee] Failed to connect to enclave\n");
    
    return -1;
}


// ---------------------------------------------------------------------------
int utee_register_ecall(utee_call_t call) {
    if(utee_ecalls < UTEE_MAX_ECALLS) {
        ecall[utee_ecalls++] = call;
        return utee_ecalls - 1;
    } else {
        fprintf(stderr, "[utee] Could not register ECALL: maximum number of ECALLs reached\n");
        return -1;
    }
}

// ---------------------------------------------------------------------------
int utee_register_ocall(utee_call_t call) {
    if(utee_ocalls < UTEE_MAX_OCALLS) {
        ocall[utee_ocalls++] = call;
        return utee_ocalls - 1;
    } else {
        fprintf(stderr, "[utee] Could not register OCALL: maximum number of OCALLs reached\n");
        return -1;
    }
}

// ---------------------------------------------------------------------------
uint64_t utee_ecall(utee_msg_t* msg) {
    assert(msg && "ECALL message must not be NULL");
    memcpy(msg_ecall->data, msg->data, msg->len);
    for(int i = 0; i < 6; i++) {
        msg_ecall->param[0] = msg->param[0];
    }
    msg_ecall->len = msg->len;
    msg_ecall->call = msg->call;
    sem_post(&(msg_ecall->calls));
    sem_wait(&(msg_ecall->results));
    memcpy(msg->data, msg_ecall->data, msg->len);
    return msg_ecall->result;
}

// ---------------------------------------------------------------------------
uint64_t utee_ocall(utee_msg_t* msg) {
    assert(msg && "OCALL message must not be NULL");
    memcpy(msg_ocall->data, msg->data, msg->len);
    for(int i = 0; i < 6; i++) {
        msg_ocall->param[0] = msg->param[0];
    }
    msg_ocall->len = msg->len;
    msg_ocall->call = msg->call;
    sem_post(&(msg_ocall->calls));
    sem_wait(&(msg_ocall->results));
    memcpy(msg->data, msg_ocall->data, msg->len);
    return msg_ocall->result;
}

// ---------------------------------------------------------------------------
static void* utee_signal_handler(void* handler) {
    while(1) {
        sem_wait(&(msg_signal->calls));
        msg_signal->result = ((utee_signal_handler_t)handler)(msg_signal->call, (void*)(msg_signal->param[0]));
        sem_post(&(msg_signal->results));
    }   
}

// ---------------------------------------------------------------------------
void utee_register_signal_handler(utee_signal_handler_t handler) {
    pthread_t p;
    assert(!pthread_create(&p, NULL, utee_signal_handler, (void*)handler) && "Could not start signal handler");
    has_signal_handler = 1;
}


// ---------------------------------------------------------------------------
static void* utee_ocall_handler(void* handler) {
    UNUSED(handler);
    while(1) {
        sem_wait(&(msg_ocall->calls));
        if(msg_ocall->call < utee_ocalls) {
            msg_ocall->result = ocall[msg_ocall->call](msg_ocall->param[0], msg_ocall->param[1], msg_ocall->param[2], msg_ocall->param[3], msg_ocall->param[4], msg_ocall->param[5], msg_ocall->len, msg_ocall->data);
        }
        sem_post(&(msg_ocall->results));
    }   
}

// ---------------------------------------------------------------------------
void utee_start_ocall_handler() {
    pthread_t p;
    assert(!pthread_create(&p, NULL, utee_ocall_handler, NULL) && "Could not start OCALL handler");
}
