#ifndef _UTEE_H_
#define _UTEE_H_
#include <stdint.h>
#include <semaphore.h>

/** Maximum number of enclave calls (ECALLs) supported */
#define UTEE_MAX_ECALLS 128
/** Maximum number of out calls (OCALLs) supported */
#define UTEE_MAX_OCALLS 128
/** Maximum size of a message in bytes */
#define UTEE_MAX_MESSAGE_SIZE 4096
/** Maximum size for enclave name */
#define UTEE_MAX_ENCLAVE_NAME 128
/** Maximum number of connection retries */
#define UTEE_MAX_CONNECTION_RETRY 100


/** UTEE message format for ECALL and OCALL */
typedef struct {
    /** Semaphore used to wait for the call */
    sem_t calls;
    /** Semaphore to wait for the result of the call */
    sem_t results;
    /** ECALL/OCALL ID to call */
    uint64_t call;
    /** Parameters for the ECALL/OCALL */
    uint64_t param[6];
    /** Return value of the ECALL/OCALL */
    uint64_t result;
    /** Length of the additional data in the ECALL/OCALL */
    uint64_t len;
    /** Additional data of the ECALL/OCALL */
    char data[];
} utee_msg_t;

/** Function pointer for an ECALL/OCALL callback */
typedef uint64_t (*utee_call_t)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,void*);
/** Function pointer for a signal-handler callback */
typedef int (*utee_signal_handler_t)(int, void*);

/** Macro to suppress warnings for unused function parameters */
#define UNUSED(x) (void)(x)

/**
 * @defgroup ENCLAVE Functions used from the enclave host
 *
 * @{
 */

/**
 * Initialize a UTEE enclave
 * 
 * This function initializes a UTEE enclave. This function has to be called
 * from the host application that provides the enclave. 
 * The initialization includes the creation of the shared memory used for 
 * communication (ECALL, OCALL, and signals), and the initialization of the
 * message passing between enclave and host application.
 * 
 * @param name Unique name of the UTEE enclave, should be the file name
 * @return 0 on success, 1 otherwise
 */
int utee_enclave_init(const char* name);

/**
 * Start the enclave
 * 
 * Starts the event-handling loop of the enclave. This function does not
 * return as long as the enclave is running. After this function is called, 
 * the enclave can be used by other applications.
 * 
 * @return 0 if the enclave exited, 1 if starting the enclave failed
 */
int utee_enclave_start();

/**
 * Register an ECALL
 * 
 * Enclaves use this function to register an ECALL, i.e., a function that
 * is provided to other applications. Every ECALL has a unique number, 
 * 6 parameters (all 64-bit unsigned integers), and potential additional 
 * data (up to 4000 bytes). 
 * 
 * @param call Function to be registered as ECALL
 * @return The number of the ECALL (used for calling the ECALL)
 */
int utee_register_ecall(utee_call_t call);

/**
 * Call an OCALL
 * 
 * Calls a registered OCALL of an application from the enclave. The semaphores 
 * and the result member of the struct are ignored, only call, param, len, and data
 * are used for the OCALL.
 * 
 * @param msg OCALL message to send to application
 * @result The result of the OCALL
 */
uint64_t utee_ocall(utee_msg_t* msg);

/**
 * Cleanup the enclave
 * 
 * Free the shared memory used for the communication. 
 * Should be called after enclave_start() returns.
 */
void utee_cleanup();

/** @} */

/**
 * @defgroup INTERFACE Functions used by other applications to interact with the enclave
 *
 * @{
 */

/**
 * Connect to a running enclave
 * 
 * Connect the ECALL/OCALL communication to a running enclave. 
 * Every application that wants to use the enclave has to connect to 
 * the runnig enclave using this function.
 * 
 * @param name Name of the UTEE enclave, usually the file name
 * @return 0 on success, 1 if it was not possible to connect to the enclave
 */
int utee_enclave_connect(const char* name);

/**
 * Register an OCALL
 * 
 * Applications use this function to register an OCALL, i.e., a function that
 * is provided to the enclave. Every OCALL has a unique number, 
 * 6 parameters (all 64-bit unsigned integers), and potential additional 
 * data (up to 4000 bytes). 
 * 
 * @param call Function to be registered as OCALL
 * @return The number of the OCALL (used for calling the OCALL)
 */
int utee_register_ocall(utee_call_t call);

/**
 * Call an ECALL
 * 
 * Calls a registered ECALL of the enclave. The semaphores and the result
 * member of the struct are ignored, only call, param, len, and data
 * are used for the ECALL.
 * 
 * @param msg ECALL message to send to enclave
 * @result The result of the ECALL
 */
uint64_t utee_ecall(utee_msg_t* msg);

/**
 * Start the OCALL listener
 * 
 * If the applications provides at least one OCALL, the OCALL handler
 * has to be started using this function. The OCALL handler is started 
 * as a thread, so it does not block. The function returns immediately.
 */
void utee_start_ocall_handler();


/**
 * Start an enclave and connect to the enclave
 * 
 * This wrapper function instantiates the enclaves, connects to it via
 * utee_enclave_connect(), and starts the OCALL handler via utee_start_ocall_handler() 
 * if the application has at least one OCALL registered. 
 * 
 * @param filename File name of the enclave to load and start
 * @return -1 on failure, otherwise the process ID (PID) of the enclave
 */
int utee_enclave_load(const char* filename);

/**
 * Register a signal handler
 * 
 * Applications can register a signal handler. If the enclave receives a signal, 
 * e.g., a segmentation fault, the handler is called and can handle the signal.
 * The handler function receives the signal number, and the instruction pointer
 * where the signal was received. Note that the instruction pointer is rounded
 * down to the page boundary.
 * 
 * @param handler A callback function that gets the signal number and instruction pointer
 */
void utee_register_signal_handler(utee_signal_handler_t handler);

/** @} */


#endif
