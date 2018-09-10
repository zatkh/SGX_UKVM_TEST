#include <stdarg.h>
#include <stdio.h>     
#include <string.h>
#include "enclave.h"
#include "enclave_t.h" 
#include "bypass_to_sgx.h"
#include "t_mem_mgmt.h"



void ecall_test(int val){
    
    val++;
     printf("[ecall_test] %d\n",val);
     printf("from enclave: ecall_test successfull \n");
    
}