/****
 * t_io: io wrapper for io ocalls we need inside enclave
 * 
 * 
 * 
 * 
 * 
 * */

#include <stdarg.h>
#include <stdio.h>     
#include <stdlib.h>

#include "sgx_trts.h"
#include "bypass_to_sgx.h"
#include "enclave_t.h"  
#include "t_common.h"




void sgx_printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

int t_close(int fd){
    int ret=0;
	ocall_close(&ret, fd);
	return ret;

}
int t_open(const char* pathname, int flags)
{
	int ret=0;
	printf("[t_open] enter\n");
	ocall_open_short(&ret, pathname,  flags);
	printf("[t_open] pathname: %s, flag: %d, ret: %d \n",pathname, flags,ret);
    return ret;

}
