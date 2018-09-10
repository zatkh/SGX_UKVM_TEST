#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>

#if defined(__cplusplus)
extern "C" {
#endif
int init_private_disk(void);
int tfs_test(void);
void ecall_init_blk(void);
//void printf(const char *fmt, ...);
void ecall_test(int val);
#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
