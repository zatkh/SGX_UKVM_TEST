#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_close, (int fd));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_open_short, (const char* pathname, int flags));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t ecall_test(sgx_enclave_id_t eid, int val);
sgx_status_t init_private_disk(sgx_enclave_id_t eid, int* retval);
sgx_status_t tfs_test(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_init_blk(sgx_enclave_id_t eid);
sgx_status_t ecall_write_blk(sgx_enclave_id_t eid, int* retval, const void* buf, unsigned long long buf_size);
sgx_status_t ecall_read_blk(sgx_enclave_id_t eid, int* retval, void* buf, unsigned long long buf_size);
sgx_status_t ecall_seek(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
