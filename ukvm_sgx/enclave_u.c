#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_test_t {
	int ms_val;
} ms_ecall_test_t;

typedef struct ms_init_private_disk_t {
	int ms_retval;
} ms_init_private_disk_t;

typedef struct ms_tfs_test_t {
	int ms_retval;
} ms_tfs_test_t;

typedef struct ms_ecall_write_blk_t {
	int ms_retval;
	void* ms_buf;
	unsigned long long ms_buf_size;
} ms_ecall_write_blk_t;

typedef struct ms_ecall_read_blk_t {
	int ms_retval;
	void* ms_buf;
	unsigned long long ms_buf_size;
} ms_ecall_read_blk_t;

typedef struct ms_ecall_seek_t {
	int ms_retval;
} ms_ecall_seek_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_close_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_close_t;

typedef struct ms_ocall_open_short_t {
	int ms_retval;
	char* ms_pathname;
	int ms_flags;
} ms_ocall_open_short_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_close(void* pms)
{
	ms_ocall_close_t* ms = SGX_CAST(ms_ocall_close_t*, pms);
	ms->ms_retval = ocall_close(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_open_short(void* pms)
{
	ms_ocall_open_short_t* ms = SGX_CAST(ms_ocall_open_short_t*, pms);
	ms->ms_retval = ocall_open_short((const char*)ms->ms_pathname, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[7];
} ocall_table_enclave = {
	7,
	{
		(void*)enclave_ocall_print_string,
		(void*)enclave_ocall_close,
		(void*)enclave_ocall_open_short,
		(void*)enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_test(sgx_enclave_id_t eid, int val)
{
	sgx_status_t status;
	ms_ecall_test_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t init_private_disk(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_init_private_disk_t ms;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t tfs_test(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_tfs_test_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_init_blk(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, NULL);
	return status;
}

sgx_status_t ecall_write_blk(sgx_enclave_id_t eid, int* retval, const void* buf, unsigned long long buf_size)
{
	sgx_status_t status;
	ms_ecall_write_blk_t ms;
	ms.ms_buf = (void*)buf;
	ms.ms_buf_size = buf_size;
	status = sgx_ecall(eid, 4, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_read_blk(sgx_enclave_id_t eid, int* retval, void* buf, unsigned long long buf_size)
{
	sgx_status_t status;
	ms_ecall_read_blk_t ms;
	ms.ms_buf = buf;
	ms.ms_buf_size = buf_size;
	status = sgx_ecall(eid, 5, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_seek(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_seek_t ms;
	status = sgx_ecall(eid, 6, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

