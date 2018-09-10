/* ===============================================================
 * Baremetal File System - A file system designed for BareMetal OS
 * Copyright (C) 2008 - 2018 Return Infinity
 * See COPYING for license information.
 * ===============================================================
 */

#include <bmfs/time.h>
#include <time.h>

//#include "sgx_tae_service.h"

int bmfs_get_current_time(bmfs_uint64 *time_ptr) {
/*
	sgx_time_source_nonce_t nonce = {0};
	sgx_time_t current_timestamp;
    uint32_t ret = sgx_get_trusted_time(&current_timestamp, &nonce);
       
       if(ret != SGX_SUCCESS)
	   	return -1;

	*time_ptr = current_timestamp;

*/
	return 0;
}
	