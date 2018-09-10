
#ifndef TFS_ENCLAVE_H
#define TFS_ENCLAVE_H

#include "../common/common.h"

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
//6705d0cc-0180-4139-9c91-62bb410275be



#define TFS_UUID \
	{ 0x6705d0cc, 0x0180, 0x4139, \
		{ 0x9c, 0x91, 0x62, 0xbb, 0x41, 0x02, 0x75, 0xbe} }




#define TA_HELLO_WORLD_CMD_INC_VALUE 0
#define ECALL_BMFS_TEST 1
#define ECALL_CREATE 2
#define ECALL_OPEN 3
#define ECALL_READ 4
#define ECALL_WRITE 5
#define ECALL_SEEK 6
#define ECALL_CLOSE 7
#define ECALL_BMFS_CLEAN 8
#define ECALL_INIT_PRIVATE_FILE 9



#endif //TFS_ENCLAVE_H
