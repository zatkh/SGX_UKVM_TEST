
#include "enclave.h"
#include "enclave_t.h" 
#include "bypass_to_sgx.h"

#include <bmfs/dir.h>
#include <bmfs/errno.h>
#include <bmfs/fs.h>
#include <bmfs/file.h>
#include <bmfs/limits.h>
#include <bmfs/ramdisk.h>
#include <bmfs/encoding.h>

#include <stdlib.h>
#include <string.h>

#include "bmfs_assert.h"
#define DEBUG_PRINTF 1

/* Allocate memory for ramdisk */
size_t buf_size = BMFS_MINIMUM_DISK_SIZE;
void *ramdisk_buf;
/* Setup the file system structure. */
struct BMFS p_fs;
/* Setup the ramdisk */
struct BMFSRamdisk p_disk;
struct BMFSFile p_file;
const char* file_name="/tmp/test.txt";
char wbuf[] = "this is a sgx fs test";
bmfs_uint64 wbuf_size=sizeof(wbuf);


int init_private_disk(void)
{
	ramdisk_buf= malloc(buf_size);
	bmfs_assert(ramdisk_buf != NULL);

	bmfs_ramdisk_init(&p_disk);

	int err = bmfs_ramdisk_set_buf(&p_disk, ramdisk_buf, buf_size);
	bmfs_assert(err == 0);

	bmfs_init(&p_fs);

	bmfs_set_disk(&p_fs, &p_disk.base);

	/* Format the disk. */

	err = bmfs_format(&p_fs, buf_size);
	bmfs_assert(err == 0);

	/* Test the creation of directories */

	err = bmfs_create_dir(&p_fs, "/tmp");
	bmfs_assert(err == 0);

	return 0;

}


int bmfs_create_del_file_test(void)
{
	int err = bmfs_create_file(&p_fs, "/tmp/test.txt");
	bmfs_assert(err == 0);
	if(err != 0 )
		{
			printf("[bmfs_create_del_file_test]failed to create file \n");
			return -1;
		}
	else
		printf("[bmfs_create_del_file_test]created the file %s\n","/tmp/test.txt");

	err= bmfs_delete_file(&p_fs, "/tmp/test.txt");	
	if(err != 0 )
		{
			printf("[bmfs_create_del_file_test]failed to delete file \n");
			return -1;
		}
	else
		printf("[bmfs_create_del_file_test]deleted the file %s\n","/tmp/test.txt");

	return 0;	
}

int bmfs_create_blk(void)
{
	int err = bmfs_create_file(&p_fs, file_name);
	bmfs_assert(err == 0);
	if(err != 0 )
		{
			printf("[bmfs_create_blk]failed to create file %s \n", file_name);
			return -1;
		}

	return 0;	
}

int bmfs_delete_file_test(void)
{
	
	int err= bmfs_delete_file(&p_fs, file_name);	
	if(err != 0 )
		{
			printf("[bmfs_create_del_file_test]failed to delete file %s \n", file_name);
			return -1;
		}

	return 0;	
}

int bmfs_open_blk(void)
{

	int err=bmfs_open_file(&p_fs, &p_file, file_name);
	
	if(err !=0)
		{
			printf("[bmfs_open_blk]failed to open file %s \n", file_name);
			return -1;
		}
	
    bmfs_file_set_mode(&p_file,BMFS_FILE_MODE_RW);

	return 0;

}

int bmfs_write_file_test(void)
{

	bmfs_uint64 result;
	int err= bmfs_file_write(&p_file,wbuf, wbuf_size,&result);

	if(err !=0 )
		{
			printf("[bmfs_open_blk]failed to open file %s \n", file_name);
			return -1;
		}
	return 0;

}


int ecall_write_blk(const void* buf,bmfs_uint64 buf_size )
{

	bmfs_uint64 result;
	int err= bmfs_file_write(&p_file,buf, buf_size,&result);

	if(err !=0 )
		{
			printf("[ecall_write_blk]failed to open file %s \n", file_name);
			return -1;
		}
	return 0;

}

int bmfs_read_file_test(void)
{
   	bmfs_uint64 result;
    char * rbuf=  (char*) malloc (sizeof(char)*wbuf_size);
	int err= bmfs_file_read(&p_file,rbuf,wbuf_size,&result);	
	if(err !=0)
		{
			printf("[bmfs_open_blk]failed to open file %s \n", file_name);
			return -1;
		}

	printf("[bmfs_open_blk]read buffer %s \n", rbuf);


return 0;

}
    
int ecall_read_blk( void* buf,bmfs_uint64 buf_size )
{
   	bmfs_uint64 result;
	int err= bmfs_file_read(&p_file,buf,buf_size,&result);	
	if(err !=0)
		{
			printf("[ecall_read_blk]failed to open file %s \n", file_name);
			return -1;
		}

	printf("[ecall_read_blk]read buffer %s \n",(char*) buf);


return 0;

}

int ecall_seek(void)
{
	int err= bmfs_file_seek(&p_file,0,BMFS_SEEK_SET);
	if(err !=0)
		{
			printf("[bmfs_open_blk]failed to open file %s \n", file_name);
			return -1;
		}
	return 0;

}
void bmfs_close_file_test(void)
{
	bmfs_file_close(&p_file);

}

void ecall_init_blk(void)
{
	init_private_disk();
	bmfs_file_init(&p_file);
	bmfs_create_blk();
	bmfs_open_blk();
}



int tfs_test(void)
{

 	printf("fs test start\n");
	int ret=init_private_disk();
	bmfs_file_init(&p_file);
	#ifdef DEBUG_PRINTF
	printf("fs test end, ret: %d \n", ret);
	#endif
	ret=bmfs_create_del_file_test();
	#ifdef DEBUG_PRINTF
	printf("fs create file test end, ret: %d \n", ret);
	#endif

	ret=bmfs_create_blk();
	ret=bmfs_open_blk();
	ret=bmfs_write_file_test();
	ret=ecall_seek();
	ret=bmfs_read_file_test();

	if(ret !=0)
		{
			printf("[tfs_test]failed  \n");
			return -1;
		}

	//int ret=fs_test();

	return 0;

}

void bmfs_cleanup(void)
{
	bmfs_delete_file_test();	
	free(ramdisk_buf);


}

