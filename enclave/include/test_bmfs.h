#ifndef _TEST_BMFS_H
#define _TEST_BMFS_H

int bmfs_create_blk(void);
int bmfs_delete_file_test(void);
int bmfs_open_blk(void);
int bmfs_write_file_test(void);
int bmfs_read_file_test(void);
int ecall_seek(void);
void bmfs_close_file_test(void);
void bmfs_cleanup(void);
void ecall_init_blk(void);


#endif //_TEST_BMFS_H