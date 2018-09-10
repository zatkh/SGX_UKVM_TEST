
#ifndef _BYPASS_TO_SGXSSL_
#define _BYPASS_TO_SGXSSL_

//file flags
#define O_RDONLY	0x0000
#define O_WRONLY	0x0001
#define O_RDWR		0x0002
#define O_ACCMODE	0x0003
#define O_CREAT		0x0100	/* second byte, away from DOS bits */
#define O_EXCL		0x0200
#define O_NOCTTY	0x0400
#define O_TRUNC		0x0800
#define O_APPEND	0x1000
#define O_NONBLOCK	0x2000



// ocalls wrapper
#define mmap sgxssl_mmap
#define munmap sgxssl_munmap
#define mprotect sgxssl_mprotect
#define mlock sgxssl_mlock
#define madvise sgxssl_madvise

#define printf sgx_printf
#define open t_open
#define close t_close


#if defined(__cplusplus)
extern "C" {
#endif

void sgx_printf(const char *fmt, ...);
int t_close(int fd);
int t_open(const char* pathname, int flags);

#if defined(__cplusplus)
}
#endif

#endif
