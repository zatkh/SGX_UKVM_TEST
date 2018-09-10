#ifndef __TMEM_MGMT__
#define __TMEM_MGMT__


// mmap flags

#define FAKE_DEV_ZERO_FD	99
#define PAGE_SIZE 			((uint64_t)0x1000) 	// 4096 Bytes
#define PROT_NONE			0x0
#define PROT_READ			0x1
#define PROT_WRITE			0x2
#define MAP_ANON			0x20
#define MAP_PRIVATE 		0x02
#define MADV_DONTDUMP		16
#define MAP_FAILED			(void *) -1

#ifdef __cplusplus
extern "C" {
#endif

void * mmap_alloc (size_t length);
int sgxssl_munmap (void *addr, size_t len);
int sgxssl_mprotect (void *addr, size_t len, int prot);
int sgxssl_madvise (void *addr, size_t len, int advice);
int sgxssl_mlock (const void *__addr, size_t __len);
extern void * sgxssl_mmap (void *addr, size_t len, int prot, int flags, int fd, __off_t offset);

#ifdef __cplusplus
}
#endif
#endif //__TMEM_MGMT__