// LD_PRELOAD wrapper to print the (estimated) peak memory usage

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <malloc.h>

static void *(*origmalloc        )(size_t);
static void *(*origcalloc        )(size_t, size_t);
static void *(*origrealloc       )(void *, size_t);
static void  (*origfree          )(void *);
#if doalign
static void *(*origvalloc        )(size_t);
static void *(*origpvalloc       )(size_t);
static void  (*origmemalign      )(size_t, size_t);
static void *(*origaligned_alloc )(size_t, size_t);
static int   (*origposix_memalign)(void **, size_t, size_t);
#endif
#if dommap
static void *(*origmmap          )(void *, size_t, int, int, int, off_t);
static int   (*origmunmap        )(void *, size_t);
static void *(*origmremap        )(void *, size_t, size_t, int, void *);
#endif
// no brk and sbrk...

enum {
  MALLOC,
  CALLOC,
  REALLOC,
  FREE,
  VALLOC,
  PVALLOC,
  MEMALIGN,
  ALIGNED_ALLOC,
  POSIX_MEMALIGN,
  MMAP,
  MUNMAP,
  MREMAP,
  EMPTYENTRY
};

static const char *names[] = {
  [MALLOC]         = "malloc",
  [CALLOC]         = "calloc",
  [REALLOC]        = "realloc",
  [FREE]           = "free",
  [VALLOC]         = "valloc",
  [PVALLOC]        = "pvalloc",
  [MEMALIGN]       = "memalign",
  [ALIGNED_ALLOC]  = "aligned_alloc",
  [POSIX_MEMALIGN] = "posix_memalign",
  [MMAP]           = "mmap",
  [MUNMAP]         = "munmap",
  [MREMAP]         = "mremap",
};

static size_t totalsize, maxsize, count[EMPTYENTRY];




// simple hash table with linear probing

static struct {
  void **k;
  size_t *v;
  size_t used, size;
} table;

#if 0
// jenkins hash
static uint32_t hash(void *ptr) {
  char buf[sizeof(void *)];
  memcpy(buf, &ptr, sizeof buf);
  uint32_t ret = 0;
  for (size_t i = 0; i < sizeof(void *); i++) {
    ret += buf[i];
    ret += ret << 10;
    ret ^= ret >> 6;
  }
  ret += ret << 3;
  ret ^= ret >> 11;
  ret += ret << 15;
  return ret;
}
#else
// http://stackoverflow.com/a/12996028/2815203
static uint32_t hash32(void *ptr) {
  uintptr_t x = (uintptr_t)ptr;
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = (x >> 16) ^ x;
  return x;
}
static uint64_t hash64(void *ptr) {
  uintptr_t x = (uintptr_t)ptr;
  x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
  x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
  x = x ^ (x >> 31);
  return x;
}
#define hash(x) (sizeof(x) == sizeof(uint32_t) ? hash32(x) : hash64(x))
#endif

#define DELETED ((void *)1)
static size_t insert_size(void *ptr, size_t size) {
  size_t h = hash(ptr) & (table.size - 1);
  while (table.k[h] && table.k[h] != DELETED)
    h = (h + 1) & (table.size - 1);

  int deleted = table.k[h] == DELETED;
  table.k[h] = ptr;
  table.v[h] = size;

  if (!deleted && table.used++ > table.size/2) {
    table.size *= 2;
    table.used = 0;

    void  **tmpk = table.k;
    size_t *tmpv = table.v;
    table.k = origcalloc(table.size, sizeof(void *));
    table.v = origcalloc(table.size, sizeof(size_t));

    for (size_t i = 0; i < table.size/2; i++)
      if (tmpk[i] && tmpk[i] != DELETED)
        insert_size(tmpk[i], tmpv[i]);

    origfree(tmpk);
    origfree(tmpv);
  }
  return table.v[h];
}

static inline size_t insert(void *ptr) {
  return insert_size(ptr, malloc_usable_size(ptr)); // sorta portable...
}

static size_t lookup(void *ptr) {
  size_t h = hash(ptr) & (table.size - 1);
  while (table.k[h] && table.k[h] != ptr)
    h = (h + 1) & (table.size - 1);

  if (!table.k[h]) write(2, "error, abort abort!!!\n", 22), abort(); // double free
  table.k[h] = DELETED;
  return table.v[h];
}




// the actual wrappers
void *malloc(size_t size) {
  count[MALLOC]++;
  void *ret = origmalloc(size);
  totalsize += insert(ret);
  if (maxsize < totalsize) maxsize = totalsize;
  return ret;
}

void *realloc(void *ptr, size_t size) {
  count[REALLOC]++;
  void *ret = origrealloc(ptr, size);
  if (ptr) totalsize -= lookup(ptr); // realloc(NULL, ..) is legal
  totalsize += insert(ret);
  if (maxsize < totalsize) maxsize = totalsize;
  return ret;
}

void free(void *ptr) {
  count[FREE]++;
  if (!ptr) return; // free(NULL) is valid but 0 is used as an empty key
  totalsize -= lookup(ptr);
  origfree(ptr);
}

void *calloc(size_t nmemb, size_t size) {
  count[CALLOC]++;
  void *ret = origcalloc(nmemb, size);
  totalsize += insert(ret);
  if (maxsize < totalsize) maxsize = totalsize;
  return ret;
}

#if doalign
void *valloc(size_t size) {
  count[VALLOC]++;
  void *ret = origvalloc(size);
  totalsize += insert(ret);
  if (maxsize < totalsize) maxsize = totalsize;
  return ret;
}

void *pvalloc(size_t size) {
  count[PVALLOC]++;
  void *ret = origpvalloc(size);
  totalsize += insert(ret);
  if (maxsize < totalsize) maxsize = totalsize;
  return ret;
}

void *memalign(size_t alignment, size_t size) {
  count[MEMALIGN]++;
  void *ret = origaligned_alloc(alignment, size);
  totalsize += insert(ret);
  if (maxsize < totalsize) maxsize = totalsize;
  return ret;
}

void *aligned_alloc(size_t alignment, size_t size) {
  count[ALIGNED_ALLOC]++;
  void *ret = origaligned_alloc(alignment, size);
  totalsize += insert(ret);
  if (maxsize < totalsize) maxsize = totalsize;
  return ret;
}

int posix_memalign(void **ptr, size_t alignment, size_t size) {
  count[POSIX_MEMALIGN]++;
  int ret = origposix_memalign(ptr, alignment, size);
  totalsize += insert(*ptr);
  if (maxsize < totalsize) maxsize = totalsize;
  return ret;
}
#endif

#if dommap
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  count[MMAP]++;
  void *ret = origmmap(addr, length, prot, flags, fd, offset);
  totalsize += insert_size(ret, length);
  if (maxsize < totalsize) maxsize = totalsize;
  return ret;
}

int munmap(void *ptr, size_t length) {
  count[MUNMAP]++;
  // same problem as above...  but munmap(NULL, x) is invalid (at least on linux)
  if (ptr) totalsize -= lookup(ptr);
  return origmunmap(ptr, length);
}

void *mremap(void *old_addr, size_t old_len, size_t new_len, int flags, void *new_addr) {
  count[MREMAP]++;
  void *ret = mremap(old_addr, old_len, new_len, flags, new_addr);
  totalsize -= lookup(old_addr);
  totalsize += insert(ret);
  if (maxsize < totalsize) maxsize = totalsize;
	return ret;
}
#endif




// ctor/dtor
__attribute__((constructor))
static void begin() {
  origmalloc         = dlsym(RTLD_NEXT, "malloc"        );
  origcalloc         = dlsym(RTLD_NEXT, "calloc"        );
  origrealloc        = dlsym(RTLD_NEXT, "realloc"       );
  origfree           = dlsym(RTLD_NEXT, "free"          );
#if doalign
  origvalloc         = dlsym(RTLD_NEXT, "valloc"        );
  origpvalloc        = dlsym(RTLD_NEXT, "pvalloc"       );
  origmemalign       = dlsym(RTLD_NEXT, "memalign"      );
  origaligned_alloc  = dlsym(RTLD_NEXT, "aligned_alloc" );
  origposix_memalign = dlsym(RTLD_NEXT, "posix_memalign");
#endif
#if dommap
  origmmap           = dlsym(RTLD_NEXT, "mmap"          );
  origmremap         = dlsym(RTLD_NEXT, "mremap"        );
  origmunmap         = dlsym(RTLD_NEXT, "munmap"        );
#endif

  table.size = 1024;
  table.k = origcalloc(table.size, sizeof(void *));
  table.v = origcalloc(table.size, sizeof(size_t));
}

__attribute__((destructor))
static void end() {
  fprintf(stderr, "%20s: %20zu bytes\n", "peak memory usage", maxsize);

  for (int i = 0; i < EMPTYENTRY; i++)
    if (count[i])
      fprintf(stderr, "%20s: %20zu times\n", names[i], count[i]);
}
