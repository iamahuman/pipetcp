/*
 * Copyright (c) 2021  Jinoh Kang
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifdef UAF_DEBUG
static unsigned char *udm_base;
static unsigned char *udm_next;
static unsigned char *udm_end;
static size_t allocsize;

static void udm_init(void)
{
	SYSTEM_INFO sinfo;
	size_t totsize;

	if (udm_base)
		return;

	GetSystemInfo(&sinfo);
	allocsize = sinfo.dwPageSize;
	if (allocsize < sizeof(struct client))
		allocsize = (sizeof(struct client) + allocsize - 1) / allocsize * allocsize;

	totsize = allocsize * 0x100;
	udm_base = VirtualAlloc(
		(void *)0x18000000UL,
		totsize,
		MEM_RESERVE,
		PAGE_NOACCESS
	);
	if (!udm_base)
		abort();

	udm_next = udm_base + allocsize;
	udm_end = udm_base + totsize;
}

static void *udm_alloc(void)
{
	unsigned char *ptr;
	size_t size;

	udm_init();

	size = allocsize;
	ptr = udm_next;
	if (ptr + size > udm_end)
		return NULL;
	if (!VirtualAlloc((void *)ptr, size, MEM_COMMIT, PAGE_READWRITE))
		return NULL;
	udm_next += size;

	return (void *)ptr;
}

static void udm_free(void *mem)
{
	DWORD err, prot;
	size_t size;
	unsigned char *ptr = (unsigned char *)mem;

	if (!(udm_base <= ptr && ptr < udm_next)) {
		fprintf(stderr, "invalid pointer passed to free: %p\n", mem);
		abort();
	}
	if ((ptr - udm_base) % allocsize) {
		fprintf(stderr, "invalid pointer passed to free: %p\n", mem);
		abort();
	}

	size = allocsize;
	err = GetLastError();
	if (!VirtualProtect((void *)ptr, size, PAGE_NOACCESS, &prot) ||
	    prot == PAGE_NOACCESS) {
		fprintf(stderr, "double free(): %p\n", mem);
		abort();
	}
	VirtualFree((void *)ptr, size, MEM_DECOMMIT);
	SetLastError(err);
}
#endif
