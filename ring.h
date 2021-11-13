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

#ifndef PIPETCP_RING_H
#define RING_BUFFER_SIZE 65536
#include <stddef.h>
#include <winsock2.h>

struct ring
{
	unsigned char buffer[RING_BUFFER_SIZE];
	unsigned int prod;
	unsigned int cons;
};


static unsigned int ring_cons_avail(struct ring const *r)
{
	return (RING_BUFFER_SIZE + r->prod - r->cons) % RING_BUFFER_SIZE;
}

static unsigned int ring_prod_avail(struct ring const *r)
{
	return (RING_BUFFER_SIZE - 1 + r->cons - r->prod) % RING_BUFFER_SIZE;
}

static unsigned int ring_cons_avail_linear(struct ring const *r)
{
	return (r->cons > r->prod ? RING_BUFFER_SIZE : r->prod) - r->cons;
}

static unsigned int ring_prod_avail_linear(struct ring const *r)
{
	unsigned int limit = (RING_BUFFER_SIZE - 1 + r->cons) % RING_BUFFER_SIZE;
	return (r->prod > limit ? RING_BUFFER_SIZE : limit) - r->prod;
}

static void ring_prod_advance(struct ring *r, unsigned int n)
{
	r->prod = (r->prod + n) % RING_BUFFER_SIZE;
}

static void ring_cons_advance(struct ring *r, unsigned int n)
{
	r->cons = (r->cons + n) % RING_BUFFER_SIZE;
}

static void *ring_prod_base(struct ring *r)
{
	return (void *)(r->buffer + r->prod);
}

static void *ring_cons_base(struct ring *r)
{
	return (void *)(r->buffer + r->cons);
}

static unsigned int ring_prod_peek_iovecs(struct ring *r, WSABUF *iovp)
{
	unsigned int i = 0, n1, n2;

	n1 = ring_prod_avail_linear(r);
	n2 = ring_prod_avail(r);

	if (n1) {
		iovp[i].buf = (char *)ring_prod_base(r);
		iovp[i].len = n1;
		i++;
	}

	if (n1 < n2) {
		iovp[i].buf = (char *)r->buffer;
		iovp[i].len = n2 - n1;
		i++;
	}

	return i;
}

static unsigned int ring_cons_peek_iovecs(struct ring *r, WSABUF *iovp)
{
	unsigned int i = 0, n1, n2;

	n1 = ring_cons_avail_linear(r);
	n2 = ring_cons_avail(r);

	if (n1) {
		iovp[i].buf = (char *)ring_cons_base(r);
		iovp[i].len = n1;
		i++;
	}

	if (n1 < n2) {
		iovp[i].buf = (char *)r->buffer;
		iovp[i].len = n2 - n1;
		i++;
	}

	return i;
}
#endif
