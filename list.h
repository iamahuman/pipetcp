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

#ifndef PIPETCP_LIST_H
#define PIPETCP_LIST_H

struct listhead
{
	struct listhead *next;
	struct listhead *prev;
};

static void list_init(struct listhead *list)
{
	list->next = list;
	list->prev = list;
}

#define DECLARE_LISTHEAD(name) struct listhead name = { &name, &name }

static int list_empty(struct listhead *list)
{
	return list->next == list && list->prev == list;
}

static void list_insert_internal(struct listhead *item, struct listhead *prev, struct listhead *next)
{
	item->prev = prev;
	item->next = next;
	prev->next = item;
	next->prev = item;
}

static void list_append(struct listhead *list, struct listhead *item)
{
	list_insert_internal(item, list->prev, list);
}

static void list_remove_internal(struct listhead *next, struct listhead *prev)
{
	next->prev = prev;
	prev->next = next;
}

static void list_remove(struct listhead *item)
{
	list_remove_internal(item->next, item->prev);
	list_init(item);
}

static struct listhead *list_first(struct listhead *item)
{
	struct listhead *next = item->next;
	return next == item ? NULL : next;
}

static struct listhead *list_last(struct listhead *item)
{
	struct listhead *next = item->next;
	return next == item ? NULL : next;
}

#define foreach_list_safe(list, iter, next) \
	for ((iter) = (list)->next; \
		(next) = (iter)->next, (iter) != (list); \
		(iter) = (next))

#endif
