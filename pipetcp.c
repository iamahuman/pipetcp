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

#ifndef WINVER
#define WINVER 0x0500
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0500
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <wchar.h>
#include <windows.h>
#include <sddl.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "list.h"
#include "ring.h"
#include "errors.h"

#define IOCP_USED 1

typedef BOOL WINAPI (*LPCANCELIOEX)(HANDLE hFile, LPOVERLAPPED lpOverlapped);

enum struct_magic
{
	CLIENT_OBJ_MAGIC = 0X22B778B9,
	SERVER_OBJ_MAGIC = 0x1733531A,
};

enum retry_flags
{
	RETRY_READ = 1,
	RETRY_WRITE = 2,
};

enum status
{
	IOSTATE_IDLE,
	IOSTATE_PENDING,
};

enum connect_status
{
	CLIENT_DISCONNECTED,
	CLIENT_CONNECTED,
};

enum server_state
{
	SERVER_INITIALISING,
	SERVER_LISTENING,
	SERVER_TERMINATING,
};

struct pipeserver_params
{
	LPCWSTR name;
	DWORD open_mode;
	DWORD pipe_mode;
	DWORD max_instances;
	DWORD out_buffer_size;
	DWORD in_buffer_size;
	DWORD default_timeout;
	LPSECURITY_ATTRIBUTES security_attributes;
};

struct socket_tx
{
	struct listhead list;
	unsigned char state;

	WSABUF iovs[2];
	DWORD iovcnt, iovoff;

	struct client *cli_ref;
};

struct pipe_tx
{
	struct listhead list;
	unsigned char state;

	unsigned char *buffer;
	DWORD length;

	struct server *srv_ref;
};

struct server
{
	DWORD magic;
	unsigned long refcount;

	struct listhead clients[2];
	struct listhead retry_io_clients;
	struct listhead socket_tx_queue;

	struct pipeserver_params params;
	DWORD num_threads;
	unsigned char is_datagram;
	unsigned char state;
	unsigned char read_pending;

	DWORD error;
	DWORD last_tick_time;

	unsigned long num_clients[2];
	unsigned long num_backlog;
	size_t required_room;

	HANDLE iocp;

	SOCKET socket;
	WSAOVERLAPPED sock_read_ov;
	WSAOVERLAPPED sock_write_ov;

	WSABUF iovs[2];

	struct pipe_tx socket2pipe;
	struct ring readbuf;
};

struct client
{
	DWORD magic;
	unsigned long refcount;

	struct listhead list;
	struct listhead list_retry_io;
	struct listhead pipe_tx_queue;
	struct client *closing_next;
	struct server *srv;

	DWORD next_io_retry_at;
	unsigned char retry_flags;

	unsigned char is_connected;
	unsigned char read_pending;
	size_t required_room;

	HANDLE pipe;
	OVERLAPPED pipe_connect_ov;
	OVERLAPPED pipe_read_ov;
	OVERLAPPED pipe_write_ov;

	struct socket_tx pipe2socket;
	struct ring readbuf;
};

#include "udm.h"

#ifdef DEBUG
#define trace_prefix_(x, y) x ":" #y " "
#define trace_prefix(x, y) trace_prefix_(x, y)
#define trace(...) fprintf(stderr, trace_prefix(__FILE__, __LINE__) __VA_ARGS__)
#else
#define trace(...) ((void)0)
#endif

static LPCANCELIOEX lpCancelIoEx;

static DWORD on_server_write(struct server *srv, DWORD err, DWORD nsent);
static DWORD on_server_read(struct server *srv, DWORD err, DWORD nread);
static DWORD on_client_connect(struct client *cli, DWORD err);
static DWORD on_client_read(struct client *cli, DWORD err, DWORD nread);
static DWORD on_client_write(struct client *cli, DWORD err, DWORD nwritten);
static DWORD update_client(struct client *cli, BOOL incoming, unsigned char suppress_io);
static DWORD update_server(struct server *srv, BOOL incoming, unsigned char suppress_io);
static void remove_socket_tx(struct socket_tx *item);
static void remove_pipe_tx(struct pipe_tx *item);
static DWORD server_start_read(struct server *srv);
static DWORD server_start_write(struct server *srv);
static DWORD client_start_connect(struct client *cli);
static DWORD client_start_read(struct client *cli);
static DWORD client_start_write(struct client *cli);


static void dumpring(struct ring const *r, const char *name)
{
	(void)r;
	(void)name;
	trace("## [%s] %p: PROD=%u CONS=%u [", name, r, (unsigned)r->prod, (unsigned)r->cons);
#if 0
	for (size_t i = r->cons; i != r->prod; i = (i + 1) % RING_BUFFER_SIZE)
		fputc(r->buffer[i], stderr);
#endif
	trace("]\n");
}

static BOOL is_pipe_datagram(struct server const *srv)
{
	return (srv->params.pipe_mode & PIPE_TYPE_MESSAGE) == PIPE_TYPE_MESSAGE;
}

static void check_client_obj(struct client const *cli)
{
	if (cli->magic != CLIENT_OBJ_MAGIC || !cli->refcount) {
		fprintf(stderr, "invalid client object (%p): %#lx, %lu\n", cli, cli->magic, cli->refcount);
		abort();
	}
}

static void check_server_obj(struct server const *srv)
{
	if (srv->magic != SERVER_OBJ_MAGIC || !srv->refcount) {
		fprintf(stderr, "invalid server object (%p): %#lx, %lu\n", srv, srv->magic, srv->refcount);
		abort();
	}
}

static struct server *server_get(struct server *srv)
{
	if (!srv)
		return srv;

	check_server_obj(srv);
	srv->refcount++;
	check_server_obj(srv);
	return srv;
}

static void server_put(struct server *srv)
{
	if (!srv)
		return;

	check_server_obj(srv);
	if (!--srv->refcount) {
		DWORD err = GetLastError();
		if (srv->iocp) {
			CloseHandle(srv->iocp);
			srv->iocp = NULL;
		}
		SetLastError(err);
	}
	return;
}

static struct client *client_alloc(void)
{
#ifdef UAF_DEBUG
	return (struct client *)udm_alloc();
#else
	return (struct client *)HeapAlloc(
		GetProcessHeap(),
		0,
		sizeof(struct client)
	);
#endif
}

static void client_free(struct client *cli)
{
	trace("client_free(%p)\n", cli);
#ifdef UAF_DEBUG
	udm_free((void *)cli);
#else
	HeapFree(GetProcessHeap(), 0, (void *)cli);
#endif
}

static struct client *client_get(struct client *cli)
{
	trace("client_get(%p) #refs=%lu\n", cli, cli ? cli->refcount : 0);

	if (!cli)
		return cli;

	check_client_obj(cli);
	cli->refcount++;
	check_client_obj(cli);
	return cli;
}

static void client_put(struct client *cli)
{
	trace("client_put(%p) #refs=%lu\n", cli, cli ? cli->refcount : 0);

	if (!cli)
		return;

	check_client_obj(cli);
	if (!--cli->refcount) {
		DWORD err = GetLastError();
		if (cli->pipe != INVALID_HANDLE_VALUE) {
			CloseHandle(cli->pipe);
			cli->pipe = INVALID_HANDLE_VALUE;
		}
		server_put(cli->srv);
		client_free(cli);
		SetLastError(err);
	}
}

static void set_server_ref(struct server **ptr, struct server *srv)
{
	struct server *old;

	old = *ptr;
	if (old != srv) {
		*ptr = server_get(srv);
		server_put(old);
	}
}

static void set_client_ref(struct client **ptr, struct client *cli)
{
	struct client *old;

	old = *ptr;
	if (old != cli) {
		*ptr = client_get(cli);
		client_put(old);
	}
}

static struct server *pop_server_ref(struct server **ptr)
{
	struct server *old = *ptr;
	*ptr = NULL;
	return old;
}

static struct client *pop_client_ref(struct client **ptr)
{
	struct client *old = *ptr;
	*ptr = NULL;
	return old;
}

static void client_remove_from_list(struct client *cli)
{
	unsigned long num;
	struct server *srv = cli->srv;

	check_client_obj(cli);

	if (!srv || list_empty(&cli->list))
		return;

	list_remove(&cli->list);
	num = srv->num_clients[!!cli->is_connected]--;

	if (!num) {
		fprintf(stderr, "counter underflow\n");
		abort();
	}
}

static void client_add_to_list(struct client *cli)
{
	unsigned long num;
	struct server *srv = cli->srv;

	check_client_obj(cli);

	if (!srv || !list_empty(&cli->list))
		return;

	list_append(&srv->clients[!!cli->is_connected], &cli->list);
	num = ++srv->num_clients[!!cli->is_connected];

	if (!num) {
		fprintf(stderr, "counter overflow\n");
		abort();
	}
}

static void client_cancel_retry(struct client *cli, unsigned char retry_flags)
{
	check_client_obj(cli);

	cli->retry_flags &= ~retry_flags;
	if (!cli->retry_flags)
		list_remove(&cli->list_retry_io);
}

static void client_set_connected(struct client *cli, BOOL connected)
{
	unsigned char new_is_connected = !!connected;

	check_client_obj(cli);

	if (cli->is_connected == new_is_connected)
		return;

	client_cancel_retry(cli, RETRY_READ);

	client_remove_from_list(cli);
	cli->is_connected = new_is_connected;
	client_add_to_list(cli);
}

static BOOL client_is_reusable(struct client *cli)
{
	check_client_obj(cli);

	if (list_empty(&cli->list)) {
		/* client is already removed and awaiting free */
		return FALSE;
	}

	if (cli->is_connected) {
		/* cannot reuse an already connected client */
		return FALSE;
	}

	if (cli->read_pending != IOSTATE_IDLE) {
		/* has pending I/O, cannot reuse */
		return FALSE;
	}

	if (!list_empty(&cli->pipe_tx_queue)) {
		/* TX queue is waiting to be flushed */
		return FALSE;
	}

	if ((cli->retry_flags & RETRY_READ) && !list_empty(&cli->list_retry_io)) {
		/* retrying connection */
		return FALSE;
	}

	if (!list_empty(&cli->pipe2socket.list)) {
		/* TODO should this block reusing client? */
		return FALSE;
	}

	return TRUE;
}

static void client_close(struct client *cli)
{
	DECLARE_LISTHEAD(remove_list);
	struct listhead *item, *next;
	struct pipe_tx *tx;
	DWORD err;

	trace("client_close(%p)\n", cli);

	check_client_obj(cli);

	err = GetLastError();

	if (cli->is_connected) {
		if (cli->pipe != INVALID_HANDLE_VALUE) {
			HANDLE handle = cli->pipe;
			if (lpCancelIoEx) {
				(*lpCancelIoEx)(handle, &cli->pipe_connect_ov);
				(*lpCancelIoEx)(handle, &cli->pipe_read_ov);
				(*lpCancelIoEx)(handle, &cli->pipe_write_ov);
			} else {
				CancelIo(handle);
			}
			DisconnectNamedPipe(handle);
		}
		client_set_connected(cli, FALSE);
	}

	foreach_list_safe(&cli->pipe_tx_queue, item, next) {
		tx = CONTAINING_RECORD(item, struct pipe_tx, list);
		if (tx->state == IOSTATE_IDLE) {
			list_remove(item);
			list_append(&remove_list, item);
		}
	}
	foreach_list_safe(&remove_list, item, next) {
		tx = CONTAINING_RECORD(item, struct pipe_tx, list);
		remove_pipe_tx(tx);
		assert(next->prev != item);
	}
	assert(list_empty(&remove_list));

	update_client(cli, FALSE, 0);
	SetLastError(err);
}

static void client_handle_error(struct client *cli, DWORD err, unsigned char retry_flags, DWORD retry_delay)
{
	trace("client_handle_error(%p, %lu, %d, %lu)\n", cli, err, retry_flags, retry_delay);

	check_client_obj(cli);

	if (list_empty(&cli->list))
		return;

	if (is_error_nonrecoverable(err)) {
		fprintf(stderr, "killing client %p due to %lu\n", cli->pipe, err);
		client_close(cli);
		return;
	}

	if (err != ERROR_RETRY) {
		cli->retry_flags |= retry_flags;
		if (list_empty(&cli->list_retry_io)) {
			cli->next_io_retry_at = GetTickCount() + retry_delay;
			list_append(&cli->srv->retry_io_clients, &cli->list_retry_io);
		}
		update_client(cli, FALSE, 0);
	} else {
		update_client(cli, FALSE, retry_flags);
	}

}

static unsigned long server_get_num_clients(struct server const *srv)
{
	check_server_obj(srv);

	return srv->num_clients[CLIENT_DISCONNECTED] + srv->num_clients[CLIENT_CONNECTED];
}

static BOOL server_register_handle(struct server *srv, HANDLE handle, ULONG_PTR key)
{
	HANDLE iocp;

	trace("server_register_handle(%p, %p, %p)\n", srv, handle, (void *)key);

	check_server_obj(srv);

	iocp = CreateIoCompletionPort(handle, srv->iocp, key, srv->num_threads);
	if (!iocp)
		return FALSE;

	srv->iocp = iocp;
	return TRUE;
}

static BOOL server_init(struct server *srv,
			struct pipeserver_params const *params,
			unsigned long backlog,
			DWORD num_threads,
			SOCKET socket,
			BOOL is_datagram)
{
	srv->magic = SERVER_OBJ_MAGIC;
	srv->refcount = 1;
	list_init(&srv->clients[CLIENT_DISCONNECTED]);
	list_init(&srv->clients[CLIENT_CONNECTED]);
	list_init(&srv->retry_io_clients);
	list_init(&srv->socket_tx_queue);
	srv->params = *params;
	srv->num_threads = num_threads;
	srv->is_datagram = !!is_datagram;
	srv->state = SERVER_INITIALISING;
	srv->read_pending = IOSTATE_IDLE;
	srv->error = ERROR_SUCCESS;
	srv->last_tick_time = 0;
	srv->num_clients[CLIENT_DISCONNECTED] = 0;
	srv->num_clients[CLIENT_CONNECTED] = 0;
	srv->num_backlog = backlog;
	srv->required_room = 1;
	srv->iocp = NULL;
	srv->socket = socket;
	memset(&srv->sock_read_ov, 0, sizeof(srv->sock_read_ov));
	memset(&srv->sock_write_ov, 0, sizeof(srv->sock_write_ov));
	memset(&srv->iovs, 0, sizeof(srv->iovs));
	memset(&srv->socket2pipe, 0, sizeof(struct pipe_tx));
	list_init(&srv->socket2pipe.list);
	srv->readbuf.prod = 0;
	srv->readbuf.cons = 0;

	return server_register_handle(srv, (HANDLE)socket, 0);
}

static void server_close_clients(struct server *srv)
{
	struct client *closing_next, *cli;
	struct listhead *item, *next;
	unsigned int is_connected;

	assert(srv->state == SERVER_TERMINATING);

	closing_next = NULL;
	for (is_connected = CLIENT_DISCONNECTED; is_connected <= CLIENT_CONNECTED; is_connected++) {
		foreach_list_safe(&srv->clients[is_connected], item, next) {
			cli = CONTAINING_RECORD(item, struct client, list);
			assert(cli->closing_next == NULL);
			cli->closing_next = closing_next;
			closing_next = cli;
		}
	}

	while (closing_next) {
		cli = closing_next;
		closing_next = cli->closing_next;
		cli->closing_next = NULL;
		client_close(cli);
	}
	assert(list_empty(&srv->clients[CLIENT_DISCONNECTED]));
	assert(list_empty(&srv->clients[CLIENT_CONNECTED]));
}

static void server_close(struct server *srv)
{
	DECLARE_LISTHEAD(remove_list);
	struct listhead *item, *next;
	struct socket_tx *tx;
	DWORD err;

	trace("server_close(%p)\n", srv);

	check_server_obj(srv);

	if (srv->state == SERVER_TERMINATING)
		return;

	err = GetLastError();
	srv->state = SERVER_TERMINATING;
	server_close_clients(srv);

	foreach_list_safe(&srv->socket_tx_queue, item, next) {
		tx = CONTAINING_RECORD(item, struct socket_tx, list);
		if (tx->state == IOSTATE_IDLE) {
			list_remove(item);
			list_append(&remove_list, item);
		}
	}
	foreach_list_safe(&remove_list, item, next) {
		tx = CONTAINING_RECORD(item, struct socket_tx, list);
		remove_socket_tx(tx);
		assert(next->prev != item);
	}
	assert(list_empty(&remove_list));

	if (srv->socket != INVALID_SOCKET) {
		HANDLE handle = (HANDLE)srv->socket;
		if (lpCancelIoEx) {
			(*lpCancelIoEx)(handle, &srv->sock_read_ov);
			(*lpCancelIoEx)(handle, &srv->sock_write_ov);
		} else {
			CancelIo(handle);
		}
		shutdown(srv->socket, SD_BOTH);
	}
	server_put(srv);
	SetLastError(err);
}

static void server_error(struct server *srv, DWORD err)
{
	trace("server_error(%p, %lu)\n", srv, err);

	fprintf(stderr, "killing server due to %lu\n", err);

	check_server_obj(srv);

	if (srv->error == ERROR_SUCCESS)
		srv->error = err;
	server_close(srv);
}

static BOOL server_is_accepting_clients(struct server *srv, unsigned long count)
{
	unsigned long max_clients;

	if (srv->state == SERVER_TERMINATING)
		return FALSE;

	if (count > srv->num_backlog ||
	    srv->num_clients[CLIENT_DISCONNECTED] > srv->num_backlog - count)
		return FALSE;

	max_clients = srv->params.max_instances == PIPE_UNLIMITED_INSTANCES
		? (unsigned long)-1 : srv->params.max_instances;
	if (count > max_clients ||
	    server_get_num_clients(srv) > max_clients - count)
		return FALSE;

	return TRUE;
}

static size_t iovec_advance(WSABUF *iovec, size_t count, ULONG len)
{
	size_t i;
	for (i = 0; i < count; i++) {
		if (iovec[i].len > len) {
			iovec[i].buf += len;
			iovec[i].len -= len;
			break;
		}
	}
	return i;
}

static void server_append_tx(struct server *srv, struct socket_tx *tx)
{
	trace("server_append_tx(%p, %p)\n", srv, tx);

	check_server_obj(srv);

	assert(list_empty(&tx->list));
	assert(tx->state == IOSTATE_IDLE);

	list_append(&srv->socket_tx_queue, &tx->list);
	server_start_write(srv);
}

static void client_append_tx(struct client *cli, struct pipe_tx *tx)
{
	trace("client_append_tx(%p, %p)\n", cli, tx);

	check_client_obj(cli);

	assert(list_empty(&tx->list));
	assert(tx->state == IOSTATE_IDLE);

	list_append(&cli->pipe_tx_queue, &tx->list);
	client_start_write(cli);
}

static void remove_socket_tx(struct socket_tx *item)
{
	struct client *cli;

	trace("remove_socket_tx(%p)\n", item);

	assert(item->state == IOSTATE_IDLE);
	list_remove(&item->list);
	memset(&item->iovs, 0, sizeof(item->iovs));
	item->iovcnt = 0;
	item->iovoff = 0;
	cli = pop_client_ref(&item->cli_ref);
	if (cli) {
		update_client(cli, FALSE, 0);
		client_put(cli);
	}
}

static void remove_pipe_tx(struct pipe_tx *item)
{
	struct server *srv;

	trace("remove_pipe_tx(%p)\n", item);

	assert(item->state == IOSTATE_IDLE);
	list_remove(&item->list);
	item->buffer = NULL;
	item->length = 0;
	srv = pop_server_ref(&item->srv_ref);
	if (srv) {
		update_server(srv, FALSE, 0);
		server_put(srv);
	}
}

static BOOL client_init(struct client *cli, struct server *srv, HANDLE pipe)
{
	trace("client_init(%p, %p, %p)\n", cli, srv, pipe);

	check_server_obj(srv);

	cli->magic = CLIENT_OBJ_MAGIC;
	cli->refcount = 1;
	list_init(&cli->list);
	list_init(&cli->list_retry_io);
	list_init(&cli->pipe_tx_queue);
	cli->closing_next = NULL;
	cli->srv = server_get(srv);
	cli->next_io_retry_at = 0;
	cli->retry_flags = 0;
	cli->is_connected = 0;
	cli->read_pending = IOSTATE_IDLE;
	cli->required_room = 1;
	cli->pipe = pipe;
	memset(&cli->pipe_connect_ov, 0, sizeof(cli->pipe_connect_ov));
	memset(&cli->pipe_read_ov, 0, sizeof(cli->pipe_read_ov));
	memset(&cli->pipe_write_ov, 0, sizeof(cli->pipe_write_ov));
	memset(&cli->pipe2socket, 0, sizeof(cli->pipe2socket));
	list_init(&cli->pipe2socket.list);
	cli->readbuf.prod = 0;
	cli->readbuf.cons = 0;

	if (!server_register_handle(srv, pipe, (ULONG_PTR)cli)) {
		client_put(cli);
		return FALSE;
	}

	client_add_to_list(cli);
	return TRUE;
}

static DWORD client_start_connect(struct client *cli)
{
	DWORD err;
	BOOL res;

	trace("client_start_connect(%p)\n", cli);

retry:
	check_client_obj(cli);

	client_cancel_retry(cli, RETRY_READ);

	if (list_empty(&cli->list) || cli->is_connected)
		return ERROR_SUCCESS;

	if (cli->read_pending != IOSTATE_IDLE)
		return ERROR_MORE_DATA;

	client_get(cli);
	cli->read_pending = IOSTATE_PENDING;
	err = 0;
	memset(&cli->pipe_connect_ov, 0, sizeof(cli->pipe_connect_ov));
	res = ConnectNamedPipe(cli->pipe, &cli->pipe_connect_ov);

	if (!res && (err = GetLastError()) == ERROR_IO_PENDING) {
		cli->srv->params.open_mode &= ~FILE_FLAG_FIRST_PIPE_INSTANCE;
		return ERROR_IO_PENDING;
	}

	if (res)
		cli->srv->params.open_mode &= ~FILE_FLAG_FIRST_PIPE_INSTANCE;

	if (!res || !IOCP_USED) {
		err = on_client_connect(cli, err);
		if (err == ERROR_RETRY)
			goto retry;
	}

	return res;
}

static DWORD server_listen_for_next_client(struct server *srv)
{
	struct client *cli;
	HANDLE pipe;
	DWORD err;

	trace("server_listen_for_next_client(%p)\n", srv);

	check_server_obj(srv);

	if (!server_is_accepting_clients(srv, 1))
		return ERROR_MORE_DATA;

	SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	cli = client_alloc();
	if (!cli)
		return GetLastError();

	pipe = CreateNamedPipeW(
		srv->params.name,
		srv->params.open_mode | FILE_FLAG_OVERLAPPED,
		srv->params.pipe_mode,
		srv->params.max_instances,
		srv->params.out_buffer_size,
		srv->params.in_buffer_size,
		srv->params.default_timeout,
		srv->params.security_attributes
	);
	if (pipe == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		client_free(cli);
		return err;
	}

	if (!client_init(cli, srv, pipe)) {
		err = GetLastError();
		CloseHandle(pipe);
		client_free(cli);
		return err;
	}

	return update_client(cli, FALSE, 0);
}

static DWORD server_listen(struct server *srv)
{
	DWORD err;

	while ((err = server_listen_for_next_client(srv)) == ERROR_SUCCESS)
		;

	return err == ERROR_MORE_DATA ? 0 : err;
}

static DWORD on_client_connect(struct client *cli, DWORD err)
{
	trace("on_client_connect(%p, %lu)\n", cli, err);

	check_client_obj(cli);

	if (err) {
		client_handle_error(cli, err, RETRY_READ, 1000);
		client_put(cli);
		return err;
	}

	cli->read_pending = IOSTATE_IDLE;
	client_set_connected(cli, TRUE);

	update_server(cli->srv, FALSE, 0);
	update_client(cli, FALSE, RETRY_READ);

	client_put(cli);
	return ERROR_RETRY;
}

static DWORD server_start_write(struct server *srv)
{
	int res;
	DWORD err;
	DWORD nsent;
	struct socket_tx *item;

	trace("server_start_write(%p)\n", srv);

retry:
	check_server_obj(srv);

	if (srv->state == SERVER_TERMINATING)
		return ERROR_SUCCESS;

	if (list_empty(&srv->socket_tx_queue))
		return ERROR_MORE_DATA;

	item = CONTAINING_RECORD(list_first(&srv->socket_tx_queue), struct socket_tx, list);
	if (item->state != IOSTATE_IDLE)
		return ERROR_MORE_DATA;

	item->state = IOSTATE_PENDING;
	server_get(srv);
	err = 0;
	nsent = 0;
	memset(&srv->sock_write_ov, 0, sizeof(srv->sock_write_ov));
	res = WSASend(
		srv->socket,
		item->iovs + item->iovoff,
		item->iovcnt - item->iovoff,
		&nsent,
		0,
		&srv->sock_write_ov,
		NULL
	);

	if (res && (err = WSAGetLastError()) == WSA_IO_PENDING)
		return ERROR_IO_PENDING;

	if (res || !IOCP_USED) {
		err = on_server_write(srv, err, nsent);
		if (err == ERROR_RETRY)
			goto retry;
	}

	return err;
}

static DWORD on_server_write(struct server *srv, DWORD err, DWORD nsent)
{
	struct socket_tx *item;
	struct client *cli;

	trace("on_server_write(%p, %lu, %lu)\n", srv, err, nsent);

	check_server_obj(srv);

	if (srv->state == SERVER_TERMINATING)
		err = WSAESHUTDOWN;

	if (list_empty(&srv->socket_tx_queue)) {
		server_put(srv);
		return ERROR_MORE_DATA;
	}

	item = CONTAINING_RECORD(list_first(&srv->socket_tx_queue), struct socket_tx, list);
	assert(item->state != IOSTATE_IDLE);

	item->state = IOSTATE_IDLE;

	if (err) {
		if (err != ERROR_RETRY)
			server_error(srv, err);
		else
			update_server(srv, FALSE, RETRY_WRITE);
		server_put(srv);
		return err;
	}

	item->iovoff = iovec_advance(
		item->iovs + item->iovoff,
		item->iovcnt - item->iovoff,
		nsent
	);

	cli = item->cli_ref;
	if (cli) {
		dumpring(&cli->readbuf, "on_server_write cons before");
		ring_cons_advance(&cli->readbuf, nsent);
		dumpring(&cli->readbuf, "on_server_write cons after");
		update_client(cli, FALSE, 0);
	}

	if (item->iovoff < item->iovcnt) {
		err = ERROR_RETRY;
	} else {
		remove_socket_tx(item);
	}

	update_server(srv, FALSE, RETRY_WRITE);

	server_put(srv);
	return err;
}

static DWORD server_start_read(struct server *srv)
{
	int res;
	DWORD err;
	DWORD nrecv;
	DWORD flags;
	size_t n, niovs;

	trace("server_start_read(%p)\n", srv);

retry:
	check_server_obj(srv);

	if (srv->state == SERVER_TERMINATING)
		return ERROR_SUCCESS;

	if (srv->read_pending != IOSTATE_IDLE)
		return ERROR_MORE_DATA;

	if (is_pipe_datagram(srv) && !list_empty(&srv->socket2pipe.list))
		return ERROR_MORE_DATA;

	n = ring_prod_avail(&srv->readbuf);
	if (srv->required_room > n)
		return ERROR_MORE_DATA;

	server_get(srv);
	memset(&srv->iovs, 0, sizeof(srv->iovs));
	niovs = ring_prod_peek_iovecs(&srv->readbuf, srv->iovs);
	err = 0;
	nrecv = 0;
	flags = 0;
	srv->read_pending = IOSTATE_PENDING;
	memset(&srv->sock_read_ov, 0, sizeof(srv->sock_read_ov));
	res = WSARecv(
		srv->socket,
		srv->iovs,
		niovs,
		&nrecv,
		&flags,
		&srv->sock_read_ov,
		NULL
	);

	if (res && (err = WSAGetLastError()) == WSA_IO_PENDING)
		return ERROR_IO_PENDING;

	if (res || !IOCP_USED) {
		err = on_server_read(srv, err, nrecv);
		if (err == ERROR_RETRY)
			goto retry;
	}

	return err;
}

static void start_socket_to_pipe(struct server *srv, struct client *cli)
{
	struct pipe_tx *tx = &srv->socket2pipe;

	trace("start_socket_to_pipe(%p, %p)\n", srv, cli);

	check_server_obj(srv);
	check_client_obj(cli);

	if (srv->state == SERVER_TERMINATING)
		return;

	if (list_empty(&tx->list)) {
		assert(tx->state == IOSTATE_IDLE);

		tx->buffer = (unsigned char *)ring_cons_base(&srv->readbuf);
		tx->length = ring_cons_avail_linear(&srv->readbuf);
		set_server_ref(&tx->srv_ref, srv);

		client_append_tx(cli, tx);
	} else if (tx->state == IOSTATE_IDLE &&
		   tx->srv_ref == srv &&
		   tx->buffer == (unsigned char *)ring_cons_base(&srv->readbuf) &&
		   !is_pipe_datagram(srv)) {
		tx->length = ring_cons_avail_linear(&srv->readbuf);
	}
}

static DWORD update_server(struct server *srv, BOOL incoming, unsigned char suppress_io)
{
	struct client *cli;

	(void)suppress_io;

	trace("update_server(%p, %d, %d)\n", srv, incoming, suppress_io);

	check_server_obj(srv);

	if (!list_empty(&srv->clients[CLIENT_CONNECTED]) &&
	    (incoming || ring_cons_avail(&srv->readbuf))) {
		cli = CONTAINING_RECORD(list_last(&srv->clients[CLIENT_CONNECTED]), struct client, list);
		start_socket_to_pipe(srv, cli);
	}

	if (!(suppress_io & RETRY_READ))
		server_start_read(srv);
	if (!(suppress_io & RETRY_WRITE))
		server_start_write(srv);

	return 0;
}

static void start_pipe_to_socket(struct client *cli)
{
	struct socket_tx *tx = &cli->pipe2socket;
	struct server *srv = cli->srv;

	trace("start_pipe_to_socket(%p)\n", cli);

	check_server_obj(srv);
	check_client_obj(cli);

	if (srv->state == SERVER_TERMINATING)
		return;

	if (list_empty(&tx->list)) {
		assert(tx->state == IOSTATE_IDLE);

		memset(&tx->iovs, 0, sizeof(tx->iovs));
		tx->iovoff = 0;
		tx->iovcnt = ring_cons_peek_iovecs(&cli->readbuf, tx->iovs);
		set_client_ref(&tx->cli_ref, cli);

		server_append_tx(srv, tx);
	} else if (tx->state == IOSTATE_IDLE &&
		   tx->cli_ref == cli &&
		   tx->iovoff == 0 &&
		   tx->iovs[0].buf == (char *)ring_cons_base(&cli->readbuf) &&
		   !cli->srv->is_datagram) {
		tx->iovcnt = ring_cons_peek_iovecs(&cli->readbuf, tx->iovs);
	}
}

static DWORD update_client(struct client *cli, BOOL incoming, unsigned char suppress_io)
{
	DWORD err = 0;

	trace("update_client(%p, %d, %d)\n", cli, incoming, suppress_io);

	check_client_obj(cli);

	if (incoming /* accept empty datagrams */ || ring_cons_avail(&cli->readbuf))
		start_pipe_to_socket(cli);

	if (list_empty(&cli->list))
		return err;

	if (cli->is_connected) {
		if (!((cli->retry_flags | suppress_io) & RETRY_READ))
			client_start_read(cli);
		if (!((cli->retry_flags | suppress_io) & RETRY_WRITE))
			client_start_write(cli);
	} else if (client_is_reusable(cli) && server_is_accepting_clients(cli->srv, 0)) {
		if (!((cli->retry_flags | suppress_io) & RETRY_READ))
			err = client_start_connect(cli);
	}

	if (client_is_reusable(cli)) {
		list_remove(&cli->list_retry_io);
		client_remove_from_list(cli);
		client_put(cli);
	}

	return err;
}

static DWORD on_server_read(struct server *srv, DWORD err, DWORD nread)
{
	trace("on_server_read(%p, %lu, %lu)\n", srv, err, nread);

	check_server_obj(srv);

	if (srv->state == SERVER_TERMINATING)
		err = WSAESHUTDOWN;

	if (!err && !nread && !srv->is_datagram)
		err = WSAEDISCON;

	srv->required_room = 1;
	srv->read_pending = IOSTATE_IDLE;

	if (err) {
		if (err == WSAEMSGSIZE)
			err = ERROR_RETRY;
		if (is_wsa_error_nonrecoverable(err))
			server_error(srv, err);
		else
			update_server(srv, TRUE, RETRY_READ);
		server_put(srv);
		return err;
	}

	dumpring(&srv->readbuf, "on_server_read prod before");
	ring_prod_advance(&srv->readbuf, nread);
	dumpring(&srv->readbuf, "on_server_read prod after");
	update_server(srv, TRUE, RETRY_READ);

	server_put(srv);
	return ERROR_RETRY;
}

static DWORD client_start_read(struct client *cli)
{
	BOOL res;
	DWORD err;
	DWORD nread;
	size_t n;

	trace("client_start_read(%p)\n", cli);

retry:
	check_client_obj(cli);

	client_cancel_retry(cli, RETRY_READ);

	if (list_empty(&cli->list))
		return ERROR_SUCCESS;

	if (cli->read_pending != IOSTATE_IDLE || !cli->is_connected)
		return ERROR_MORE_DATA;

	if (cli->srv->is_datagram && !list_empty(&cli->pipe2socket.list))
		return ERROR_MORE_DATA;

	n = ring_prod_avail_linear(&cli->readbuf);
	if (cli->required_room > n)
		return ERROR_MORE_DATA;

	client_get(cli);
	cli->read_pending = IOSTATE_PENDING;
	err = 0;
	nread = 0;
	memset(&cli->pipe_read_ov, 0, sizeof(cli->pipe_read_ov));
	res = ReadFile(
		cli->pipe,
		ring_prod_base(&cli->readbuf),
		n,
		&nread,
		&cli->pipe_read_ov
	);

	if (!res && (err = GetLastError()) == ERROR_IO_PENDING)
		return ERROR_IO_PENDING;

	if (!res || !IOCP_USED) {
		err = on_client_read(cli, err, nread);
		if (err == ERROR_RETRY)
			goto retry;
	}

	return err;
}

static DWORD on_client_read(struct client *cli, DWORD err, DWORD nread)
{
	check_client_obj(cli);

	cli->required_room = 1;
	cli->read_pending = IOSTATE_IDLE;

	trace("on_client_read(%p, %lu, %lu)\n", cli, err, nread);

	check_client_obj(cli);

	if (err) {
		if (err == ERROR_MORE_DATA) {
			dumpring(&cli->readbuf, "on_client_read MOREDATA cons before");
			ring_prod_advance(&cli->readbuf, nread);
			dumpring(&cli->readbuf, "on_client_read MOREDATA cons after");
			err = ERROR_RETRY;
		}
		client_handle_error(cli, err, RETRY_READ, 1000);
		client_put(cli);
		return err;
	}

	dumpring(&cli->readbuf, "on_client_read cons before");
	ring_prod_advance(&cli->readbuf, nread);
	dumpring(&cli->readbuf, "on_client_read cons after");
	update_client(cli, TRUE, RETRY_READ);

	client_put(cli);
	return ERROR_RETRY;
}

static DWORD client_start_write(struct client *cli)
{
	BOOL res;
	DWORD err;
	DWORD nwritten;
	struct pipe_tx *item;

	trace("client_start_write(%p)\n", cli);

retry:
	check_client_obj(cli);

	client_cancel_retry(cli, RETRY_WRITE);

	if (list_empty(&cli->list))
		return ERROR_SUCCESS;

	if (list_empty(&cli->pipe_tx_queue))
		return ERROR_MORE_DATA;
	item = CONTAINING_RECORD(list_first(&cli->pipe_tx_queue), struct pipe_tx, list);

	if (item->state != IOSTATE_IDLE)
		return ERROR_MORE_DATA;

	item->state = IOSTATE_PENDING;
	client_get(cli);
	err = 0;
	nwritten = 0;
	memset(&cli->pipe_write_ov, 0, sizeof(cli->pipe_write_ov));
	res = WriteFile(
		cli->pipe,
		item->buffer,
		item->length,
		&nwritten,
		&cli->pipe_write_ov
	);

	if (!res && (err = GetLastError()) == ERROR_IO_PENDING)
		return ERROR_IO_PENDING;

	if (!res || !IOCP_USED) {
		err = on_client_write(cli, err, nwritten);
		if (err == ERROR_RETRY)
			goto retry;
	}

	return err;
}

static DWORD on_client_write(struct client *cli, DWORD err, DWORD nwritten)
{
	struct server *srv;
	struct pipe_tx *item;

	trace("on_client_write(%p, %lu, %lu)\n", cli, err, nwritten);

	check_client_obj(cli);

	if (list_empty(&cli->pipe_tx_queue)) {
		update_client(cli, FALSE, RETRY_WRITE);
		client_put(cli);
		return ERROR_MORE_DATA;
	}

	item = CONTAINING_RECORD(list_first(&cli->pipe_tx_queue), struct pipe_tx, list);
	assert(item->state != IOSTATE_IDLE);

	item->state = IOSTATE_IDLE;

	if (err) {
		client_handle_error(cli, err, RETRY_WRITE, 1000);
		client_put(cli);
		return err;
	}

	item->buffer += nwritten;
	item->length -= nwritten;

	srv = cli->srv;
	dumpring(&cli->readbuf, "on_client_write cons before");
	ring_cons_advance(&srv->readbuf, nwritten);
	dumpring(&cli->readbuf, "on_client_write cons after");

#if 0 /* already done in loop*/
	server_start_read(srv);
#endif

	if (item->length > 0) {
		err = ERROR_RETRY;
	} else {
		remove_pipe_tx(item);
	}
	update_client(cli, FALSE, RETRY_WRITE);

	client_put(cli);
	return err;
}

static DWORD client_io_complete(struct client *cli, LPOVERLAPPED overlapped, DWORD err, DWORD numbytes)
{
	DWORD res = 0;

	trace("client_io_complete(%p, %p, %lu, %lu)\n", cli, overlapped, err, numbytes);

	check_client_obj(cli);

	if (overlapped == &cli->pipe_connect_ov) {
		res = on_client_connect(cli, err);
		if (res == ERROR_RETRY)
			res = client_start_connect(cli);
	} else if (overlapped == &cli->pipe_read_ov) {
		res = on_client_read(cli, err, numbytes);
		if (res == ERROR_RETRY)
			res = client_start_read(cli);
	} else if (overlapped == &cli->pipe_write_ov) {
		res = on_client_write(cli, err, numbytes);
		if (res == ERROR_RETRY)
			res = client_start_write(cli);
	}

	trace("client_io_complete(%p, %p, %lu, %lu) = %lu\n", cli, overlapped, err, numbytes, res);

	return res;
}

static DWORD server_io_complete(struct server *srv, LPOVERLAPPED overlapped, DWORD err, DWORD numbytes)
{
	DWORD res = 0;

	trace("server_io_complete(%p, %p, %lu, %lu)\n", srv, overlapped, err, numbytes);

	check_server_obj(srv);

	if (overlapped == (LPOVERLAPPED)&srv->sock_read_ov) {
		res = on_server_read(srv, err, numbytes);
		if (res == ERROR_RETRY)
			res = server_start_read(srv);
	} else if (overlapped == (LPOVERLAPPED)&srv->sock_write_ov) {
		res = on_server_write(srv, err, numbytes);
		if (res == ERROR_RETRY)
			res = server_start_write(srv);
	}

	trace("server_io_complete(%p, %p, %lu, %lu) = %lu\n", srv, overlapped, err, numbytes, res);

	return res;
}

static DWORD server_tick_internal(struct server *srv, DWORD cur_time)
{
	DECLARE_LISTHEAD(remove_list);
	struct listhead *item, *next;
	DWORD base_time = srv->last_tick_time;
	DWORD next_tick, curr_tick;

	curr_tick = cur_time - base_time;
	next_tick = curr_tick;

	foreach_list_safe(&srv->retry_io_clients, item, next) {
		struct client *cli = CONTAINING_RECORD(item, struct client, list_retry_io);
		DWORD req_tick = cli->next_io_retry_at - base_time;

		if (req_tick <= curr_tick) {
			list_remove(item);
			list_append(&remove_list, item);
		} else if (req_tick <= next_tick) {
			next_tick = req_tick;
		}
	}
	foreach_list_safe(&remove_list, item, next) {
		struct client *cli = CONTAINING_RECORD(item, struct client, list_retry_io);
		unsigned char retry_flags;

		retry_flags = cli->retry_flags;
		cli->retry_flags = 0;
		list_remove(item);

		if (retry_flags & RETRY_READ) {
			if (cli->is_connected)
				client_start_read(cli);
			else
				client_start_connect(cli);
		}
		if (retry_flags & RETRY_WRITE)
			client_start_write(cli);
	}
	assert(list_empty(&remove_list));

	return next_tick;
}

static DWORD server_get_wait_time(struct server *srv, DWORD next_tick, DWORD cur_time, DWORD drift)
{
	DWORD next_time, wait_ticks;

	next_time = srv->last_tick_time + next_tick;
	srv->last_tick_time = cur_time + drift;

	if (next_time == cur_time)
		return INFINITE;

	wait_ticks = next_time - cur_time;
	return wait_ticks > drift ? wait_ticks - drift : 0;
}

static DWORD server_tick(struct server *srv)
{
	DWORD cur_time, next_tick;

	cur_time = GetTickCount();
	next_tick = server_tick_internal(srv, cur_time);
	return server_get_wait_time(srv, next_tick, cur_time, GetTickCount() - cur_time);
}

static int init_wsa(WORD version_required)
{
	WSADATA wsadata;
	int err;

	err = WSAStartup(version_required, &wsadata);
	if (err != 0)
		return err;

	if (wsadata.wVersion == version_required)
		return 0;

	WSACleanup();
	return WSAVERNOTSUPPORTED;
}

static SOCKET create_conn(wchar_t const *hostname, wchar_t const *servname)
{
	int res;
	DWORD err = 0;
	SOCKET sock;
	ADDRINFOW aihint, *aires, *ptr;

	memset(&aihint, 0, sizeof(aihint));
	aihint.ai_flags = 0;
	aihint.ai_family = AF_UNSPEC;
	aihint.ai_socktype = SOCK_STREAM;
	aihint.ai_protocol = IPPROTO_TCP;

	res = GetAddrInfoW(hostname, servname, &aihint, &aires);
	if (res) {
		fprintf(stderr, "GetAddrInfoW failed: %d\n", res);
		return INVALID_SOCKET;
	}

	sock = INVALID_SOCKET;
	for (ptr = aires; ptr; ptr = ptr->ai_next) {
		sock = WSASocket(
			ptr->ai_family,
			ptr->ai_socktype,
			ptr->ai_protocol,
			0,
			0,
			WSA_FLAG_OVERLAPPED
		);
		if (sock == INVALID_SOCKET) {
			err = WSAGetLastError();
			fprintf(stderr, "WSASocket() failed: %d\n", WSAGetLastError());
			continue;
		}

		res = connect(sock, ptr->ai_addr, ptr->ai_addrlen);
		if (res) {
			err = WSAGetLastError();
			fprintf(stderr, "connect() failed: %d\n", res);
			closesocket(sock);
			sock = INVALID_SOCKET;
			continue;
		}

		break;
	}

	FreeAddrInfoW(aires);
	WSASetLastError(err);

	return sock;
}

static void load_dll_procs(void)
{
	HMODULE kernel32;

	kernel32 = GetModuleHandleW(L"KERNEL32.DLL");
	if (kernel32) {
		lpCancelIoEx = (LPCANCELIOEX)(LPVOID)GetProcAddress(kernel32, "CancelIoEx");
	}
}

static DWORD server_loop(struct server *srv)
{
	DWORD dwerr, numbytes, waitmsecs;
	ULONG_PTR key;
	LPOVERLAPPED ovl;
	BOOL success;

	while (srv->refcount) {
		check_server_obj(srv);
		server_get(srv);

		dwerr = server_start_read(srv);
		if (is_failure(dwerr)) {
			fprintf(stderr, "socket read failed: %lu\n", dwerr);
		}

		dwerr = server_listen(srv);
		if (is_failure(dwerr)) {
			fprintf(stderr, "listen failed: %lu\n", dwerr);
		}

		waitmsecs = server_tick(srv);

		server_put(srv);
		if (!srv->refcount)
			break;

		trace("\n==== LOOP #refs=%lu #disconnected-clients=%lu #connected_clients=%lu ===\n", srv->refcount, srv->num_clients[CLIENT_DISCONNECTED], srv->num_clients[CLIENT_CONNECTED]);

		numbytes = 0;
		key = 0;
		ovl = NULL;
		success = GetQueuedCompletionStatus(srv->iocp, &numbytes, &key, &ovl, waitmsecs);
		dwerr = success ? 0 : GetLastError();
		if (!success && !ovl && dwerr != WAIT_TIMEOUT) {
			fprintf(stderr, "GetQueuedCompletionStatus failed: %lu\n", dwerr);
			server_error(srv, dwerr);
			continue;
		}

		if (ovl) {
			trace(">> OVL=%p KEY=%p ERR=%lu NUM=%lu\n", ovl, (void *)key, dwerr, numbytes);
			if (!key) {
				server_get(srv);
				dwerr = server_io_complete(srv, ovl, dwerr, numbytes);
				server_put(srv);
			} else if (((struct client *)key)->magic == CLIENT_OBJ_MAGIC) {
				struct client *cli = (struct client *)key;
				dwerr = client_io_complete(cli, ovl, dwerr, numbytes);
			}
		}
	}

	return srv->error;
}

int wmain(int argc, wchar_t **argv)
{
	struct server srv;
	int err, code;
	DWORD dwerr;
	SOCKET sock;
	struct pipeserver_params ps_params;
#if 0
	SECURITY_ATTRIBUTES sec_attrib;
	PSECURITY_DESCRIPTOR sd = NULL;
	ULONG sd_size = 0;
#endif

	if (argc != 4) {
		code = HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
		goto fail;
	}

	load_dll_procs();

#if 0
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
		L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;CO)",
		SDDL_REVISION_1,
		&sd,
		&sd_size
	)) {
		code = HRESULT_FROM_WIN32(GetLastError());
		goto fail;
	}

	memset(&sec_attrib, 0, sizeof(sec_attrib));
	sec_attrib.nLength = sizeof(SECURITY_ATTRIBUTES);
	sec_attrib.lpSecurityDescriptor = sd;
	sec_attrib.bInheritHandle = FALSE;
#endif

	memset(&ps_params, 0, sizeof(ps_params));
	ps_params.name = argv[1];
	ps_params.open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED;
	ps_params.pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS;
	ps_params.max_instances = 1;
	ps_params.out_buffer_size = RING_BUFFER_SIZE;
	ps_params.in_buffer_size = RING_BUFFER_SIZE;
	ps_params.default_timeout = 0;
#if 0
	ps_params.security_attributes = &sec_attrib;
#endif

	err = init_wsa(MAKEWORD(2, 2));
	if (err) {
		fprintf(stderr, "winsock init failed: %d\n", err);
		code = HRESULT_FROM_WIN32(err);
		goto free_sd;
	}

	sock = create_conn(argv[2], argv[3]);
	if (sock == INVALID_SOCKET) {
		dwerr = WSAGetLastError();
		fprintf(stderr, "connection failed: %lu\n", dwerr);
		code = HRESULT_FROM_WIN32(dwerr);
		goto wsacleanup;
	}

	if (!server_init(&srv, &ps_params, 1, 1, sock, 0)) {
		dwerr = GetLastError();
		fprintf(stderr, "server init failed: %lu\n", dwerr);
		code = HRESULT_FROM_WIN32(dwerr);
		goto closeconn;
	}
	srv.state = SERVER_LISTENING;

	code = HRESULT_FROM_WIN32(server_loop(&srv));

closeconn:
	closesocket(sock);
wsacleanup:
	WSACleanup();
free_sd:
#if 0
	LocalFree(sd);
#endif
fail:
	return code;
}
