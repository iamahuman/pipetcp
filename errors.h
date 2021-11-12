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

#ifndef PIPETCP_ERRORS_H
#define PIPETCP_ERRORS_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winbase.h>

static BOOL is_failure(DWORD err)
{
	switch (err) {
	case ERROR_SUCCESS:
	case ERROR_MORE_DATA:
	case ERROR_IO_PENDING:
		return FALSE;
	default:
		return TRUE;
	}
}

static BOOL is_error_nonrecoverable(DWORD err)
{
	switch (err) {
	case ERROR_BROKEN_PIPE:
	case ERROR_NO_DATA:
	case ERROR_INVALID_HANDLE:
	case ERROR_INVALID_PARAMETER:
	case ERROR_INVALID_STATE:
		return TRUE;
	case ERROR_RETRY:
	case ERROR_NOT_ENOUGH_MEMORY:
	case ERROR_NOT_ENOUGH_QUOTA:
	case ERROR_NO_SYSTEM_RESOURCES:
	default:
		return FALSE;
	}
}

static BOOL is_wsa_error_nonrecoverable(DWORD err)
{
	switch (err) {
	case WSAEBADF:
	case WSAENOTSOCK:
	case WSAECONNABORTED:
	case WSAECONNRESET:
	case WSAESHUTDOWN:
	case WSAENOTCONN:
	case WSAEISCONN:
	case WSAECONNREFUSED:
	case WSAEDISCON:
		return TRUE;
	default:
		return is_error_nonrecoverable(err);
	}
}

#endif
