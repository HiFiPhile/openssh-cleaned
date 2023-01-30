/*
 * Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
 * ssh-agent implementation on Windows
 * 
 * Copyright (c) 2015 Microsoft Corp.
 * All rights reserved
 *
 * Microsoft openssh win32 port
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "agent.h"
#include "agent-request.h"
#include "config.h"
#include <sddl.h>
#include <UserEnv.h>
#include "..\misc_internal.h"
#include <pwd.h>

#define BUFSIZE 5 * 1024

#define AGENT_PIPE_ID L"\\\\.\\pipe\\openssh-ssh-agent"

HANDLE ghSvcStopEvent = NULL;

static SECURITY_ATTRIBUTES sa;

static HANDLE hPipe;

extern void
idtab_init(void);

static void
ConnectionLoop()
{
	HANDLE hConnectEvent;
	OVERLAPPED oConnect;
	LPPIPEINST lpPipeInst;
	DWORD dwWait, cbRet;
	BOOL fSuccess, fPendingIO;
	HANDLE waitEvents[2];

	wchar_t* sddl_str;
	memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength = sizeof(sa);
	/*
	 * SDDL - GA to System and Builtin/Admins and restricted access to Authenticated users
	 * 0x12019b - FILE_GENERIC_READ/WRITE minus FILE_CREATE_PIPE_INSTANCE
	 */
	sddl_str = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;AU)";
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl_str, SDDL_REVISION_1,
		&sa.lpSecurityDescriptor, &sa.nLength))
		fatal("cannot convert sddl ERROR:%d", GetLastError());

	sa.bInheritHandle = FALSE;

	// Create one event object for the connect operation. 
	hConnectEvent = CreateEvent(
		NULL,    // default security attribute
		TRUE,    // manual reset event 
		TRUE,    // initial state = signaled 
		NULL);   // unnamed event object 

	if (hConnectEvent == NULL)
	{
		fatal("CreateEvent failed with %d.\n", GetLastError());
	}

	oConnect.hEvent = hConnectEvent;

	// Call a subroutine to create one instance, and wait for 
	// the client to connect. 
	fPendingIO = CreateAndConnectInstance(&oConnect);

	waitEvents[0] = hConnectEvent;
	waitEvents[1] = ghSvcStopEvent;

	while (1)
	{
		// Wait for a client to connect, or for a read or write 
		// operation to be completed, which causes a completion 
		// routine to be queued for execution. 

		dwWait = WaitForMultipleObjectsEx(
			2,
			waitEvents,		// event object to wait for 
			FALSE,			// wait for one
			INFINITE,       // waits indefinitely 
			TRUE);          // alertable wait enabled 

		switch (dwWait)
		{
			// The wait conditions are satisfied by a completed connect 
			// operation. 
		case WAIT_OBJECT_0:
			// If an operation is pending, get the result of the 
			// connect operation. 

			if (fPendingIO)
			{
				fSuccess = GetOverlappedResult(
					hPipe,     // pipe handle 
					&oConnect, // OVERLAPPED structure 
					&cbRet,    // bytes transferred 
					FALSE);    // does not wait 
				if (!fSuccess)
				{
					fatal("ConnectNamedPipe (%d)", GetLastError());
				}
			}

			// Allocate storage for this instance. 

			lpPipeInst = (LPPIPEINST)HeapAlloc(GetProcessHeap(),
				HEAP_ZERO_MEMORY, sizeof(PIPEINST));
			if (lpPipeInst == NULL)
			{
				fatal("GlobalAlloc failed (%d)", GetLastError());
			}

			lpPipeInst->hPipeInst = hPipe;

			// Start the read operation for this client. 
			// Note that this same routine is later used as a 
			// completion routine after a write operation. 

			CompletedWriteRoutine(0, 0, (LPOVERLAPPED)lpPipeInst);

			// Create new pipe instance for the next client. 

			fPendingIO = CreateAndConnectInstance(
				&oConnect);
			break;

			// The wait is satisfied by a completed read or write 
			// operation. This allows the system to execute the 
			// completion routine. 

		case WAIT_OBJECT_0 + 1:
			debug("shutting down");
			return;

		case WAIT_IO_COMPLETION:
			break;

			// An error occurred in the wait function. 

		default:
		{
			fatal("WaitForSingleObjectEx (%d)", GetLastError());
		}
		}
	}
}

// CompletedWriteRoutine(DWORD, DWORD, LPOVERLAPPED) 
// This routine is called as a completion routine after writing to 
// the pipe, or when a new client has connected to a pipe instance.
// It starts another read operation. 
VOID WINAPI CompletedWriteRoutine(DWORD dwErr, DWORD cbWritten,
	LPOVERLAPPED lpOverLap)
{
	LPPIPEINST lpPipeInst = (LPPIPEINST)lpOverLap;
	BOOL fRead = FALSE;

	debug3("connection io write %p #bytes:%d", lpPipeInst, cbWritten);

	// The write operation has finished, so read the next request (if 
	// there is no error). 
	SecureZeroMemory(lpPipeInst->chBuf, sizeof(lpPipeInst->chSize));

	if ((dwErr == 0) && (cbWritten == lpPipeInst->chSize))
		lpPipeInst->chSize = 0;
		fRead = ReadFileEx(
			lpPipeInst->hPipeInst,
			lpPipeInst->chBuf,
			MAX_MESSAGE_SIZE,
			(LPOVERLAPPED)lpPipeInst,
			(LPOVERLAPPED_COMPLETION_ROUTINE)CompletedReadRoutine);

	// Disconnect if an error occurred. 
	if (!fRead)
		DisconnectAndClose(lpPipeInst);
}

// CompletedReadRoutine(DWORD, DWORD, LPOVERLAPPED) 
// This routine is called as an I/O completion routine after reading 
// a request from the client. It gets data and writes it to the pipe. 
VOID WINAPI 
CompletedReadRoutine(DWORD dwErr, DWORD cbBytesRead, LPOVERLAPPED lpOverLap)
{
	LPPIPEINST lpPipeInst = (LPPIPEINST)lpOverLap;
	BOOL success = FALSE, readDone = FALSE;
	int num_bytes;

	debug3("connection io read %p #bytes:%d", lpPipeInst, cbBytesRead);

	if ((dwErr == 0) && (cbBytesRead != 0))
		lpPipeInst->chSize += cbBytesRead;

	if (lpPipeInst->chSize > HEADER_SIZE)
	{
		num_bytes = PEEK_U32(lpPipeInst->chBuf);
		if (num_bytes == lpPipeInst->chSize - HEADER_SIZE)
			readDone = TRUE;
		else if (num_bytes < lpPipeInst->chSize - HEADER_SIZE)
			DisconnectAndClose(lpPipeInst);
	}

	if (readDone)
	{
		if (ProcessRequest(lpPipeInst) == 0)
			success = WriteFileEx(
				lpPipeInst->hPipeInst,
				lpPipeInst->chBuf,
				lpPipeInst->chSize,
				(LPOVERLAPPED)lpPipeInst,
				(LPOVERLAPPED_COMPLETION_ROUTINE)CompletedWriteRoutine);
	}
	else
	{
		success = ReadFileEx(
			lpPipeInst->hPipeInst,
			lpPipeInst->chBuf + lpPipeInst->chSize,
			MAX_MESSAGE_SIZE - lpPipeInst->chSize,
			(LPOVERLAPPED)lpPipeInst,
			(LPOVERLAPPED_COMPLETION_ROUTINE)CompletedReadRoutine);
	}

	// Disconnect if an error occurred. 
	if (!success)
		DisconnectAndClose(lpPipeInst);
}

// DisconnectAndClose(LPPIPEINST) 
// This routine is called when an error occurs or the client closes 
// its handle to the pipe. 

VOID DisconnectAndClose(LPPIPEINST lpPipeInst)
{
	// Disconnect the pipe instance. 
	if (!DisconnectNamedPipe(lpPipeInst->hPipeInst))
	{
		error("DisconnectNamedPipe failed with %d.", GetLastError());
	}

	// Close the handle to the pipe instance. 
	CloseHandle(lpPipeInst->hPipeInst);

	// Release the storage for the pipe instance. 
	debug("connection %p clean up", lpPipeInst);
	for (size_t i = 0; i < lpPipeInst->nsession_ids; i++) {
		sshkey_free(lpPipeInst->session_ids[i].key);
		sshbuf_free(lpPipeInst->session_ids[i].sid);
	}
	free(lpPipeInst->session_ids);
	lpPipeInst->nsession_ids = 0;

	SecureZeroMemory(lpPipeInst, sizeof(lpPipeInst));

	HeapFree(GetProcessHeap(), 0, lpPipeInst);
}

// CreateAndConnectInstance(LPOVERLAPPED) 
// This function creates a pipe instance and connects to the client. 
// It returns TRUE if the connect operation is pending, and FALSE if 
// the connection has been completed. 

BOOL CreateAndConnectInstance(LPOVERLAPPED lpoOverlap)
{
	hPipe = CreateNamedPipeW(
		AGENT_PIPE_ID,            // pipe name 
		PIPE_ACCESS_DUPLEX |      // read/write access 
		FILE_FLAG_OVERLAPPED,     // overlapped mode 
		PIPE_TYPE_BYTE |          // message-type pipe 
		PIPE_READMODE_BYTE |      // message read mode 
		PIPE_WAIT,                // blocking mode 
		PIPE_UNLIMITED_INSTANCES, // unlimited instances 
		BUFSIZE,				  // output buffer size 
		BUFSIZE,				  // input buffer size 
		0,						  // client time-out 
		&sa);                     // default security attributes
	if (hPipe == INVALID_HANDLE_VALUE)
	{
		fatal("CreateNamedPipe failed with %d.", GetLastError());
	}

	// Call a subroutine to connect to the new client. 
	return ConnectToNewClient(hPipe, lpoOverlap);
}

BOOL ConnectToNewClient(HANDLE hPipe, LPOVERLAPPED lpo)
{
	BOOL fConnected, fPendingIO = FALSE;

	// Start an overlapped connection for this pipe instance. 
	fConnected = ConnectNamedPipe(hPipe, lpo);

	// Overlapped ConnectNamedPipe should return zero. 
	if (fConnected)
	{
		error("ConnectNamedPipe failed with %d.", GetLastError());
		return 0;
	}

	switch (GetLastError())
	{
		// The overlapped connection in progress. 
	case ERROR_IO_PENDING:
		fPendingIO = TRUE;
		break;

		// Client is already connected, so signal an event. 

	case ERROR_PIPE_CONNECTED:
		if (SetEvent(lpo->hEvent))
			break;

		// If an error occurs during the connect operation... 
	default:
	{
		error("ConnectNamedPipe failed with %d.", GetLastError());
		return 0;
	}
	}
	return fPendingIO;
}

static int
ProcessRequest(LPPIPEINST con)
{
	int r = -1, num_bytes;
	struct sshbuf* request = NULL, * response = NULL;
	u_char type;
	errno_t err = 0;

	num_bytes = PEEK_U32(con->chBuf);
	if (num_bytes != con->chSize - HEADER_SIZE)
	{
		debug("Invalid request");
		return -1;
	}

	request = sshbuf_from(con->chBuf + HEADER_SIZE, con->chSize - HEADER_SIZE);
	response = sshbuf_new();
	if ((request == NULL) || (response == NULL))
		goto done;

	if (sshbuf_get_u8(request, &type) != 0)
		return -1;
	debug("process agent request type %d", type);

	switch (type) {
	case SSH_AGENTC_REQUEST_RSA_IDENTITIES:
	case SSH_AGENTC_RSA_CHALLENGE:
	case SSH_AGENTC_ADD_RSA_IDENTITY:
	case SSH_AGENTC_REMOVE_RSA_IDENTITY:
	case SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		r = process_unsupported_request(request, response, con);
		break;
	case SSH2_AGENTC_ADD_IDENTITY:
		r = process_add_identity(request, response, con);
		break;
	case SSH2_AGENTC_REQUEST_IDENTITIES:
		r = process_request_identities(request, response, con);
		break;
	case SSH2_AGENTC_SIGN_REQUEST:
		r = process_sign_request(request, response, con);
		break;
	case SSH2_AGENTC_REMOVE_IDENTITY:
		r = process_remove_key(request, response, con);
		break;
	case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		r = process_remove_all(request, response, con);
		break;
#ifdef ENABLE_PKCS11
	case SSH_AGENTC_ADD_SMARTCARD_KEY:
	case SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED:
		r = process_add_smartcard_key(request, response, con);
		break;
	case SSH_AGENTC_REMOVE_SMARTCARD_KEY:
		r = process_remove_smartcard_key(request, response, con);
		break;
#endif /* ENABLE_PKCS11 */
	case SSH_AGENTC_EXTENSION:
		r = process_extension(request, response, con);
		break;
	default:
		debug("unknown agent request %d", type);
		r = -1;
		break;
	}

done:
	if (request)
		sshbuf_free(request);

	SecureZeroMemory(&con->chBuf, sizeof(con->chBuf));
	if (r == 0) {
		POKE_U32(con->chBuf, (u_int32_t)sshbuf_len(response));
		if ((err = memcpy_s(con->chBuf + HEADER_SIZE, sizeof(con->chBuf) - HEADER_SIZE, sshbuf_ptr(response), sshbuf_len(response))) != 0) {
			debug("memcpy_s failed with error: %d.", err);
			r = -1;
		}
		con->chSize = (DWORD)sshbuf_len(response) + HEADER_SIZE;
	}

	if (response)
		sshbuf_free(response);

	return r;
}


void
agent_start(BOOL dbg_mode) 
{
	int r;
	HKEY agent_root = NULL;
	DWORD process_id = GetCurrentProcessId();
	wchar_t* sddl_str;

	verbose("%s pid:%d, dbg:%d", __FUNCTION__, process_id, dbg_mode);

	memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength = sizeof(sa);

	idtab_init();
#ifdef ENABLE_PKCS11
	pkcs11_init(0);
#endif /* ENABLE_PKCS11 */

	// SDDL - FullAcess to System and Builtin/Admins
	sddl_str = L"D:PAI(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)";
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl_str, SDDL_REVISION_1,
	    &sa.lpSecurityDescriptor, &sa.nLength))
		fatal("cannot convert sddl ERROR:%d", GetLastError());
	if ((ghSvcStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL)
		fatal("cannot create global stop event ERROR:%d", GetLastError());
	if ((r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, SSH_AGENT_ROOT, 0, 0, 0, KEY_WRITE, &sa, &agent_root, 0)) != ERROR_SUCCESS)
		fatal("cannot create agent root reg key, ERROR:%d", r);
	if ((r = RegSetValueExW(agent_root, L"ProcessID", 0, REG_DWORD, (BYTE*)&process_id, 4)) != ERROR_SUCCESS)
		fatal("cannot publish agent master process id ERROR:%d", r);
	hPipe = INVALID_HANDLE_VALUE;
	sa.bInheritHandle = FALSE;
	ConnectionLoop();
}
