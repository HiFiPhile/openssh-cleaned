#include <Windows.h>
#include <stdio.h>
#include "Debug.h"
#include "misc_internal.h"

#define MAX_MESSAGE_SIZE 256 * 1024

#define SSH_AGENT_ROOT SSH_REGISTRY_ROOT L"\\Agent"
#define SSH_KEYS_KEY L"Keys"
#define SSH_KEYS_ROOT SSH_AGENT_ROOT L"\\" SSH_KEYS_KEY
#define SSH_PKCS11_PROVIDERS_KEY L"PKCS11_Providers"
#define SSH_PKCS11_PROVIDERS_ROOT SSH_AGENT_ROOT L"\\" SSH_PKCS11_PROVIDERS_KEY
/* Maximum number of recorded session IDs/hostkeys per connection */
#define AGENT_MAX_SESSION_IDS		16
/* Maximum size of session ID */
#define AGENT_MAX_SID_LEN		128
/* Maximum number of destination constraints to accept on a key */
#define AGENT_MAX_DEST_CONSTRAINTS	1024

#define HEADER_SIZE 4

struct hostkey_sid {
	struct sshkey *key;
	struct sshbuf *sid;
	int forwarded;
};

typedef struct
{
	OVERLAPPED oOverlap;
	HANDLE hPipeInst;
	char chBuf[MAX_MESSAGE_SIZE];
	DWORD chSize;

	size_t nsession_ids;
	struct hostkey_sid* session_ids;
} PIPEINST, * LPPIPEINST;

extern HANDLE ghSvcStopEvent;

void agent_start(BOOL dbg_mode);

static VOID ConnectionLoop(VOID);
VOID DisconnectAndClose(LPPIPEINST);
BOOL CreateAndConnectInstance(LPOVERLAPPED);
BOOL ConnectToNewClient(HANDLE, LPOVERLAPPED);
VOID GetAnswerToRequest(LPPIPEINST);

VOID WINAPI CompletedWriteRoutine(DWORD, DWORD, LPOVERLAPPED);
VOID WINAPI CompletedReadRoutine(DWORD, DWORD, LPOVERLAPPED);
