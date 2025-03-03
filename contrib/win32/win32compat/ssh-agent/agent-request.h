typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
typedef unsigned __int64 u_int64_t;
#define __attribute__(a)
#include <stdint.h>
#include "sshkey.h"
#include "sshbuf.h"
#include <openssl/bn.h>
#include "authfd.h"
#include "digest.h"


/* key management */
int process_unsupported_request(struct sshbuf*, struct sshbuf*, LPPIPEINST);
int process_add_identity(struct sshbuf*, struct sshbuf*, LPPIPEINST);
int process_request_identities(struct sshbuf*, struct sshbuf*, LPPIPEINST);
int process_sign_request(struct sshbuf*, struct sshbuf*, LPPIPEINST);
int process_remove_key(struct sshbuf*, struct sshbuf*, LPPIPEINST);
int process_remove_all(struct sshbuf*, struct sshbuf*, LPPIPEINST);
int process_add_smartcard_key(struct sshbuf*, struct sshbuf*, LPPIPEINST);
int process_remove_smartcard_key(struct sshbuf*, struct sshbuf*, LPPIPEINST);
int process_extension(struct sshbuf*, struct sshbuf*, LPPIPEINST);

/* auth */
