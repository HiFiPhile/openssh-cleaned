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
#include "openbsd-compat/sys-queue.h"
#include "config.h"
#include <sddl.h>
#ifdef ENABLE_PKCS11
#include "ssh-pkcs11.h"
#endif
#include "xmalloc.h"

#pragma warning(push, 3)

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME_LENGTH 16383
#define MAX_VALUE_DATA_LENGTH 2048

typedef struct identity {
	TAILQ_ENTRY(identity) next;
	struct sshkey* key;
	char* comment;
	char* provider;
} Identity;

struct idtable {
	int nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
struct idtable* idtab;

/* 
 * get registry root where keys are stored 
 * user keys are stored in user's hive
 * while system keys (host keys) in HKLM
 */

extern struct sshkey *
lookup_key(const struct sshkey *k);

extern void
add_key(struct sshkey *k, char *name);

extern void
del_all_keys();

void
idtab_init(void)
{
	idtab = xcalloc(1, sizeof(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

/* return matching private key for given public key */
static Identity*
lookup_identity(struct sshkey* key)
{
	Identity* id;

	TAILQ_FOREACH(id, &idtab->idlist, next) {
		if (sshkey_equal(key, id->key))
			return (id);
	}
	return (NULL);
}

static void
free_identity(Identity* id)
{
	sshkey_free(id->key);
	free(id->provider);
	free(id->comment);
	free(id);
}

static int
get_user_root(struct agent_connection* con, HKEY *root)
{
	int r = 0;
	LONG ret;
	*root = HKEY_LOCAL_MACHINE;
	
	if (con->client_type <= ADMIN_USER) {
		if (ImpersonateLoggedOnUser(con->client_impersonation_token) == FALSE)
			return -1;
		*root = NULL;
		/* 
		 * TODO - check that user profile is loaded, 
		 * otherwise, this will return default profile 
		 */
		if ((ret = RegOpenCurrentUser(KEY_ALL_ACCESS, root)) != ERROR_SUCCESS) {
			debug("unable to open user's registry hive, ERROR - %d", ret);
			r = -1;
		}
			
		RevertToSelf();
	}
	return r;
}

static int
convert_blob(struct agent_connection* con, const char *blob, DWORD blen, char **eblob, DWORD *eblen, int encrypt) {
	int success = 0;
	DATA_BLOB in, out;
	errno_t r = 0;

	if (con->client_type <= ADMIN_USER)
		if (ImpersonateLoggedOnUser(con->client_impersonation_token) == FALSE)
			return -1;

	in.cbData = blen;
	in.pbData = (char*)blob;
	out.cbData = 0;
	out.pbData = NULL;

	if (encrypt) {
		if (!CryptProtectData(&in, NULL, NULL, 0, NULL, 0, &out)) {
			debug("cannot encrypt data");
			goto done;
		}
	} else {
		if (!CryptUnprotectData(&in, NULL, NULL, 0, NULL, 0, &out)) {
			debug("cannot decrypt data");
			goto done;
		}
	}

	*eblob = malloc(out.cbData);
	if (*eblob == NULL) 
		goto done;

	if((r = memcpy_s(*eblob, out.cbData, out.pbData, out.cbData)) != 0) {
		debug("memcpy_s failed with error: %d.", r);
		goto done;
	}
	*eblen = out.cbData;
	success = 1;
done:
	if (out.pbData)
		LocalFree(out.pbData);
	if (con->client_type <= ADMIN_USER)
		RevertToSelf();
	return success? 0: -1;
}

#define REG_KEY_SDDL L"D:P(A;; GA;;; SY)(A;; GA;;; BA)"

int
process_unsupported_request(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con)
{
	int r = 0;
	debug("ssh protocol 1 is not supported");
	if (sshbuf_put_u8(response, SSH_AGENT_FAILURE) != 0)
		r = -1;
	return r;
}

int
process_add_identity(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	Identity* id;
	struct sshkey* key = NULL;
	int r = 0, request_invalid = 0, success = 0;
	char *fp = NULL, *comment;

	/* parse input request */
	if ((r = sshkey_private_deserialize(request, &key)) != 0 ||
		key == NULL ||
		(r = sshbuf_get_cstring(request, &comment, NULL)) != 0) {
		error("key add request is invalid");
		request_invalid = 1;
		goto done;
	}

	if ((r = sshkey_shield_private(key)) != 0) {
		error("shield private");
		goto done;
	}

	if ((id = lookup_identity(key)) == NULL) {
		id = xcalloc(1, sizeof(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
		/* Increment the number of identities. */
		idtab->nentries++;
		/* success */
		id->key = key;
		id->comment = comment;
		id->provider = NULL;
	}

	if ((fp = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
		SSH_FP_DEFAULT)) == NULL)
		fatal_f("sshkey_fingerprint failed");

	free(fp);

	key = NULL;
	comment = NULL;

	debug("added key to store");
	success = 1;
done:
	r = 0;
	if (request_invalid)
		r = -1;
	else if (sshbuf_put_u8(response, success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE) != 0)
		r = -1;
	if (comment)
		free(comment);
	if (key)
		sshkey_free(key);
	return r;
}

static int sign_blob(const struct sshkey *pubkey, u_char ** sig, size_t *siglen,
	const u_char *blob, size_t blen, u_int flags, struct agent_connection* con) 
{
	HKEY reg = 0, sub = 0, user_root = 0;
	int r = 0, success = 0;
	struct sshkey* prikey = NULL;
	char *thumbprint = NULL, *regdata = NULL, *algo = NULL;
	DWORD regdatalen = 0, keyblob_len = 0;
	struct sshbuf* tmpbuf = NULL;
	char *keyblob = NULL;
	const char *sk_provider = NULL;
#ifdef ENABLE_PKCS11
	int is_pkcs11_key = 0;
#endif /* ENABLE_PKCS11 */

	*sig = NULL;
	*siglen = 0;

#ifdef ENABLE_PKCS11
	if ((prikey = lookup_key(pubkey)) == NULL) {
#endif /* ENABLE_PKCS11 */
		if ((thumbprint = sshkey_fingerprint(pubkey, SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL ||
			get_user_root(con, &user_root) != 0 ||
			RegOpenKeyExW(user_root, SSH_KEYS_ROOT,
				0, STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS, &reg) != 0 ||
			RegOpenKeyExA(reg, thumbprint, 0,
				STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &sub) != 0 ||
			RegQueryValueExW(sub, NULL, 0, NULL, NULL, &regdatalen) != ERROR_SUCCESS ||
			(regdata = malloc(regdatalen)) == NULL ||
			RegQueryValueExW(sub, NULL, 0, NULL, regdata, &regdatalen) != ERROR_SUCCESS ||
			convert_blob(con, regdata, regdatalen, &keyblob, &keyblob_len, FALSE) != 0 ||
			(tmpbuf = sshbuf_from(keyblob, keyblob_len)) == NULL ||
			sshkey_private_deserialize(tmpbuf, &prikey) != 0) {
				error("cannot retrieve and deserialize key from registry");
				goto done;
			}
#ifdef ENABLE_PKCS11
	}
	else
		is_pkcs11_key = 1;
#endif /* ENABLE_PKCS11 */
	if (flags & SSH_AGENT_RSA_SHA2_256)
		algo = "rsa-sha2-256";
	else if (flags & SSH_AGENT_RSA_SHA2_512)
		algo = "rsa-sha2-512";

	if (sshkey_is_sk(prikey))
		sk_provider = "internal";
	if (sshkey_sign(prikey, sig, siglen, blob, blen, algo, sk_provider, NULL, 0) != 0) {
		error("cannot sign using retrieved key");
		goto done;
	}

	success = 1;

done:
	if (keyblob)
		free(keyblob);
	if (regdata)
		free(regdata);
	if (tmpbuf)
		sshbuf_free(tmpbuf);
#ifdef ENABLE_PKCS11
	if (!is_pkcs11_key)
#endif /* ENABLE_PKCS11 */
		if (prikey)
			sshkey_free(prikey);
	if (thumbprint)
		free(thumbprint);
	if (user_root)
		RegCloseKey(user_root);
	if (reg)
		RegCloseKey(reg);
	if (sub)
		RegCloseKey(sub);

	return success ? 0 : -1;
}

int
process_sign_request(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	u_char *blob, *data, *signature = NULL;
	size_t blen, dlen, slen = 0;
	u_int flags = 0;
	int r, request_invalid = 0, success = 0;
	struct sshkey *key = NULL;

#ifdef ENABLE_PKCS11
	int i, count = 0, index = 0;;
	wchar_t sub_name[MAX_KEY_LENGTH];
	DWORD sub_name_len = MAX_KEY_LENGTH;
	DWORD pin_len, epin_len, provider_len;
	char *pin = NULL, *npin = NULL, *epin = NULL, *provider = NULL;
	HKEY root = 0, sub = 0, user_root = 0;
	struct sshkey **keys = NULL;
	SECURITY_ATTRIBUTES sa = { 0, NULL, 0 };

	pkcs11_init(0);

	memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength = sizeof(sa);
	if ((!ConvertStringSecurityDescriptorToSecurityDescriptorW(REG_KEY_SDDL, SDDL_REVISION_1, &sa.lpSecurityDescriptor, &sa.nLength)) ||
		get_user_root(con, &user_root) != 0 ||
		RegCreateKeyExW(user_root, SSH_PKCS11_PROVIDERS_ROOT, 0, 0, 0, KEY_WRITE | STANDARD_RIGHTS_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &sa, &root, NULL) != 0) {
		goto done;
	}

	while (1) {
		sub_name_len = MAX_KEY_LENGTH;
		if (sub) {
			RegCloseKey(sub);
			sub = NULL;
		}
		if (RegEnumKeyExW(root, index++, sub_name, &sub_name_len, NULL, NULL, NULL, NULL) == 0) {
			if (RegOpenKeyExW(root, sub_name, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &sub) == 0 &&
				RegQueryValueExW(sub, L"provider", 0, NULL, NULL, &provider_len) == 0 &&
				RegQueryValueExW(sub, L"pin", 0, NULL, NULL, &epin_len) == 0) {
				if ((epin = malloc(epin_len + 1)) == NULL ||
					(provider = malloc(provider_len + 1)) == NULL ||
					RegQueryValueExW(sub, L"provider", 0, NULL, provider, &provider_len) != 0 ||
					RegQueryValueExW(sub, L"pin", 0, NULL, epin, &epin_len) != 0)
					goto done;
				provider[provider_len] = '\0';
				epin[epin_len] = '\0';
				if (convert_blob(con, epin, epin_len, &pin, &pin_len, 0) != 0 ||
					(npin = realloc(pin, pin_len + 1)) == NULL) {
					goto done;
				}
				pin = npin;
				pin[pin_len] = '\0';
				count = pkcs11_add_provider(provider, pin, &keys, NULL);
				for (i = 0; i < count; i++) {
					add_key(keys[i], provider);
				}
				free(keys);
				if (provider)
					free(provider);
				if (pin) {
					SecureZeroMemory(pin, (DWORD)pin_len);
					free(pin);
				}
				if (epin) {
					SecureZeroMemory(epin, (DWORD)epin_len);
					free(epin);
				}
				provider = NULL;
				pin = NULL;
				epin = NULL;
			}
		}
		else
			break;
	}
#endif /* ENABLE_PKCS11 */

	if (sshbuf_get_string_direct(request, &blob, &blen) != 0 ||
	    sshbuf_get_string_direct(request, &data, &dlen) != 0 ||
	    sshbuf_get_u32(request, &flags) != 0 ||
	    sshkey_from_blob(blob, blen, &key) != 0) {
		debug("sign request is invalid");
		request_invalid = 1;
		goto done;
	}

	if (sign_blob(key, &signature, &slen, data, dlen, flags, con) != 0)
		goto done;

	success = 1;
done:
	r = 0;
	if (request_invalid)
		r = -1;
	else {
		if (success) {
			if (sshbuf_put_u8(response, SSH2_AGENT_SIGN_RESPONSE) != 0 ||
			    sshbuf_put_string(response, signature, slen) != 0) {
				r = -1;
			}
		} else if (sshbuf_put_u8(response, SSH_AGENT_FAILURE) != 0)
				r = -1;
	}

	if (key)
		sshkey_free(key);
	if (signature)
		free(signature);
#ifdef ENABLE_PKCS11
	del_all_keys();
	pkcs11_terminate();
	if (provider)
		free(provider);
	if (pin) {
		SecureZeroMemory(pin, (DWORD)pin_len);
		free(pin);
	}
	if (epin) {
		SecureZeroMemory(epin, (DWORD)epin_len);
		free(epin);
	}
	if (user_root)
		RegCloseKey(user_root);
	if (root)
		RegCloseKey(root);
	if (sub)
		RegCloseKey(sub);
#endif /* ENABLE_PKCS11 */
	return r;
}

int
process_remove_key(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	char *blob = NULL;
	size_t blen;
	int r = 0, success = 0, request_invalid = 0;
	struct sshkey *key = NULL;
	Identity* id;

	if (sshbuf_get_string_direct(request, &blob, &blen) != 0 ||
	    sshkey_from_blob(blob, blen, &key) != 0) { 
		request_invalid = 1;
		goto done;
	}

	if ((id = lookup_identity(key)) == NULL) {
		debug("key not found");
		goto done;
	}

	/* We have this key, free it. */
	if (idtab->nentries < 1)
		fatal("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, next);
	free_identity(id);
	idtab->nentries--;
	success = 1;
done:
	r = 0;
	if (request_invalid)
		r = -1;
	else if (sshbuf_put_u8(response, success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE) != 0)
		r = -1;
	if (key)
		sshkey_free(key);
	return r;
}

int 
process_remove_all(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	int r = 0;
	Identity* id;

	/* Loop over all identities and clear the keys. */
	for (id = TAILQ_FIRST(&idtab->idlist); id;
		id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}

	if (sshbuf_put_u8(response, SSH_AGENT_SUCCESS) != 0)
		r = -1;
	return r;
}

#ifdef ENABLE_PKCS11
int process_add_smartcard_key(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con)
{
	char *provider = NULL, *pin = NULL, canonical_provider[PATH_MAX];
	int i, count = 0, r = 0, request_invalid = 0, success = 0;
	size_t pin_len;
	struct sshkey **keys = NULL;
	struct sshkey* key = NULL;
	Identity* id;

	if ((r = sshbuf_get_cstring(request, &provider, NULL)) != 0 ||
		(r = sshbuf_get_cstring(request, &pin, &pin_len)) != 0 ||
		pin_len > 256) {
		error("add smartcard request is invalid");
		request_invalid = 1;
		goto done;
	}

	if (realpath(provider, canonical_provider) == NULL) {
		error("failed PKCS#11 add of \"%.100s\": realpath: %s",
			provider, strerror(errno));
		request_invalid = 1;
		goto done;
	}

	// Remove 'drive root' if exists
	if (canonical_provider[0] == '/')
		memmove(canonical_provider, canonical_provider + 1, strlen(canonical_provider));

	count = pkcs11_add_provider(canonical_provider, pin, &keys, NULL);
	if (count <= 0) {
		error_f("failed to add key to store. count:%d", count);
		goto done;
	}

	for (i = 0; i < count; i++) {
		key = keys[i];
		if (lookup_identity(key) == NULL) {
			id = xcalloc(1, sizeof(Identity));
			id->key = key;
			keys[i] = NULL; /* transferred */
			id->provider = xstrdup(canonical_provider);
			id->comment = xstrdup(canonical_provider);
			TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
			idtab->nentries++;
			success = 1;
			debug("added smartcard keys to store");
		}
		/* XXX update constraints for existing keys */
		sshkey_free(keys[i]);
	}

done:
	r = 0;
	if (request_invalid)
		r = -1;
	else if (sshbuf_put_u8(response, success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE) != 0)
		r = -1;
	if (keys)
		free(keys);
	if (provider)
		free(provider);
	if (pin) {
		SecureZeroMemory(pin, (DWORD)pin_len);
		free(pin);
	}
	return r;
}

int process_remove_smartcard_key(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con)
{
	char *provider = NULL, *pin = NULL, canonical_provider[PATH_MAX];
	int r = 0, request_invalid = 0, success = 0, index = 0;
	HKEY user_root = 0;
	Identity* id, * nxt;

	if ((r = sshbuf_get_cstring(request, &provider, NULL)) != 0 ||
		(r = sshbuf_get_cstring(request, &pin, NULL)) != 0) {
		error("remove smartcard request is invalid");
		request_invalid = 1;
		goto done;
	}

	if (realpath(provider, canonical_provider) == NULL) {
		error("failed PKCS#11 add of \"%.100s\": realpath: %s",
			provider, strerror(errno));
		request_invalid = 1;
		goto done;
	}

	// Remove 'drive root' if exists
	if (canonical_provider[0] == '/')
		memmove(canonical_provider, canonical_provider + 1, strlen(canonical_provider));

	debug_f("remove %.100s", canonical_provider);
	for (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		/* Skip file--based keys */
		if (id->provider == NULL)
			continue;
		if (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		}
	}
	if (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	else
		error("pkcs11_del_provider failed");

done:
	r = 0;
	if (request_invalid)
		r = -1;
	else if (sshbuf_put_u8(response, success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE) != 0)
		r = -1;
	if (provider)
		free(provider);
	if (pin)
		free(pin);
	return r;
}
#endif /* ENABLE_PKCS11 */

int
process_request_identities(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	int success = 0, r = 0;
	DWORD key_count = 0;
	struct sshbuf* identities;
	Identity* id;

	if ((identities = sshbuf_new()) == NULL)
		goto done;

	TAILQ_FOREACH(id, &idtab->idlist, next) {
		if ((r = sshkey_puts_opts(id->key, identities,
			SSHKEY_SERIALIZE_INFO)) != 0 ||
			(r = sshbuf_put_cstring(identities, id->comment)) != 0) {
			error("compose key/comment");
			continue;
		}
		key_count++;
	}

	success = 1;
done:
	r = 0;
	if (success) {
		if (sshbuf_put_u8(response, SSH2_AGENT_IDENTITIES_ANSWER) != 0 ||
			sshbuf_put_u32(response, key_count) != 0 ||
			sshbuf_putb(response, identities) != 0)
			goto done;
	} else
		r = -1;
	if (identities)
		sshbuf_free(identities);
	return r;
}

extern int timingsafe_bcmp(const void* b1, const void* b2, size_t n);

static int
buf_equal(const struct sshbuf *a, const struct sshbuf *b)
{
	if (sshbuf_ptr(a) == NULL || sshbuf_ptr(b) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (sshbuf_len(a) != sshbuf_len(b))
		return SSH_ERR_INVALID_FORMAT;
	if (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		return SSH_ERR_INVALID_FORMAT;
	return 0;
}

static int
process_ext_session_bind(struct sshbuf* request, struct agent_connection* con)
{
	int r, sid_match, key_match;
	struct sshkey *key = NULL;
	struct sshbuf *sid = NULL, *sig = NULL;
	char *fp = NULL;
	size_t i;
	u_char fwd = 0;

	debug2_f("entering");
	if ((r = sshkey_froms(request, &key)) != 0 ||
	    (r = sshbuf_froms(request, &sid)) != 0 ||
	    (r = sshbuf_froms(request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(request, &fwd)) != 0) {
		error_fr(r, "parse");
		goto out;
	}
	if ((fp = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == NULL)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	if ((r = sshkey_verify(key, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), NULL, 0, NULL)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(key), fp);
		goto out;
	}
	/* check whether sid/key already recorded */
	for (i = 0; i < con->nsession_ids; i++) {
		if (!con->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			goto out;
		}
		sid_match = buf_equal(sid, con->session_ids[i].sid) == 0;
		key_match = sshkey_equal(key, con->session_ids[i].key);
		if (sid_match && key_match) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(key), fp);
			r = 0;
			goto out;
		} else if (sid_match) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(key), fp);
			r = -1;
			goto out;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	if (con->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		goto out;
	}
	con->session_ids = xrecallocarray(con->session_ids, con->nsession_ids,
	    con->nsession_ids + 1, sizeof(*con->session_ids));
	i = con->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(key), fp, i,
	    AGENT_MAX_SESSION_IDS);
	con->session_ids[i].key = key;
	con->session_ids[i].forwarded = fwd != 0;
	key = NULL; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	if ((con->session_ids[i].sid = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	if ((r = sshbuf_putb(con->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 out:
	sshkey_free(key);
	sshbuf_free(sid);
	sshbuf_free(sig);
	return r == 0 ? 1 : 0;
}

int
process_extension(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con)
{
	int r, success = 0;
	char *name;

	debug2_f("entering");
	if ((r = sshbuf_get_cstring(request, &name, NULL)) != 0) {
		error_fr(r, "parse");
		goto send;
	}
	if (strcmp(name, "session-bind@openssh.com") == 0)
		success = process_ext_session_bind(request, con);
	else
		debug_f("unsupported extension \"%s\"", name);
	free(name);
send:
	if ((r = sshbuf_put_u32(response, 1) != 0) ||
		((r = sshbuf_put_u8(response, success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE)) != 0))
		fatal_fr(r, "compose");

	r = success ? 0 : -1;
	
	return r;
}

#if 0
int process_keyagent_request(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	u_char type;

	if (sshbuf_get_u8(request, &type) != 0)
		return -1;
	debug2("process key agent request type %d", type);

	switch (type) {
	case SSH2_AGENTC_ADD_IDENTITY:
		return process_add_identity(request, response, con);
	case SSH2_AGENTC_REQUEST_IDENTITIES:
		return process_request_identities(request, response, con);
	case SSH2_AGENTC_SIGN_REQUEST:
		return process_sign_request(request, response, con);
	case SSH2_AGENTC_REMOVE_IDENTITY:
		return process_remove_key(request, response, con);
	case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		return process_remove_all(request, response, con);
#ifdef ENABLE_PKCS11
	case SSH_AGENTC_ADD_SMARTCARD_KEY:
		return process_add_smartcard_key(request, response, con);
	case SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED:
		return process_add_smartcard_key(request, response, con);
	case SSH_AGENTC_REMOVE_SMARTCARD_KEY:
		return process_remove_smartcard_key(request, response, con);
		break;
#endif /* ENABLE_PKCS11 */
	default:
		debug("unknown key agent request %d", type);
		return -1;		
	}
}
#endif

#pragma warning(pop)
