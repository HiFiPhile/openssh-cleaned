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

static char*
agent_decode_alg(struct sshkey* key, u_int flags)
{
	if (key->type == KEY_RSA) {
		if (flags & SSH_AGENT_RSA_SHA2_256)
			return "rsa-sha2-256";
		else if (flags & SSH_AGENT_RSA_SHA2_512)
			return "rsa-sha2-512";
	}
	else if (key->type == KEY_RSA_CERT) {
		if (flags & SSH_AGENT_RSA_SHA2_256)
			return "rsa-sha2-256-cert-v01@openssh.com";
		else if (flags & SSH_AGENT_RSA_SHA2_512)
			return "rsa-sha2-512-cert-v01@openssh.com";
	}
	return NULL;
}

int
process_unsupported_request(struct sshbuf* request, struct sshbuf* response, LPPIPEINST con)
{
	int r = 0;
	debug("ssh protocol 1 is not supported");
	if (sshbuf_put_u8(response, SSH_AGENT_FAILURE) != 0)
		r = -1;
	return r;
}

static int
parse_key_constraint_extension(struct sshbuf *m)
{
	char *ext_name = NULL, *skprovider = NULL;
	int r;

	if ((r = sshbuf_get_cstring(m, &ext_name, NULL)) != 0) {
		error_fr(r, "parse constraint extension");
		goto out;
	}
	debug_f("constraint ext %s", ext_name);
	if (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		if ((r = sshbuf_get_cstring(m, &skprovider, NULL)) != 0) {
			error_fr(r, "parse %s", ext_name);
			goto out;
		}
		if (strcmp(skprovider, "internal") != 0) {
			error_f("unsupported sk-provider: %s", skprovider);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			goto out;
		}
	} else {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		goto out;
	}
	/* success */
	r = 0;
 out:
	free(ext_name);
	return r;
}

static int
parse_key_constraints(struct sshbuf *m)
{
	int r;
	u_char ctype;

	while (sshbuf_len(m)) {
		if ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error("get constraint type returned %d", r);
			return r;
		}
		switch (ctype) {
		case SSH_AGENT_CONSTRAIN_EXTENSION:
			if ((r = parse_key_constraint_extension(m)) != 0)
				return r;
			break;
		default:
			error("Unknown constraint %d", ctype);
			return SSH_ERR_FEATURE_UNSUPPORTED;
		}
	}

	return 0;
}

int
process_add_identity(struct sshbuf* request, struct sshbuf* response, LPPIPEINST con) 
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

	if ((r = parse_key_constraints(request)) != 0) {
		if (r != SSH_ERR_FEATURE_UNSUPPORTED)
			request_invalid = 1;
		goto done;
	}

	if ((r = sshkey_shield_private(key)) != 0) {
		error("shield private");
		goto done;
	}

	/* Shield key again with DPAPI */
	CryptProtectMemory(key->shielded_private, (DWORD)key->shielded_len, CRYPTPROTECTMEMORY_SAME_PROCESS);
	CryptProtectMemory(key->shield_prekey, (DWORD)key->shield_prekey_len, CRYPTPROTECTMEMORY_SAME_PROCESS);

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
		fatal("sshkey_fingerprint failed");

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

int
process_sign_request(struct sshbuf* request, struct sshbuf* response, LPPIPEINST con) 
{
	u_char* blob, * data, * signature = NULL;
	size_t blen, dlen, slen = 0;
	u_int flags = 0;
	char* fp = NULL;
	int r, request_invalid = 0, success = 0;
	struct sshkey* key = NULL;
	struct identity* id;
	const char* sk_provider = NULL;

	if (sshbuf_get_string_direct(request, &blob, &blen) != 0 ||
		sshbuf_get_string_direct(request, &data, &dlen) != 0 ||
		sshbuf_get_u32(request, &flags) != 0 ||
		sshkey_from_blob(blob, blen, &key) != 0) {
		debug("sign request is invalid");
		request_invalid = 1;
		goto done;
	}

	if ((id = lookup_identity(key)) == NULL) {
		verbose_f("%s key not found", sshkey_type(key));
		goto done;
	}

	if ((fp = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
		SSH_FP_DEFAULT)) == NULL) {
		fatal("fingerprint failed");
		goto done;
	}

	if (sshkey_is_sk(key))
		sk_provider = "internal";
	
	/* Un-shield key with DPAPI */
	CryptUnprotectMemory(id->key->shielded_private, (DWORD)id->key->shielded_len, CRYPTPROTECTMEMORY_SAME_PROCESS);
	CryptUnprotectMemory(id->key->shield_prekey, (DWORD)id->key->shield_prekey_len, CRYPTPROTECTMEMORY_SAME_PROCESS);

	if ((r = sshkey_sign(id->key, &signature, &slen, data, dlen,
		agent_decode_alg(key, flags), sk_provider, NULL, 0)) != 0) {
			error("cannot sign using retrieved key");
			goto done;
	}
	/* Success */
	success = 1;
done:
	if (id) {
		/* Shield key again with DPAPI */
		CryptProtectMemory(id->key->shielded_private, (DWORD)id->key->shielded_len, CRYPTPROTECTMEMORY_SAME_PROCESS);
		CryptProtectMemory(id->key->shield_prekey, (DWORD)id->key->shield_prekey_len, CRYPTPROTECTMEMORY_SAME_PROCESS);
	}

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

	return r;
}

int
process_remove_key(struct sshbuf* request, struct sshbuf* response, LPPIPEINST con) 
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
process_remove_all(struct sshbuf* request, struct sshbuf* response, LPPIPEINST con) 
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
int process_add_smartcard_key(struct sshbuf* request, struct sshbuf* response, LPPIPEINST con)
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

int process_remove_smartcard_key(struct sshbuf* request, struct sshbuf* response, LPPIPEINST con)
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
process_request_identities(struct sshbuf* request, struct sshbuf* response, LPPIPEINST con) 
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
process_ext_session_bind(struct sshbuf* request, LPPIPEINST con)
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
process_extension(struct sshbuf* request, struct sshbuf* response, LPPIPEINST con)
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
int process_keyagent_request(struct sshbuf* request, struct sshbuf* response, LPPIPEINST con)
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
