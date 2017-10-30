/*
 * easy-signing-party: simple utilities used to do a signing party
 * Copyright (C) 2017  Iru Cai <mytbk920423@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

/* RSA public key data parsed from public key packet */

struct RSA_pubkey {
	uint32_t rsa_nlen;
	uint32_t rsa_elen;
	uint8_t keyhash[20];
	uint8_t RSA_n[1024];
	uint8_t RSA_e[1024];
};

/* signature data parsed from signature packet */

typedef struct siginfo {
	uint8_t hashdata[1024];
	uint32_t siglen;
	uint8_t sigdata[1024];
	uint8_t issuer[8];
	uint8_t issuer_fpr[20];
	uint8_t has_fpr;
	uint8_t sigtype;
	uint8_t pubalgo;
	uint8_t hashalgo;
	/* hashlen: the length of the part of signature packet
		needed to hash when creating a signature
		hashlen = 6+<length of the hashed subpackets>
	*/
	uint32_t hashlen;
	/* unhashlen: the length of subpackets unhashed */
	uint32_t unhashlen;
	uint8_t hashleft[2];
} siginfo;

enum HashAlgo {
	HASH_MD5=1,
	HASH_SHA1,
	HASH_RIPEMD160,
	HASH_SHA256=8,
	HASH_SHA384,
	HASH_SHA512,
	HASH_SHA224
};

int parse_pubkey(uint8_t *buff, struct RSA_pubkey *rsa_info);
int find_pubkey(uint8_t *buff, int bufflen, struct RSA_pubkey *rsa_info, const uint8_t *keyid);
int parse_sigpkt(uint8_t *buffer, siginfo *pgpdata);
/* verify RSA signature */
int sigverify(
	const uint8_t *sigdata, uint32_t siglen_bytes,
	uint8_t hashalgo, const uint8_t *digest_toverify,
	struct RSA_pubkey *pubkey);
