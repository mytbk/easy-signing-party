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

#include <stdio.h>
#include <string.h>
#include "cryptodata.h"

#define perror(x) {}

struct sigpktv4 {
	uint8_t ver; /* should be 4*/
	uint8_t sigtype;
	uint8_t pubalgo;
	uint8_t hashalgo;
	uint8_t hashsublen[2];
	uint8_t hashsub[0];
};

static uint32_t
imm32be(const uint8_t *buff, int len)
{
	int i;
	uint32_t sum=0;

	for (i=0; i<len; i++) {
		sum = sum*256+buff[i];
	}
	return sum;
}

/*
 * parse signature subpacket and try to get issuer and issuer fingerprint
 * return the length parsed
 */
static int
parse_subpacket(const uint8_t *buff, siginfo *pgpdata)
{
	uint32_t packlen;
	uint8_t packtype;
	uint32_t totallen;

	if (buff[0]<192) {
		packlen = buff[0];
		buff += 1;
		totallen = packlen + 1;
	} else if (buff[0]<255) {
		packlen = ((buff[0]-192)<<8) + buff[1] + 192;
		buff += 2;
		totallen = packlen + 2;
	} else {
		perror("Unsupported signature subpacket length.\n");
		return -1;
	}

	packtype = *buff;

	if (packtype==16) {
		/* issuer type */
		if (packlen!=9) {
			perror("Incorrect length of issuer subpacket type.\n");
			return -1;
		}
		*(unsigned long long*)pgpdata->issuer = *(unsigned long long*)(buff+1);
	}

	if (packtype==33) {
		/* issuer fingerprint, buff[0] is 33, buff[1] is 4 */
		pgpdata->has_fpr = 1;
		memcpy(pgpdata->issuer_fpr, buff+2, 20);
	}

	return totallen;
}

int
parse_sigpkt(const uint8_t *buffer, siginfo *pgpdata)
{
	uint8_t PTag = buffer[0];
	uint8_t packettag = 0;
	const uint8_t *parse_buf = buffer;
	// uint32_t packetlen = 0;
	int hashlen;
	int unhashlen;

	if (pgpdata==NULL) {
		perror("pgpdata==NULL\n");
		return -1;
	}

	if ((PTag&0x80)==0) {
		perror("Invalid packet.\n");
		return -1;
	}

	if ((PTag&0x40)==1) {
		perror("New packet format not supported.\n");
		return -1;
	} else {
		/* old format */
		packettag = (PTag>>2)&0xf;
		switch (PTag&0x3) {
		case 0:
			// packetlen = buffer[1];
			parse_buf += 2;
			break;
		case 1:
			// packetlen = imm32be(buffer+1, 2);
			parse_buf += 3;
			break;
		case 2:
			// packetlen = imm32be(buffer+1, 4);
			parse_buf += 5;
			break;
		case 3:
		default:
			perror("Indeterminate length packet not supported!\n");
			return -1;
		}
	}

	if (packettag!=2) {
		perror("Not a signature packet!\n");
		return -1;
	}

	struct sigpktv4 *sigpkt = (struct sigpktv4*)parse_buf;

	if (sigpkt->ver!=4) {
		perror("Not a version 4 signature packet!\n");
		return -1;
	}

	pgpdata->sigtype = sigpkt->sigtype;
	pgpdata->pubalgo = sigpkt->pubalgo;

	hashlen = imm32be(sigpkt->hashsublen, 2);
	parse_buf += 6; /* skip the first 6 bytes of the packet */
	pgpdata->hashlen = (void*)parse_buf + hashlen - (void*)sigpkt;
	memcpy(pgpdata->hashdata, (uint8_t*)sigpkt, pgpdata->hashlen);

	pgpdata->hashalgo = sigpkt->hashalgo;
	pgpdata->has_fpr = 0;

	/* parse the hashed part */
	while (hashlen>0) {
		int parselen = parse_subpacket(parse_buf, pgpdata);
		if (parselen==-1) {
			perror("Parse subpacket error.\n");
			return -1;
		}
		parse_buf += parselen;
		hashlen -= parselen;
	}
	if (hashlen<0) {
		perror("Length of hash subpackets error.\n");
		return -1;
	}

	/* to parse unhashed part */
	unhashlen = imm32be(parse_buf, 2);
	parse_buf += 2;
	pgpdata->unhashlen = unhashlen;

	while (unhashlen>0) {
		int parselen = parse_subpacket(parse_buf, pgpdata);
		if (parselen==-1) {
			perror("Parse subpacket error.\n");
			return -1;
		}
		parse_buf += parselen;
		unhashlen -= parselen;
	}

	pgpdata->hashleft[0] = parse_buf[0];
	pgpdata->hashleft[1] = parse_buf[1];
	parse_buf += 2;

	/* to parse the signature */
	pgpdata->siglen = imm32be(parse_buf, 2);
	memcpy(pgpdata->sigdata, parse_buf+2, (pgpdata->siglen+7)/8);

	return 0;
}
