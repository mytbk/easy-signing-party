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
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "cryptodata.h"
#include "packet.h"

static void *
mmapopen(const char *fn, long *size)
{
	struct stat statbuf;
	if (stat(fn, &statbuf)<0) {
		puts("error calling stat()");
		return NULL;
	} else {
		printf("file size: %ld\n", statbuf.st_size);
	}

	*size = statbuf.st_size;
	int fildes = open(fn, O_RDONLY);
	return mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fildes, 0);
}

static unsigned char
hexvalue(char c)
{
	if (isdigit(c))
		return c-'0';
	if (isupper(c))
		return c-'A'+10;
	if (islower(c))
		return c-'a'+10;
	return -1;
}

static void
str2id(const char *s, unsigned char *_id)
{
	while (*s) {
		*_id = (hexvalue(s[0])<<4) | hexvalue(s[1]);
		_id++;
		s += 2;
	}
}

static char *
getmailfromuid(const unsigned char *buffer)
{
	packet_info info;
	get_packet_info(buffer, &info);

	buffer += info.hdrlen;
	int i, j;
	for (j=info.pktlen-1; j>=0 && buffer[j]!='>'; j--)
		;
	if (j<0)
		return NULL;
	for (i=j-1; i>=0 && buffer[i]!='<'; i--)
		;
	if (i<0)
		return NULL;

	int len = j - i;
	char *mail = (char*)malloc(len);
	memcpy(mail, buffer+i+1, len-1);
	mail[len-1] = 0;
	return mail;
}

int
main(int argc, char *argv[])
{
	if (argc != 5) {
		printf("usage: %s <pubkey file> <yourkeyid> <keyid> <outputdir>\n", argv[0]);
		return 1;
	}

	const char *fn = argv[1];
	const char *outpath = argv[4];
	long fsize;
	unsigned char *addr = mmapopen(fn, &fsize);

	const char *_id1, *_id2;
	unsigned char id1[20], id2[20];
	int id1len, id2len;

	if (argv[2][0]=='0' && (argv[2][1]=='x' || argv[2][1]=='X'))
		_id1 = argv[2]+2;
	else
		_id1 = argv[2];

	if (argv[3][0]=='0' && (argv[3][1]=='x' || argv[3][1]=='X'))
		_id2 = argv[3]+2;
	else
		_id2 = argv[3];

	id1len = strlen(_id1);
	id2len = strlen(_id2);

	int oplen = strlen(outpath);
	int baselen = oplen+id2len;
	char *outfnbase = malloc(baselen+2);
	char *outfn = malloc(baselen+10);
	memcpy(outfnbase, outpath, oplen);
	if (outpath[oplen-1]=='/') {
		strcpy(outfnbase+oplen, _id2);
	} else {
		outfnbase[oplen] = '/';
		strcpy(outfnbase+oplen+1, _id2);
		baselen++;
	}

	if ((id1len%8) || (id2len%8)) {
		puts("the hex key id/fingerprint length should be multiple of 8.\n");
		return 1;
	}
	if (id1len>40 || id2len>40) {
		puts("key id/fingerprint too long.\n");
		return 1;
	}
	str2id(_id1, id1);
	str2id(_id2, id2);
	id1len /= 2;
	id2len /= 2;
	printf("id1: ");
	for (int i=0; i<id1len; i++)
		printf("%02hhx", id1[i]);
	printf(", id2: ");
	for (int i=0; i<id2len; i++)
		printf("%02hhx", id2[i]);
	puts("");

	long offset = 0;
	packet_info info;

	while (offset<fsize) {
		get_packet_info(addr+offset, &info);
		if (info.tag == PUBKEY)
			break;

		offset += info.hdrlen + info.pktlen;
	}

	long puboffset = offset;
	long pubpktlen = info.hdrlen + info.pktlen;
	printf("pubkey offset: %lx, size: %ld\n", puboffset, pubpktlen);

	int uidcount = 0;
	long uidoffset = offset;
	while (uidoffset<fsize) {
		get_packet_info(addr+uidoffset, &info);
		if (info.tag == UIDPKT) {
			long uidlen = info.hdrlen+info.pktlen;
			printf("uid found, offset: %lx, size: %ld\n",
					 uidoffset, uidlen);
			char *mail = getmailfromuid(addr+uidoffset);
			printf("email address: %s\n", mail);
			sprintf(outfn, "%s.%02d", outfnbase, uidcount);
			FILE *fp = fopen(outfn, "wb");
			fwrite(addr+puboffset, 1, pubpktlen, fp);
			fwrite(addr+uidoffset, 1, uidlen, fp);
			uidcount++;

			/* find signature packet, sig type 0x10 to 0x13 */
			long sigoffset = uidoffset+info.hdrlen+info.pktlen;
			while (sigoffset<fsize) {
				int do_write = 0;
				get_packet_info(addr+sigoffset, &info);
				if (info.tag != SIGPKT)
					break;
				siginfo sigdata;
				parse_sigpkt(addr+sigoffset, &sigdata);
				printf("signature found, type is 0x%hhx, issuer ", sigdata.sigtype);
				for (int i=0; i<8; i++)
					printf("%02hhx", sigdata.issuer[i]);
				if (id1len<8 && memcmp(id1, sigdata.issuer+8-id1len, id1len)==0) {
					printf(" (signer)");
					do_write = 1;
				}
				if (id2len<8 && memcmp(id2, sigdata.issuer+8-id2len, id2len)==0) {
					printf(" (signee)");
					do_write = 1;
				}

				if (sigdata.has_fpr) {
					printf(", fpr ");
					for (int i=0; i<20; i++)
						printf("%02hhx", sigdata.issuer_fpr[i]);
					/* TODO: if key id matches but fingerprint doesn't match,
						we shouldn't write this signature packet
					*/
					if (id1len<8 && memcmp(id1, sigdata.issuer_fpr+20-id1len, id1len)==0) {
						printf(" (signer)");
						do_write = 1;
					}
					if (id2len<8 && memcmp(id2, sigdata.issuer_fpr+20-id2len, id2len)==0) {
						printf(" (signee)");
						do_write = 1;
					}
				}
				puts("");
				if (do_write)
					fwrite(addr+sigoffset, 1, info.hdrlen+info.pktlen, fp);

				sigoffset += info.hdrlen + info.pktlen;
			}
			uidoffset = sigoffset;
			fclose(fp);
			continue;
		}

		uidoffset += info.hdrlen+info.pktlen;
	}
}
