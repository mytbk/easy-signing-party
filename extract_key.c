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

static inline int
cmp_issuer(unsigned char id[], int idlen, unsigned char issuer[])
{
	return (idlen >= 8 && memcmp(id+idlen-8, issuer, 8)==0) ||
		(memcmp(id, issuer+8-idlen, idlen)==0);
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
	char *mailsfn = malloc(oplen+10);
	memcpy(outfnbase, outpath, oplen);
	memcpy(mailsfn, outpath, oplen);
	if (outpath[oplen-1]=='/') {
		strcpy(outfnbase+oplen, _id2);
		strcat(mailsfn, "mails");
	} else {
		outfnbase[oplen] = '/';
		strcpy(outfnbase+oplen+1, _id2);
		baselen++;
		strcat(mailsfn, "/mails");
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

	int npackets;
	packet_info *all_packets = get_all_packets(addr, fsize, &npackets);
	int pubidx = 0;
	packet_info *pubkey_pkt;
	long pubpktlen;
	while (pubidx < npackets && all_packets[pubidx].tag != PUBKEY)
		pubidx++;

	pubkey_pkt = all_packets + pubidx;
	pubpktlen = pubkey_pkt->pktlen + pubkey_pkt->hdrlen;

	printf("pubkey offset: 0x%lx, size: %ld\n", pubkey_pkt->data - addr,
			 pubpktlen);

	FILE *fmails = fopen(mailsfn, "w");
	fputs("MAILS=(\n", fmails);

	int uidcount = 0;
	int uididx = pubidx + 1;
	while (uididx < npackets) {
		if (all_packets[uididx].tag == UIDPKT) {
			packet_info *u = &all_packets[uididx];
			long uidlen = u->hdrlen + u->pktlen;
			printf("uid found, offset: %lx, size: %ld\n",
					 u->data - addr, uidlen);
			char *mail = getmailfromuid(u->data);
			printf("email address: %s\n", mail);
			fprintf(fmails, "  %s\n", mail);
			sprintf(outfn, "%s.%02d", outfnbase, uidcount);
			FILE *fp = fopen(outfn, "wb");
			fwrite(pubkey_pkt->data, 1, pubpktlen, fp);
			fwrite(u->data, 1, uidlen, fp);
			uidcount++;

			/* find signature packet, sig type 0x10 to 0x13 */
			long sigidx = uididx + 1;
			while (sigidx < npackets) {
				int do_write = 0;
				if (all_packets[sigidx].tag != SIGPKT)
					break;
				siginfo sigdata;
				long sigpktlen = all_packets[sigidx].pktlen + all_packets[sigidx].hdrlen;
				parse_sigpkt(all_packets[sigidx].data, &sigdata);
				printf("signature found, type is 0x%hhx", sigdata.sigtype);

				if (sigdata.has_fpr) {
					printf(", fpr ");
					for (int i=0; i<20; i++)
						printf("%02hhx", sigdata.issuer_fpr[i]);

					if (memcmp(id1, sigdata.issuer_fpr+20-id1len, id1len)==0) {
						printf(" (signer)");
						do_write = 1;
					}
					if (memcmp(id2, sigdata.issuer_fpr+20-id2len, id2len)==0) {
						printf(" (signee)");
						do_write = 1;
					}
				} else { /* no fingerprint, check key id */
					printf(", issuer ");
					for (int i=0; i<8; i++)
						printf("%02hhx", sigdata.issuer[i]);
					if (cmp_issuer(id1, id1len, sigdata.issuer)) {
						printf(" (signer)");
						do_write = 1;
					}
					if (cmp_issuer(id2, id2len, sigdata.issuer)) {
						printf(" (signee)");
						do_write = 1;
					}
				}

				puts("");
				if (do_write)
					fwrite(all_packets[sigidx].data, 1, sigpktlen, fp);

				sigidx++;
			}
			uididx = sigidx;
			fclose(fp);
		} else { /* if (all_packets[uididx].tag == UIDPKT) */
			uididx ++;
		}
	} /* while (uididx < npackets) */

	fputs(")\n", fmails);
	fclose(fmails);
}
