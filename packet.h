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

typedef struct
{
	unsigned long pktlen; /* length excluding packet header */
	unsigned int hdrlen;
	unsigned char tag;
	const unsigned char *data;
} packet_info;

#define SIGPKT 2
#define PUBKEY 6
#define UIDPKT 13

void get_packet_info(const unsigned char *buffer, packet_info *pkt);
packet_info * get_all_packets(const unsigned char *buffer,
  unsigned long bufsz, int *npkts);
