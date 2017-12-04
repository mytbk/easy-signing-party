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

#include "packet.h"
#include <stdlib.h>

void get_packet_info(const unsigned char *buffer, packet_info *pkt)
{
	pkt->data = buffer;
	pkt->tag = (buffer[0]>>2)&0xf;
	unsigned char ltype = (buffer[0])&0x3;

	switch (ltype) {
	case 0:
		pkt->hdrlen = 2;
		pkt->pktlen = buffer[1];
		break;
	case 1:
		pkt->hdrlen = 3;
		pkt->pktlen = (buffer[1]<<8) | buffer[2];
		break;
	case 2:
		pkt->hdrlen = 5;
		pkt->pktlen = (buffer[1]<<24) | (buffer[2]<<16) | (buffer[3]<<8) | buffer[4];
		break;
	default:
		break;
		/* not supported */
	}
}

packet_info *
get_all_packets(const unsigned char *buffer, unsigned long bufsz, int *npkts)
{
	int _n = 0;
	size_t offs = 0;
	packet_info pkt;
	packet_info *pkts;

	while (offs < bufsz) {
		get_packet_info(buffer + offs, &pkt);
		offs += pkt.pktlen + pkt.hdrlen;
		_n++;
	}

	*npkts = _n;
	pkts = (packet_info *)malloc(sizeof(packet_info)*_n);
	offs = 0;
	_n = 0;
	while (offs < bufsz) {
		get_packet_info(buffer + offs, &pkts[_n]);
		offs += pkts[_n].pktlen + pkts[_n].hdrlen;
		_n++;
	}
	return pkts;
}
