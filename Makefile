# easy-signing-party: simple utilities used to do a signing party
# Copyright (C) 2017  Iru Cai <mytbk920423@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

CFLAGS+=-g -Wall

extract_key: extract_key.o sigpkt.o packet.o

.PHONY: clean
clean:
	rm -f *.o extract_key
