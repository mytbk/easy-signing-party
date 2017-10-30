easy-signing-party
===================

I'm angry with caff(1) in the signing-party package because it has so many Perl dependencies. I write this tool to make things easier.

Usage
-----

Clone this code and::

  make
  PATH="$PATH:$PWD" ./do_signing <your key id> <the key to be signed>
