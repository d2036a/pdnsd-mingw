This is a fork of pdnsd which is a proxy DNS server with permanent caching.
It adds windows supporting, so you can run it on Windows OS.

##How to compile EXE
Compiling only supports for Linux.

Install Mingw
```
apt-get install gcc-mingw32
```

Compile
```
autoconf
./configure --with-target=mingw
make
```

You can get pdnsd.exe file at root forlder.

See http://members.home.nl/p.a.rombouts/pdnsd/doc.html to know how to use.
