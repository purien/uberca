#!/bin/sh
INCLUDE=" -I/usr/include -I."
gcc -c -O2 -Wall $INCLUDE  ./extract.c        -o  ./extract.o
gcc -c -O2 -Wall $INCLUDE  ./sig.c            -o  ./sig.o
gcc -c -O2 -Wall $INCLUDE  ./makek.c          -o  ./makek.o 
#
gcc -o extract     ./extract.o   -lpthread  -lssl -lcrypto  -ldl
gcc -o sig         ./sig.o       -lpthread  -lssl -lcrypto  -ldl
gcc -o makek       ./makek.o     -lpthread  -lssl -lcrypto  -ldl
rm ./extract.o
rm ./sig.o   
rm ./makek.o









