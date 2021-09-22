#Makefile icmp
COMPILO=gcc
OPT1=-Wall


all: client server


client: icmp-c.c
	$(COMPILO) $(OPT1)  $< -o $@ 

server: icmp-m.c
	$(COMPILO) $(OPT1)  $< -o $@


