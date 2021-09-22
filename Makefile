#Makefile icmp
COMPILO=gcc
OPT1=-Wall
OPTSHARED=-shared -fPIC

all: injector icmp

icmp: client.so master

injector: ./inject.c
	$(COMPILO) $(OPT1) $< -ldl -o $@

client.so: ./icmpcommunic/icmp-c.c
	$(COMPILO) $(OPT1) $(OPTSHARED) $< -o $@ 

master: icmpcommunic/icmp-m.c
	$(COMPILO) $(OPT1) $< -o $@

clean:
	rm injector && rm client.so && rm master

