all: miruo.c miruo.h
	gcc -g -o miruo miruo.c -lpcap

clean:
	rm -f miruo
