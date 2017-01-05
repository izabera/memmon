CFLAGS = -Ofast -march=native

all: memmon.so memmon

memmon:
	echo '#!/bin/sh' > memmon
	echo 'LD_PRELOAD=$$PWD/memmon.so "$$@"' >> memmon
	chmod +x memmon

memmon.so: memmon.c
	gcc -shared -fPIC memmon.c -o memmon.so -ldl -Ddoalign -Ddommap $(CFLAGS) -std=c99

clean:
	rm memmon memmon.so

.PHONY: clean
