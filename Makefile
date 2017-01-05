all:
	gcc -shared -fPIC memmon.c -o memmon.so -ldl -Ddoalign -Ddommap -Ofast -march=native
	echo '#!/bin/sh' > memmon
	echo 'LD_PRELOAD=$$PWD/memmon.so "$$@"' >> memmon
	chmod +x memmon

