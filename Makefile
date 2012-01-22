ext2: ext2.c ext2.h
	gcc ext2.c -Wall -g -lfuse -lm -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26 -o ext2 

clean:
	@rm -f ext2 *.o
