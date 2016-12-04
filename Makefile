TARGET = bin/test
PROG_SRC = src/main.c

all: src/main.c src/sha256_digest.h src/sha256_digest.c
	gcc -o $(TARGET) $(PROG_SRC) src/sha256_digest.c

clean:
	rm -i -f -R -v src/*.o src/*.a bin/*.o bin/*.a
