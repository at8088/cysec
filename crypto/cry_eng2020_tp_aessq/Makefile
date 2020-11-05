CC=gcc
CFLAGS=-g -Wall


aes_attack: attack.o aes-128_enc.o main.o
	$(CC) -o $@ $^
test_keyed_func: attack.o aes-128_enc.o keyed_func.o test_keyed_func.o
	$(CC) -o $@ $^
%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -rf *.o aes_attack test_keyed_func
