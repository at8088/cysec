CC=gcc
CFLAGS=-g -Wall


aes_attack: attack.o aes-128_enc.o main.o
	$(CC) -o $^

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -rf *.o aes_attack
