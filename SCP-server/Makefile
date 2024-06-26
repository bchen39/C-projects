all:
	# install libgcrypt if not yet
	sudo apt-get install libgcrypt-dev
	# compile the files. Include gcrypt library.
	gcc -o purenc purenc.c -lgcrypt -lm
	gcc -o purdec purdec.c -lgcrypt
clean:
	rm -f testfile* purenc purdec ._*
