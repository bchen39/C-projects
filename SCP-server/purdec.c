#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h> 
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <arpa/inet.h> 
#include <errno.h>
#include <stdarg.h>
#include <gcrypt.h>


#define BUFSIZE 20000
#define MAX_SCAN 1024 
#define KEY_SZ 32
#define IV_SZ 16
#define SALT_SZ 64
#define HMAC_KEY_SZ 32
#define DEBUG 0

void gcry_init() {
	/* Check gcrypt version. */
	if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "libgcrypt version mismatch\n");
        exit(EXIT_FAILURE);
    }

  	/* Uncomment to disable secure memory.  */
  	//gcry_control (GCRYCTL_DISABLE_SECMEM, 0);

  	/* Tell Libgcrypt that initialization has completed. */
  	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
}

int main(int argc, char *argv[]) {
	/* length of variables (p = plaintext, h = hmac, s = salt) */
	uint16_t nread, nwrite, plength, hlength, slength;
	/* Buffer for reading from purenc */
	char buffer[BUFSIZE]; 
	/* Buffer for password */
	char passwd[100];
	/* Buffer for encryption key */
	char key[100];
	/* Buffer for HMAC key */
	char hmac_key[100];
	/* Buffer for salt */
	char salt[100];
	/* FD for reading. */
	int net_fd, sock_fd;
	/* Address, port info */
	struct sockaddr_in serv_addr;
	unsigned short int port;
	/* Crypto and MAC handle/context. */
	gcry_cipher_hd_t cipher_hd;
	gcry_md_hd_t md_hd;
	/* Initialize counter for CTR mode. */
	char *ctr = (char*)(malloc(16 * sizeof(char)));
	memset((void *) ctr, 0, (size_t) (16 * sizeof(char)));
	/* File ptr for source enc file (.pur file) and file for decryption. */
	FILE* f_src;
	FILE* f_dec;
	/* Determines whether to find encrypted file locally or receive from remote server. */
	bool local = false, rcv = false;
	/* Filename for input and output. */
	char* filename = NULL;
	char filename_out[100];
	int read_bytes;
	size_t f_sz;

	bzero((void *) buffer, BUFSIZE);

	/* Limits correct argument size. */
	if (argc < 2 || argc > 3) {
		perror("Usage: ./purdec <port number> or ./purdec -l <input file>");
		exit(1);
	}	

	if(strcmp("-l", argv[1]) == 0){
		/* Local case. */
		if (argc != 3) {
			perror("Usage: ./purdec <port number> or ./purdec -l <input file>");
			exit(1);
		}
		local = true;

		/* Obtains file name from argument and corresponding output file name. */
		filename = argv[2];
		memcpy(filename_out, filename, strlen(filename) - 4);
		filename_out[strlen(filename) - 4] = '\0';
		if (access(filename_out, F_OK) == 0) {
		// file exists
			fprintf(stderr, "Output file already exists.\n");
			exit(EXIT_FAILURE);
		}
		/* Opens encrypted file and obtain file size. */
		f_src = fopen(filename, "rb+");
		fseek(f_src, 0L, SEEK_END);
		f_sz = ftell(f_src);
		fseek(f_src, 0L, SEEK_SET);
		if (DEBUG)
			printf("file size: %ld\n", f_sz);

		/* Read salt from file. */
		if ((read_bytes = fread(salt, 1, SALT_SZ, f_src)) < 0) {
			printf("Cannot read salt\n");
			goto err_file2_local;
		}
	} else {
		/* Remote case */
		if (argc != 2) {
			perror("Usage: ./purdec <port number> or ./purdec -l <input file>");
			exit(1);
		}
		rcv = true;

		/* Sets up socket. */
		if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			perror("socket()");
			exit(1);
		}
    
    	/* Sets up receiving server address. */
    	memset(&serv_addr, 0, sizeof(serv_addr));
    	serv_addr.sin_family = AF_INET;
    	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    	serv_addr.sin_port = htons((unsigned short) strtoul(argv[1], NULL, 0));
    	if (DEBUG)
    		printf("Set %hu as the port...\n", htons(serv_addr.sin_port));
    	if (bind(sock_fd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0){
			perror("bind()");
			goto err_sock;
    	}
    
		if (listen(sock_fd, 5) < 0){
			perror("listen()");
			goto err_sock;
		}
		printf("Waiting for connection...\n");
		/* wait for connection request */
		if ((net_fd = accept(sock_fd, NULL, NULL)) < 0){
			perror("accept()");
			goto err_sock;
		}

		/* Reads in encrypted file name and create corresponding output file name. */
		char fname[100];
		bzero((void *) fname, 100);
		if ((read(net_fd, fname, 100)) < 0) {
			perror("Error reading file name.\n");
			goto err_filename;
		}
		if (DEBUG)
			printf("filename is: %s, length %ld\n", fname, strlen(fname));
		filename = fname;
		memcpy(filename_out, filename, strlen(filename) - 4);
		filename_out[strlen(filename) - 4] = '\0';
		if (access(filename_out, F_OK) == 0) {
		// file exists
			fprintf(stderr, "Output file already exists.\n");
			exit(EXIT_FAILURE);
		}

		/* read in salt */
		bzero((void *) salt, 100);
		if ((read_bytes = read(net_fd, salt, SALT_SZ + 1)) < 0) {
			perror("Error reading salt.\n");
			goto err_filename;
		}
		if (DEBUG)
			printf("Read %d bytes of salt\n", read_bytes);
	}

	/* Asks for password. */
	bzero((void *) passwd, sizeof(passwd));
	printf("Enter password: ");
	fgets(passwd, sizeof(passwd), stdin);

	/* Initialize the gcrypt */
	gcry_init();
	gpg_error_t err;

	/* Derives key from password and salt. */
	err = gcry_kdf_derive(passwd, strlen(passwd), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, salt, SALT_SZ, 10, KEY_SZ, key); 
	if (err) {
		/* Delete password from memory. */
		bzero(passwd, 100);
		fprintf(stderr, "Error deriving key: %s\n", gcry_strerror(err));
		goto err_filename;
	}

	/* Derives HMAC key from password and salt. */
	err = gcry_kdf_derive(passwd, strlen(passwd), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, salt, SALT_SZ, 20, HMAC_KEY_SZ, hmac_key); 
	bzero(passwd, 100);
	if (err) {
		fprintf(stderr, "Error deriving hmac key: %s\n", gcry_strerror(err));
		goto err_crypt;
	}

	/* Initiates cipher handle using AES256_CTR. */
	err = gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR, 0);
	if (err) {
		fprintf(stderr, "Error initializing cipher: %s\n", gcry_strerror(err));
		goto err_filename;
	}

	/* Sets up decryption key. */
	err = gcry_cipher_setkey(cipher_hd, key, KEY_SZ);
	if (err) {
		fprintf(stderr, "Error setting key: %s\n", gcry_strerror(err));
		goto err_crypt;
	}

	/* Sets up counter. */
	err = gcry_cipher_setctr(cipher_hd, ctr, 16);
	if (err) {
		fprintf(stderr, "Error setting counter: %s\n", gcry_strerror(err));
		goto err_crypt;
	}

	/* Initiates MAC handle using HMAC_SHA256. */
	err = gcry_md_open(&md_hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
	if (err) {
		fprintf(stderr, "Error initializing mac: %s\n", gcry_strerror(err));
		goto err_crypt;
	}

	/* Sets up HMAC key. */
	err = gcry_md_setkey(md_hd, hmac_key, HMAC_KEY_SZ);
	if (err) {
		fprintf(stderr, "Error setting hmac key: %s\n", gcry_strerror(err));
		goto err_md;
	}

	f_dec = fopen(filename_out, "ab+");

	if (rcv) {
		/* Begin decryption. */
		while ((read_bytes = read(net_fd, buffer, MAX_SCAN + HMAC_KEY_SZ)) > 0) {

			printf("Received %d bytes.\n", read_bytes);
			/* Performs HMAC and checks whether it matches.*/
			gcry_md_write(md_hd, buffer, read_bytes - HMAC_KEY_SZ);
			char* hmac_enc = gcry_md_read(md_hd, GCRY_MD_SHA256);
			if (memcmp(hmac_enc, buffer + read_bytes - HMAC_KEY_SZ, HMAC_KEY_SZ) != 0) {
				fprintf(stderr, "HMAC not the same.\n");
				goto err_file2;
			}
			printf("HMAC matches, continue with decryption.\n");

			/* Perform decryption (in the case of CTR mode, encryption) and write into decrypted file. */
			gcry_cipher_encrypt(cipher_hd, buffer, read_bytes - HMAC_KEY_SZ, NULL, 0);
			int bytes_written = fwrite(buffer, 1, read_bytes - HMAC_KEY_SZ, f_dec);
			printf("Written %d bytes\n", bytes_written);
		}
	} else if (local) {

		/* Reads partial file (1024 bytes of encryption and 32 bytes of MAC) from buffer. */
		while ((read_bytes = fread(buffer, 1, MAX_SCAN + HMAC_KEY_SZ, f_src)) > 0) {
    	printf("Read %d bytes.\n", read_bytes);

    	/* Performs HMAC and checks whether it matches.*/
			gcry_md_write(md_hd, buffer, read_bytes - HMAC_KEY_SZ);
			char* hmac_enc = gcry_md_read(md_hd, GCRY_MD_SHA256);
			if (memcmp(hmac_enc, buffer + read_bytes - HMAC_KEY_SZ, HMAC_KEY_SZ) != 0) {
				fprintf(stderr, "HMAC not the same.\n");
				goto err_file2;
			}
			printf("HMAC matches, continue with decryption.\n");

			/* Perform decryption (in the case of CTR mode, encryption) and write into decrypted file. */
			gcry_cipher_encrypt(cipher_hd, buffer, read_bytes - HMAC_KEY_SZ, NULL, 0);
			int bytes_written = fwrite(buffer, 1, read_bytes - HMAC_KEY_SZ, f_dec);
			printf("Written %d bytes\n", bytes_written);
		}
		if (read_bytes < 0) {
			perror("Error reading from file.\n");
			goto err_file2;
		}
	}
	/* Makes sure that when exiting, corresponding files, sockets and contexts are freed and keys are wiped from memory. */
	bzero(key, KEY_SZ);
	bzero(hmac_key, HMAC_KEY_SZ);
	if (local)
		fclose(f_src);
	fclose(f_dec);
	gcry_md_close(md_hd);
	gcry_cipher_close(cipher_hd);
	if (rcv) {
		close(sock_fd);
	}
	return 0;

	/* Makes sure that when exiting, corresponding files, sockets and contexts are freed and keys are wiped from memory. */
	err_file2:
		bzero(key, KEY_SZ);
		bzero(hmac_key, HMAC_KEY_SZ);
		fclose(f_dec);
	err_md:
		gcry_md_close(md_hd);
	err_crypt:
		gcry_cipher_close(cipher_hd);
	err_file2_local:
		if (local)
			fclose(f_src);
	err_filename:
	err_sock:
		if (rcv) {
			close(sock_fd);
		}
		exit(EXIT_FAILURE);
}




