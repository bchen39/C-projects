#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include <math.h>


#define BUFSIZE 20000
#define MAX_SCAN 1024 
#define KEY_SZ 32
#define IV_SZ 16
#define SALT_SZ 64
#define HMAC_KEY_SZ 32
#define DEBUG 0

void gcry_init() {
  /* Disable secure memory.  */
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);

  /* ... If required, other initialization goes here.  */

  /* Tell Libgcrypt that initialization has completed. */
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
}

int main(int argc, char *argv[]) {
	// takes input
	uint16_t nread, nwrite, plength, hlength, slength;
	//  uint16_t total_len, ethertype
	/* Buffer for reading from file */
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
	int sock_fd;
	/* Remote address, port info. */
	struct sockaddr_in remote;
	unsigned short int port;
	socklen_t remotelen;
	/* Crypto and MAC handle/context. */
	gcry_cipher_hd_t cipher_hd;
	gcry_md_hd_t md_hd;
	/* Initialize counter for CTR mode. */
	char *ctr = (char*)(malloc(16 * sizeof(char)));
	memset((void *) ctr, 0, (size_t) (16 * sizeof(char)));
	/* File ptr for source file to encrypt and file for encryption (.pur file). */
	FILE* f_src;
	FILE* f_enc;
	/* Determines whether to store encryption locally or send to remote server. */
	bool local = false, snd = false;
	/* Filename for input and output. */
	char* filename = argv[1];
	char filename_out[100];
	bzero((void *) filename_out, 100);
	int filelen;
	snprintf(filename_out, 100, "%s.pur", filename);
	if (access(filename_out, F_OK) == 0) {
    // file exists
    fprintf(stderr, "Output file already exists.\n");
    exit(EXIT_FAILURE);
	}

	/* Limits correct argument size. */
	if (argc < 3 || argc > 5) {
		fprintf(stderr, "Usage: ./purenc <input file> [-d <output IP-addr:port>] [-l]\n");
		exit(EXIT_FAILURE);
	}

	if (strncmp(argv[2], "-l", strlen("-l")) == 0) {
		/* Local case */
		if (argc != 3) {
			fprintf(stderr, "Usage: ./purenc <input file> [-d <output IP-addr:port>] [-l]\n");
			exit(EXIT_FAILURE);
		}
		local = true;
	} else if (strncmp(argv[2], "-d", strlen("-l")) == 0) {
		if (argc == 5) {
			if (strncmp(argv[4], "-l", strlen("-l")) == 0) {
				local = true;
			} else {
				fprintf(stderr, "Usage: ./purenc <input file> [-d <output IP-addr:port>] [-l]\n");
				exit(EXIT_FAILURE);
			}
		} else if (argc != 4) {
			fprintf(stderr, "Usage: ./purenc <input file> [-d <output IP-addr:port>] [-l]\n");
			exit(EXIT_FAILURE);
		}

		snd = true;
		if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			perror("socket()");
			exit(EXIT_FAILURE);
		}

		/* assign the destination address */
		memset(&remote, 0, sizeof(remote));
		remote.sin_family = AF_INET;
		char *token;

   	/* get the IP and port */
		token = strtok(argv[3], ":");
		if ((remote.sin_addr.s_addr = inet_addr(token)) == -1) {
			fprintf(stderr, "Error reading address.\n");
			goto err_sock;
		}
		printf("address: %s\n", token);
		token = strtok(NULL, ":");
		if (sscanf(token, "%hu", &port) == EOF) {
			fprintf(stderr, "Error reading port number.\n");
			goto err_sock;
		}
		remote.sin_port = htons(port);
		printf("port: %hu\n", ntohs(remote.sin_port));
		if (connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0) {
			printf("connection with the server failed...\n");
			goto err_sock;
		}
		printf("Connected to server %s\n", inet_ntoa(remote.sin_addr));
	} else {
		fprintf(stderr,"Usage: ./purenc <input file> [-d <output IP-addr:port>] [-l]\n");
		exit(EXIT_FAILURE);
	}
	// Initialize the gcrypt
	gcry_init();

	// Asks for password. 
	printf("Enter password: ");
	fgets(passwd, sizeof(passwd), stdin);
	
	gpg_error_t err;
	// Randomize salt
	bzero((void *) salt, 100);
	gcry_randomize(salt, SALT_SZ, GCRY_STRONG_RANDOM);
	int byte_writen;
	/* Send out the filename and salt to remote server. */
	if (snd) {
		// added one byte of terminal character to avoid recv error.
		if ((byte_writen = write(sock_fd, filename_out, strlen(filename_out) + 1)) < 0) {
			printf("Cannot write filename.\n");
			goto err_sock;
		}
		if (DEBUG)
			printf("Sent file name: %s, size %d\n", filename_out, byte_writen);
		if ((byte_writen = write(sock_fd, salt, SALT_SZ + 1)) < 0) {
			printf("Cannot write salt.\n");
			goto err_sock;
		}
		if (DEBUG)
			printf("Sent salt size %d\n", byte_writen);
	}

	/* Derives key from password and salt. */
	err = gcry_kdf_derive(passwd, strlen(passwd), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, salt, SALT_SZ, 10, KEY_SZ, key); 
	if (err) {
		fprintf(stderr, "Error deriving key: %s\n", gcry_strerror(err));
		goto err_sock;
	}

	/* Initiates cipher handle using AES256_CTR. */
	err = gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR, 0);
	if (err) {
		fprintf(stderr, "Error initializing cipher: %s\n", gcry_strerror(err));
		goto err_sock;
	}

	/* Sets up encryption key. */
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

	/* Derives HMAC key from password and salt. */
	err = gcry_kdf_derive(passwd, strlen(passwd), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, salt, SALT_SZ, 20, HMAC_KEY_SZ, hmac_key); 
	if (err) {
		fprintf(stderr, "Error deriving hmac key: %s\n", gcry_strerror(err));
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
	
	/* Opens up file to encrypt and gets size. */
	if ((f_src = fopen(filename, "rb+")) == NULL) {
		printf("Error reading source file.\n");
		goto err_md;
	}
	fseek(f_src, 0L, SEEK_END);
	size_t f_sz = ftell(f_src);
	fseek(f_src, 0L, SEEK_SET);
	if (DEBUG)
		printf("file size: %ld", f_sz);

	int read_bytes, sent_bytes;
	/* Opens local encryption file. */
	if (local) {
		if ((f_enc = fopen(filename_out, "ab+")) == NULL) {
			printf("Error opening encryption file.\n");
			goto err_file2_local;
		}
		fwrite(salt, 1, SALT_SZ, f_enc);
	}

	/* Begin encryption. */
	while ((read_bytes = fread(buffer, 1, MAX_SCAN, f_src)) > 0) {
		/* Writes encryption per 1024 byte and corresponding MAC to buffer. */
		gcry_cipher_encrypt(cipher_hd, buffer, read_bytes, NULL, 0);
		gcry_md_write(md_hd, buffer, read_bytes);
		char* hmac_enc = gcry_md_read(md_hd, GCRY_MD_SHA256);
		memcpy(buffer + read_bytes, hmac_enc, HMAC_KEY_SZ);

		/* Send buffer to server. */
		if (snd) {
			if ((sent_bytes = write(sock_fd, buffer, read_bytes + HMAC_KEY_SZ)) < 0) {
				printf("Cannot write send_length.\n");
				goto err_file2_local;
			}
			printf("Read %d bytes, sent %d bytes.\n", read_bytes, sent_bytes);
		}

		/* Store buffer locally in .pur file. */
		if (local) {
			if ((sent_bytes = fwrite(buffer, 1, read_bytes + HMAC_KEY_SZ, f_enc)) < 0) {
				printf("Cannot write to file.\n");
				goto err_file2;
			}
			printf("Read %d bytes, written %d bytes.\n", read_bytes, sent_bytes);
		}
		bzero((void *) buffer, BUFSIZE);
	}
	/* Makes sure that when exiting, corresponding files, sockets and contexts are freed. */
	if (local)
		fclose(f_enc);
	fclose(f_src);
	gcry_md_close(md_hd);
	gcry_cipher_close(cipher_hd);
	if (snd) {
		close(sock_fd);
	}
	exit(EXIT_FAILURE);
	return 0;
	/* Makes sure that when exiting, corresponding files, sockets and contexts are freed. */
	err_file2:
		if (local)
			fclose(f_enc);
	err_file2_local:
		fclose(f_src);
	err_md:
		gcry_md_close(md_hd);
	err_crypt:
		gcry_cipher_close(cipher_hd);
	err_sock:
		if (snd) {
			close(sock_fd);
		}
		exit(EXIT_FAILURE);
}

