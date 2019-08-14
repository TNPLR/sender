#ifndef CSD_H_
#define CSD_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// getopt
#include <unistd.h>

#include <sys/types.h>

#include <assert.h>
#include <stdalign.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <threads.h>
#include <stdatomic.h>
#include <stddef.h>
#include <signal.h>
#include <stdint.h>
#include <locale.h>

#include <sys/socket.h>
#include <sys/socket.h>
#include <netdb.h>

// inet_pton
#include <arpa/inet.h>

#include <gcrypt.h>

#include <ncurses.h>

#define LISTEN_PORT 2488
#define LISTEN_PORT_STR "2488"
#define MAX_CONNECTION 3
#define MAX_RECV_LEN 32768

#define MAGIC_BUF_SIZE 9

#define VERSION "0.1"

// inline function htonq and ntohq
static inline uint64_t htonq(uint64_t hostquad)
{
	return ((uint64_t)htonl((uint32_t)(hostquad >> 32) & 0xFFFFFFFFU) << 32) | htonl((uint32_t)hostquad & 0xFFFFFFFFU);
}

static inline uint64_t ntohq(uint64_t hostquad)
{
	return ((uint64_t)ntohl((uint32_t)(hostquad >> 32) & 0xFFFFFFFFU) << 32) | ntohl((uint32_t)hostquad & 0xFFFFFFFFU);
}
/*
 * TNPLR MESSAGE SENDER PROTOCOL
 * 1. TCP Client -> Server
 * 2. Client recv_magic -> Server
 * 3. Server send_magic -> Client
 * 4. Server PUBKEY -> Client
 * 5. Client PUBKEY -> Server
 *
 * *** From now on, RSA Crypto is used Except Request ***
 *
 */

enum server_rq {
	GET_MSG, // since num
	SEND_MSG, // size -> msg
	END_OF_CMD,
};

enum connect_pack_attr {
	NONE
};
struct connect_pack {
	alignas(8) size_t buffer_size;
	alignas(8) size_t signature_size;
	alignas(4) uint32_t attribute;
	char ch[];
};

#define USERNAME_MAX_LEN 32
struct message {
	uint32_t msg_num;
	char username[USERNAME_MAX_LEN];
	time_t tm;
	size_t msg_size;
	char s[];
};

// main.c
extern const char recv_magic[MAGIC_BUF_SIZE];
extern const char send_magic[MAGIC_BUF_SIZE];
extern const char message_done[MAGIC_BUF_SIZE];
extern enum pubkey_mode {
	NEW_REPLACE, NEW_INSERT, READONLY,
} key_mode;
extern gcry_sexp_t pubk;
extern gcry_sexp_t privk;

// util.c
int recvall(int socketfd, void *buf, size_t buf_size, int flags);
int sendall(int socketfd, const void *buf, size_t buf_size, int flags);
size_t recv_pack(int socketfd, void **buf, int flags);
size_t send_pack(int socketfd, const void *buf, size_t buf_size, int flags);

size_t get_arr_from_sexp(void **ptr, gcry_sexp_t sexp);

int keypair_generator(const char *file_pos);
int read_keypair(gcry_sexp_t *pubk, gcry_sexp_t *privk, const void *file_pos);
int recv_rsa_key(int socketfd, gcry_sexp_t *pubk_buf);
int send_rsa_key(int socketfd, gcry_sexp_t pub_key);
size_t receive_and_decrypt(int socketfd, gcry_sexp_t pub_key,
		gcry_sexp_t priv_key, void **plain);
int encrypt_and_send(int socketfd, gcry_sexp_t pub_key, gcry_sexp_t priv_key,
		const void *s, size_t msg_size);

// receiver.c
int receiver(void);

// client.c
int tui_client(const char *username, const char *saddr);
#endif // CSD_H_
