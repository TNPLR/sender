#include "csd.h"

#include <fcntl.h>

// Database
#include <gdbm.h>

static GDBM_FILE gdbm_data;
static GDBM_FILE gdbm_key;

static int init_msg_gdbm(void)
{
	gdbm_data = gdbm_open("data.mdg", 0, GDBM_NEWDB, O_RDWR | O_CREAT | O_TRUNC, NULL);
	if (gdbm_data == NULL) {
		printf("Cannot create data base: gdbm: %s\n", gdbm_strerror(gdbm_errno));
		return -1;
	}
	return 0;
}

static int init_key_gdbm(void)
{
	gdbm_key = gdbm_open("key.mdg", 0, GDBM_NEWDB, O_RDWR | O_CREAT | O_TRUNC, NULL);
	if (gdbm_key == NULL) {
		printf("Cannot create data base: gdbm: %s\n", gdbm_strerror(gdbm_errno));
		return -1;
	}
	return 0;
}

static void close_msg_gdbm(void)
{
	gdbm_close(gdbm_data);
}

static void close_key_gdbm(void)
{
	gdbm_close(gdbm_key);
}

static int store_key(char *name, size_t name_len, gcry_sexp_t pubkey)
{
	datum key_datum;
	datum data_datum;

	key_datum.dptr = name;
	key_datum.dsize = name_len;

	data_datum.dsize = get_arr_from_sexp((void **)&data_datum.dptr, pubkey);

	if (gdbm_store(gdbm_key, key_datum, data_datum, GDBM_REPLACE)) {
		free(data_datum.dptr);
		puts("Cannot store data");
		return -1;
	}
	gdbm_sync(gdbm_key);
	free(data_datum.dptr);
	return 0;
}

static int store_msg(struct message *m)
{
	datum key_datum;
	datum data_datum;

	key_datum.dptr = (void *)&m->msg_num;
	key_datum.dsize = sizeof m->msg_num;

	data_datum.dptr = (void *)m;
	data_datum.dsize = sizeof *m + m->msg_size;

	if (gdbm_store(gdbm_data, key_datum, data_datum, GDBM_REPLACE)) {
		puts("Cannot store data");
		return -1;
	}
	gdbm_sync(gdbm_data);
	return 0;
}

static int fetch_key(gcry_sexp_t *pub_key, char *name, size_t name_len)
{
	datum key_datum;
	datum data_datum;

	key_datum.dptr = name;
	key_datum.dsize = name_len;
	data_datum = gdbm_fetch(gdbm_key, key_datum);
	if (data_datum.dptr == NULL) {
		printf("Cannot fetch data: gdbm: %s\n", gdbm_strerror(gdbm_errno));
		return -1;
	}

	gcry_error_t err;
	err = gcry_sexp_new(pub_key, data_datum.dptr, data_datum.dsize, 0);
	if (err) {
		puts("Cannot generate pubkey from datun");
		return 1;
	}
	free(data_datum.dptr);
	return 0;
}

static datum fetch_msg(uint32_t msg_num)
{
	datum key_datum;
	datum data_datum;

	key_datum.dptr = (void *)&msg_num;
	key_datum.dsize = sizeof msg_num;
	data_datum = gdbm_fetch(gdbm_data, key_datum);
	if (data_datum.dptr == NULL) {
		printf("Cannot fetch data: gdbm: %s\n", gdbm_strerror(gdbm_errno));
	}
	return data_datum;
}

/* RSA Crypto */

static struct sockaddr_storage client;

static void serverlog(const char *msg)
{
	char buffer[32];
	time_t t = time(NULL);
	strftime(buffer, 32, "%Ec", gmtime(&t));
	printf("[%s] %s\n", buffer, msg);
}

static int send_server_msg(gcry_sexp_t pub_key, int socketfd)
{
	uint32_t count = 8;
	gdbm_count_t server_msg_count;
	if (gdbm_count(gdbm_data, &server_msg_count)) {
		puts("Cannot count record");
		return -1;
	}

	if ((gdbm_count_t)count > server_msg_count) {
		count = server_msg_count;
	}

	if (sendall(socketfd, &count, sizeof count, 0)) {
		serverlog("Cannot send count");
		return -1;
	}

	for (gdbm_count_t i = server_msg_count - count + 1; i <= server_msg_count; ++i) {
		datum buffer = fetch_msg(i);
		struct message *msg = (struct message *)buffer.dptr;
		if (msg == NULL) {
			assert(0);
		}
#if DEBUG == 2
		printf("%s:%d\n", msg->s, buffer.dsize);
#endif
		encrypt_and_send(socketfd, pub_key, privk, buffer.dptr, buffer.dsize);

		free(buffer.dptr);
	}

	return 0;
}

static int add_server_msg(int socketfd, gcry_sexp_t pubk)
{
	gdbm_count_t server_msg_count;
	if (gdbm_count(gdbm_data, &server_msg_count)) {
		puts("Cannot count record");
		return -1;
	}

	void *plain;
	size_t plain_size = receive_and_decrypt(socketfd, pubk, privk, &plain);
	if (plain_size == 0) {
		serverlog("Cannot receive or decrypt");
		return -1;
	}

	struct message *m = calloc(1, sizeof(struct message) + plain_size);
	m->msg_num = server_msg_count + 1;
	m->tm = time(NULL);
	m->msg_size = plain_size;
	memcpy(m->s, plain, plain_size);
	store_msg(m);
	free(m);

	serverlog(plain);
	gcry_free(plain);
	return 0;
}
/*
 * return value
 * 0 normal exit
 * 1 cannot receive the first magic number
 * 2 magic number wrong
 * 3 cannot send back magic
 */
static int handler(int socketfd)
{
	char buf[64];
	gcry_sexp_t pub_key;
	int ret_val;

	if (recvall(socketfd, buf, sizeof recv_magic, 0)) {
		serverlog("Cannot receive magic packet");
		ret_val = 1;
		goto cleanup;
	}

	if (memcmp(recv_magic, buf, sizeof recv_magic)) {
		serverlog("Recv magic not correct");
		ret_val = 2;
		goto cleanup;
	}

	if (sendall(socketfd, send_magic, sizeof send_magic, 0)) {
		serverlog("Cannot send Send magic");
		ret_val = 3;
		goto cleanup;
	}

	if (send_rsa_key(socketfd, pubk)) {
		serverlog("Cannot send rsa key");
		ret_val = 4;
		goto cleanup;
	}

	if (recv_rsa_key(socketfd, &pub_key)) {
		ret_val = 4;
		goto cleanup;
	}

	gcry_randomize(buf, 64, GCRY_VERY_STRONG_RANDOM);
	if (encrypt_and_send(socketfd, pub_key, privk, buf, 64)) {
		serverlog("Cannot send random message");
		ret_val = 8;
		goto cleanup;
	}

	void *back;
	size_t sz;
	if (!(sz = receive_and_decrypt(socketfd, pub_key, privk, &back))) {
		serverlog("Cannot receive random message");
		ret_val = 8;
		goto cleanup;
	}

	if (sz != 64 || memcmp(buf, back, 64)) {
		serverlog("Message wrong");
		ret_val = 8;
		goto cleanup;
	}

	while (1) {
		// Check Request type
		enum server_rq rq;
	
		if (recvall(socketfd, &rq, sizeof rq, 0)) {
			serverlog("Cannot receive command");
			ret_val = 5;
			goto cleanup;
		}

		switch (rq) {
		case GET_MSG:
			serverlog("GET_MSG");
			send_server_msg(pub_key, socketfd);
			break;
		case SEND_MSG:
			serverlog("SEND_MSG");
			add_server_msg(socketfd, pub_key);
			break;
		case END_OF_CMD:
			ret_val = 0;
			goto cleanup;
		}
	}

cleanup:
	serverlog("Disconnect");
	gcry_sexp_release(pub_key);
	gcry_free(back);
	shutdown(socketfd, 2);
	return ret_val;
}

static struct addrinfo *server;
static void clean_addrinfo(void)
{
	freeaddrinfo(server);
}
int receiver(void)
{
	if (init_msg_gdbm()) {
		return -1;
	}

	if (atexit(close_msg_gdbm)) {
		puts("Cannot load exit function");
		return -1;
	}

	struct addrinfo hints = {0};
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	int status;
	if ((status = getaddrinfo(NULL, LISTEN_PORT_STR, &hints, &server)) != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		return -1;
	}

	if (atexit(clean_addrinfo)) {
		puts("Cannot load exit function");
		return -1;
	}

	int socketfd = socket(server->ai_family, server->ai_socktype, server->ai_protocol);
	if (socketfd == -1) {
		puts("Cannot create socket");
		return -1;
	}

	if (bind(socketfd, server->ai_addr, server->ai_addrlen)) {
		puts("Could not bind address");
		return -1;
	}

	if (listen(socketfd, MAX_CONNECTION) == -1) {
		puts("Cannot listen socket");
		return -1;
	}

	int new_socket, c;
	c = sizeof(struct sockaddr_in);
	while ((new_socket = accept(socketfd, (struct sockaddr *)&client, (socklen_t *)&c))) {
		serverlog("New Connection");
		pid_t cpid = fork();
		if (cpid == 0) {
			close(socketfd);
			handler(new_socket);
			return 0;
		}
		close(new_socket);
	}
	return 0;
}
