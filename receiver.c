#include "csd.h"

/* RSA Crypto */

static struct sockaddr_storage client;
static FILE *ftmp;
static void close_tmp(void)
{
	fclose(ftmp);
}

static void serverlog(const char *msg)
{
	char buffer[32];
	time_t t = time(NULL);
	strftime(buffer, 32, "%Ec", gmtime(&t));
	printf("[%s] %s\n", buffer, msg);
}

// Message format:
// Message Time
// Message Size
// Message
// Message Size
// send to client
static int send_server_msg(gcry_sexp_t pub_key, int socketfd, int since)
{
	fseek(ftmp, 0, SEEK_SET);
	int server_msg_count;
	fread(&server_msg_count, sizeof server_msg_count, 1, ftmp);
	for (int i = 0; i < since; ++i) {
		fseek(ftmp, sizeof(time_t), SEEK_CUR);
		size_t msg_size;

		fread(&msg_size, sizeof msg_size, 1, ftmp);
		fseek(ftmp, msg_size + sizeof msg_size, SEEK_CUR);
	}

	while (since < server_msg_count) {
		time_t t;
		fread(&t, sizeof t, 1, ftmp);

		size_t msg_size;
		fread(&msg_size, sizeof msg_size, 1, ftmp);

		void *buffer = calloc(1, msg_size + sizeof t + 1);
		if (buffer == NULL) {
			serverlog("Cannot alloc memory");
			return -1;
		}

		*(time_t *)buffer = t;

		fread((char *)buffer + sizeof t, msg_size, 1, ftmp);
		encrypt_and_send(pub_key, privk, socketfd, msg_size + sizeof t + 1, buffer);
		fseek(ftmp, sizeof msg_size, SEEK_CUR);
		free(buffer);
		++since;
	}
	encrypt_and_send(pub_key, privk, socketfd, sizeof message_done, message_done);
	return 0;
}

static int add_server_msg(int socketfd, gcry_sexp_t pubk)
{
	fseek(ftmp, 0, SEEK_SET);
	int server_msg_count;
	fread(&server_msg_count, sizeof server_msg_count, 1, ftmp);
	for (int i = 0; i < server_msg_count; ++i) {
		fseek(ftmp, sizeof(time_t), SEEK_CUR);
		size_t msg_size;
		fread(&msg_size, sizeof msg_size, 1, ftmp);
		fseek(ftmp, msg_size + sizeof msg_size, SEEK_CUR);
	}
	void *plain;
	size_t plain_size = receive_and_decrypt(socketfd, pubk, privk, &plain);
	if (plain_size == 0) {
		serverlog("Cannot receive or decrypt");
		return -1;
	}
	++server_msg_count;

	time_t t = time(NULL);
	fwrite(&t, sizeof t, 1, ftmp);
	fwrite(&plain_size, sizeof plain_size, 1, ftmp);
	fwrite(plain, plain_size, 1, ftmp);
	fwrite(&plain_size, sizeof plain_size, 1, ftmp);

	fseek(ftmp, 0, SEEK_SET);
	fwrite(&server_msg_count, sizeof server_msg_count, 1, ftmp);
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
	char buf[MAGIC_BUF_SIZE];
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

	if (send_rsa_key(pubk, socketfd)) {
		serverlog("Cannot send rsa key");
		ret_val = 4;
		goto cleanup;
	}

	if (recv_rsa_key(&pub_key, socketfd)) {
		ret_val = 4;
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

		int since;
		switch (rq) {
		case GET_MSG:
			serverlog("GET_MSG");
			if (recvall(socketfd, &since, sizeof since, 0)) {
				serverlog("Cannot receive since num");
				ret_val = 6;
				goto cleanup;
			}
			send_server_msg(pub_key, socketfd, since);
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

	ftmp = fopen("receiver.msg", "wb+");
	if (ftmp == NULL) {
		puts("Cannot create tmp file");
		return -1;
	}

	if (atexit(close_tmp)) {
		puts("Cannot load exit function");
		return -1;
	}

	int server_msg_count = 0;
	fwrite(&server_msg_count, sizeof server_msg_count, 1, ftmp);

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
		puts("New Connection");
		pid_t cpid = fork();
		if (cpid == 0) {
			close(socketfd);
			handler(new_socket);
			return 0;
		}
		close(new_socket);
	}
	fclose(ftmp);
	return 0;
}
