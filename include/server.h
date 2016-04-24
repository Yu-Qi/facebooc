#ifndef SERVER_H
#define SERVER_H

#ifndef MAX_EVENTS
#define MAX_EVENTS 64
#endif

#include "list.h"
#include "request.h"
#include "response.h"

typedef struct Server {
    unsigned int port;

    ListCell *handlers;
} Server;

typedef struct t_data{
	int fd;
	int epfd;
	struct sockaddr_in *addr;
	Server *server;
}t_data;

typedef Response *(*Handler)(Request *);
typedef Response *(**HandlerP)(Request *);

Server *serverNew(unsigned int);
int make_socket_non_blocking (int sfd);
int set_fd_polling(int queue, int fd, int action, long milliseconds);
void    serverDel(Server *);
void    serverAddHandler(Server *, Handler);
void    serverAddStaticHandler(Server *);
void    serverServe(Server *);

#endif
