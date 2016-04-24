#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "bs.h"
#include "server.h"

#define GET_TIME                                  \
    time_t t = time(NULL);                        \
    char timebuff[100];                           \
    strftime(timebuff, sizeof(timebuff),          \
             "%c", localtime(&t));

#define LOG_400(addr)                             \
    do {                                          \
        GET_TIME;                                 \
        fprintf(stdout,                           \
                "%s %s 400\n",                    \
                timebuff,                         \
                inet_ntoa(addr->sin_addr));       \
    } while (0)

#define LOG_REQUEST(addr, method, path, status)   \
    do {                                          \
        GET_TIME;                                 \
        fprintf(stdout,                           \
                "%s %s %s %s %d\n",               \
                timebuff,                         \
                inet_ntoa(addr->sin_addr),        \
                method,                           \
                path,                             \
                status);                          \
    } while (0)

char *METHODS[8] = {
    "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT"
};

Server *serverNew(unsigned int port)
{
    Server *server = malloc(sizeof(Server));
    server->port = port;
    server->handlers = NULL;
    return server;
}

void serverDel(Server *server)
{
    if (server->handlers) listDel(server->handlers);
    free(server);
}

void serverAddHandler(Server *server, Handler handler)
{
    HandlerP handlerP = &handler;
    server->handlers = listCons(handlerP, sizeof(HandlerP), server->handlers);
}

static Response *staticHandler(Request *req)
{
    ROUTE(req, "/static/");

    // EXIT ON SHENANIGANS
    if (strstr(req->uri, "../")) return NULL;

    char *filename = req->uri + 1;

    // EXIT ON DIRS
    struct stat sbuff;

    if (stat(filename, &sbuff) < 0 || S_ISDIR(sbuff.st_mode))
        return NULL;

    // EXIT ON NOT FOUND
    FILE *file = fopen(filename, "r");
    if (!file) return NULL;

    // GET LENGTH
    char *buff;
    char  lens[25];
    size_t len;

    fseek(file, 0, SEEK_END);
    len = ftell(file);
    sprintf(lens, "%ld", len);
    rewind(file);

    // SET BODY
    Response *response = responseNew();

    buff = malloc(sizeof(char) * len);
    fread(buff, sizeof(char), len, file);
    responseSetBody(response, bsNewLen(buff, len));
    fclose(file);
    free(buff);

    // MIME TYPE
    char *mimeType = "text/plain";

    len = bsGetLen(req->uri);

    if (!strncmp(req->uri + len - 4, "html", 4)) mimeType = "text/html";
    else if (!strncmp(req->uri + len - 4, "json", 4)) mimeType = "application/json";
    else if (!strncmp(req->uri + len - 4, "jpeg", 4)) mimeType = "image/jpeg";
    else if (!strncmp(req->uri + len - 3,  "jpg", 3)) mimeType = "image/jpeg";
    else if (!strncmp(req->uri + len - 3,  "gif", 3)) mimeType = "image/gif";
    else if (!strncmp(req->uri + len - 3,  "png", 3)) mimeType = "image/png";
    else if (!strncmp(req->uri + len - 3,  "css", 3)) mimeType = "text/css";
    else if (!strncmp(req->uri + len - 2,   "js", 2)) mimeType = "application/javascript";

    // RESPOND
    responseSetStatus(response, OK);
    responseAddHeader(response, "Content-Type", mimeType);
    responseAddHeader(response, "Content-Length", lens);
    responseAddHeader(response, "Cache-Control", "max-age=2592000");
    return response;
}

void serverAddStaticHandler(Server *server)
{
    serverAddHandler(server, staticHandler);
}

static inline int makeSocket(unsigned int port)
{
    int sock = socket(PF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;

    if (sock < 0) {
        fprintf(stderr, "error: failed to create socket\n");
        exit(1);
    }

    {
        int optval = 1; /* prevent from address being taken */
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    }

    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        fprintf(stderr, "error: failed to bind socket to 0.0.0.0:%d\n", port);
        exit(1);
    }
    //if (make_socket_non_blocking (sock) == -1)
     //   exit(1);

    if (listen(sock, SOMAXCONN) < 0) {
        fprintf(stderr, "error: socket failed to listen\n");
        exit(1);
    }

    return sock;
}

static inline void handle(Server *server, int fd, int epfd, struct sockaddr_in *addr)
{
    int  nread;
    char buff[20480];

    if ((nread = read(fd, buff, sizeof(buff))) < 0) {
        fprintf(stderr, "error: read failed\n");
    } else if (nread > 0) {
        buff[nread] = '\0';
        Request *req = requestNew(buff);

        if (!req) {
            write(fd, "HTTP/1.0 400 Bad Request\r\n\r\nBad Request", 39);
            LOG_400(addr);
        } else {
            ListCell *handler  = server->handlers;
            Response *response = NULL;

            while (handler && !response) {
                response = (*(HandlerP)handler->value)(req);
                handler  = handler->next;
            }

            if (!response) {
                write(fd, "HTTP/1.0 404 Not Found\r\n\r\nNot Found!", 36);
                LOG_REQUEST(addr, METHODS[req->method], req->path, 404);
            } else {
                LOG_REQUEST(addr, METHODS[req->method], req->path,
                            response->status);

                responseWrite(response, fd);
                responseDel(response);
            }

            requestDel(req);
        }
    }
    set_fd_polling(epfd, fd, EPOLL_CTL_DEL, 0) ; 
    close(fd);
    pthread_exit(NULL);
}

void serverServe(Server *server)
{
    int sock = makeSocket(server->port);
    int newSock;

    socklen_t size;

    int epfd = epoll_create1(0);

    struct sockaddr_in addr;

    set_fd_polling(epfd, sock,
                          EPOLL_CTL_ADD, 0);


    fprintf(stdout, "Listening on port %d.\n\n", server->port);

    struct epoll_event chevent;
    struct epoll_event *events;

    chevent.data.fd = sock;
  
    chevent.events = EPOLLOUT | EPOLLIN |
                     EPOLLET | EPOLLERR |
                     EPOLLRDHUP | EPOLLHUP;
                
    events = calloc (MAX_EVENTS, sizeof chevent);

    for (;;) {
        int active_count = epoll_wait(epfd, events, MAX_EVENTS, 0) ;
        if (active_count < 0 ){
             fprintf(stderr, "error: failed to epoll\n");
            exit(1);           
        } 
        else{
            for (int i = 0; i < active_count; i++){

                if( events[i].events &  (~(EPOLLIN | EPOLLOUT) ) ){
                    set_fd_polling(epfd, events[i].data.fd, EPOLL_CTL_DEL, 0) ;    
                    close( events[i].data.fd);
                    continue;
                }
                else if( sock == events[i].data.fd){
                    size    = sizeof(addr);
                    newSock = accept(sock, (struct sockaddr *) &addr, &size);
                    if(newSock == -1){
                        if ((errno == EAGAIN) ||
                          (errno == EWOULDBLOCK))
                            break;
                    }
                    //make_socket_non_blocking(newSock);
                    set_fd_polling(epfd, newSock, EPOLL_CTL_ADD, 0);
                }
                
                else{ 
                    if(events[i].events & EPOLLOUT ){
                        handle(server, events[i].data.fd, epfd, &addr);
                    }
                }

            }
        }

    }

}

// todo
int set_fd_polling(int queue, int fd, int action, long milliseconds)
{
    struct epoll_event chevent;
    chevent.data.fd = fd;
    chevent.events = EPOLLOUT | EPOLLIN |
                     EPOLLET | EPOLLERR |
                     EPOLLRDHUP | EPOLLHUP;
    /*
    if (milliseconds) {
        struct itimerspec newtime;
        newtime.it_value.tv_sec = newtime.it_interval.tv_sec =
                                  milliseconds / 1000;
        newtime.it_value.tv_nsec = newtime.it_interval.tv_nsec =
                                  (milliseconds % 1000) * 1000000;
        timerfd_settime(fd, 0, &newtime, NULL);
    }*/
    return epoll_ctl(queue, action, fd, &chevent);
}
int make_socket_non_blocking (int sfd)
{
  int flags, s;

  flags = fcntl (sfd, F_GETFL, 0);
  if (flags == -1)
    {
      perror ("fcntl");
      return -1;
    }

  flags |= O_NONBLOCK;
  s = fcntl (sfd, F_SETFL, flags);
  if (s == -1)
    {
      perror ("fcntl");
      return -1;
    }

  return 0;
}