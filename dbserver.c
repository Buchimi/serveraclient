#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include "common_threads.h"
#include "msg.h"
void Usage(char *progname);
void PrintOut(int fd, struct sockaddr *addr, size_t addrlen);
void PrintReverseDNS(struct sockaddr *addr, size_t addrlen);
void PrintServerSide(int client_fd, int sock_family);
int Listen(char *portnum, int *sock_family);
void *HandleClient(void *args);
int get(int32_t fd, struct record *s);
ssize_t put(int32_t fd, struct record s);

struct threadFnArgs
{
  int c_fd;
  struct sockaddr *addr;
  size_t addrlen;
  int sock_family
};

int main(int argc, char **argv)
{
  // Expect the port number as a command line argument.
  if (argc != 2)
  {
    Usage(argv[0]);
  }

  int sock_family;
  int listen_fd = Listen(argv[1], &sock_family);
  if (listen_fd <= 0)
  {
    // We failed to bind/listen to a socket.  Quit with failure.
    printf("Couldn't bind to any addresses.\n");
    return EXIT_FAILURE;
  }

  // Loop forever, accepting a connection from a client and doing
  // an echo trick to it.
  while (1)
  {
    struct sockaddr_storage caddr;
    socklen_t caddr_len = sizeof(caddr);
    int client_fd = accept(listen_fd,
                           (struct sockaddr *)(&caddr),
                           &caddr_len);
    if (client_fd < 0)
    {
      if ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))
        continue;
      printf("Failure on accept:%d \n ", strerror(errno));
      break;
    }
    // create a new thread
    pthread_t thread;
    struct threadFnArgs *args = malloc(sizeof(struct threadFnArgs));
    args->c_fd = client_fd;
    args->sock_family = sock_family;
    args->addrlen = caddr_len;
    args->addr = (struct sockaddr *)(&caddr);
    Pthread_create(&thread, NULL, HandleClient, args);

    // HandleClient(client_fd,
    //              (struct sockaddr *)(&caddr),
    //              caddr_len,
    //              sock_family);
  }

  // Close socket
  close(listen_fd);
  return EXIT_SUCCESS;
}
// struct threadFnArgs* createArgs(struct threadFnArgs* args){
//   args->addr
// }

void Usage(char *progname)
{
  printf("usage: %s port \n", progname);
  exit(EXIT_FAILURE);
}

int Listen(char *portnum, int *sock_family)
{

  // Populate the "hints" addrinfo structure for getaddrinfo().
  // ("man addrinfo")
  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;       // IPv6 (also handles IPv4 clients)
  hints.ai_socktype = SOCK_STREAM; // stream
  hints.ai_flags = AI_PASSIVE;     // use wildcard "in6addr_any" address
  hints.ai_flags |= AI_V4MAPPED;   // use v4-mapped v6 if no v6 found
  hints.ai_protocol = IPPROTO_TCP; // tcp protocol
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  // getaddrinfo() returns a list of
  // address structures via the output parameter "result".
  struct addrinfo *result;
  int res = getaddrinfo(NULL, portnum, &hints, &result);

  // Did addrinfo() fail?
  if (res != 0)
  {
    printf("getaddrinfo failed: %s", gai_strerror(res));
    return -1;
  }

  // Loop through the returned address structures until we are able
  // to create a socket and bind to one.  The address structures are
  // linked in a list through the "ai_next" field of result.
  int listen_fd = -1;
  struct addrinfo *rp;
  for (rp = result; rp != NULL; rp = rp->ai_next)
  {
    listen_fd = socket(rp->ai_family,
                       rp->ai_socktype,
                       rp->ai_protocol);
    if (listen_fd == -1)
    {
      // Creating this socket failed.  So, loop to the next returned
      // result and try again.
      printf("socket() failed:%d \n ", strerror(errno));
      listen_fd = -1;
      continue;
    }

    // Configure the socket; we're setting a socket "option."  In
    // particular, we set "SO_REUSEADDR", which tells the TCP stack
    // so make the port we bind to available again as soon as we
    // exit, rather than waiting for a few tens of seconds to recycle it.
    int optval = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR,
               &optval, sizeof(optval));

    // Try binding the socket to the address and port number returned
    // by getaddrinfo().
    if (bind(listen_fd, rp->ai_addr, rp->ai_addrlen) == 0)
    {
      // Bind worked!  Print out the information about what
      // we bound to.
      // PrintOut(listen_fd, rp->ai_addr, rp->ai_addrlen);

      // Return to the caller the address family.
      *sock_family = rp->ai_family;
      break;
    }

    // The bind failed.  Close the socket, then loop back around and
    // try the next address/port returned by getaddrinfo().
    close(listen_fd);
    listen_fd = -1;
  }

  // Free the structure returned by getaddrinfo().
  freeaddrinfo(result);

  // If we failed to bind, return failure.
  if (listen_fd == -1)
    return listen_fd;

  // Success. Tell the OS that we want this to be a listening socket.
  if (listen(listen_fd, SOMAXCONN) != 0)
  {
    printf("Failed to mark socket as listening:%d \n ", strerror(errno));
    close(listen_fd);
    return -1;
  }

  // Return to the client the listening file descriptor.
  return listen_fd;
}

void *HandleClient(void *argu)
{
  // void HandleClient(int c_fd, struct sockaddr *addr, size_t addrlen,
  //                 int sock_family)
  struct threadFnArgs *args = (struct threadFnArgs *)argu;

  int c_fd = args->c_fd;
  struct sockaddr *addr = args->addr;
  size_t addrlen = args->addrlen;
  int sock_family = args->sock_family;

  // Print out information about the client.
  printf("\nNew client connection \n");
  PrintOut(c_fd, addr, addrlen);
  PrintReverseDNS(addr, addrlen);
  PrintServerSide(c_fd, sock_family);

  // Loop, reading data and echo'ing it back, until the client
  // closes the connection.
  while (1)
  {
    char clientbuf[1024];
    ssize_t res = read(c_fd, clientbuf, 1023);
    if (res == 0)
    {
      printf("[The client disconnected.] \n");
      Pthread_exit(NULL);
      break;
    }

    if (res == -1)
    {
      if ((errno == EAGAIN) || (errno == EINTR))
        continue;

      printf(" Error on client socket:%d \n ", strerror(errno));

      break;
    }
    clientbuf[res] = '\0';
    struct msg *clientMessage = (struct msg *)clientbuf;
    uint32_t id;
    char *name;

    if (clientMessage->type == 0)
    {
      printf("quitting");
    }
    return;

    grabNameAndID(&id, name, clientMessage);
    int fileDes = open("db", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);

    if (fileDes == -1)
    {
      free(args);
      perror("couldn't create file");
      break;
    }
    if (clientMessage->type == PUT)
    {
      ssize_t result = put(fileDes, clientMessage->rd);
      struct msg *response = malloc(sizeof(struct msg));

      if (result == -1)
      {
        response->type = FAIL;
      }
      else
      {
        response->type = SUCCESS;
      }
      write(c_fd, response, sizeof(response));
      free(response);
      printf("putting");
    }
    else if (clientMessage->type == GET)
    {

      struct msg *response = malloc(sizeof(struct msg));

      int result = get(c_fd, &(clientMessage->rd));

      if (result == -1)
      {
        response->type == FAIL;
      }
      else
      {
        response->type == SUCCESS;
        response->rd = clientMessage->rd;
        write(c_fd, response, sizeof(response));
      }
      free(response);
      printf("getting");
    }

    else
    {
      // invalid message type
      char response[] = "invalid message";
      struct msg *res = malloc(sizeof(struct msg));
      res->type = FAIL;
      strcpy(res->rd.name, response);
      write(c_fd, res, sizeof(res));
      free(res);
      continue;
    }

    printf("the client sent: %s \n", clientbuf);

    // Really should do this in a loop in case of EAGAIN, EINTR,
    // or short write, but I'm lazy.  Don't be like me. ;)
    write(c_fd, "You typed: ", strlen("You typed: "));
    write(c_fd, clientbuf, strlen(clientbuf));
  }
  free(args);
  close(c_fd);
  pthread_exit(NULL);
}

void grabNameAndID(uint32_t *id, char name[], struct msg *clientMessage)
{
  *id = clientMessage->rd.id;
  name = clientMessage->rd.name;
}

int get(int32_t fd, struct record *s)
{

  // WRITE THE CODE to seek to the appropriate offset in fd
  // The record index may be out of bounds. If so,
  // print appropriate message and return
  int fileSize = lseek(fd, 0, SEEK_END);
  int index = lseek(fd, sizeof(struct record) * s->id, 0);

  if (index > fileSize)
  {
    perror("Index does not exist");
    return;
  }

  // WRITE THE CODE to read record s from fd
  // If the record has not been put already, print appropriate message
  // and return

  int res = read(fd, s, sizeof(s));
  if (s->name == '\0')
  {
    perror("No user");
    return -1;
  }
  return res;
}

ssize_t put(int32_t fd, struct record s)
{

  lseek(fd, s.id * sizeof(struct record), SEEK_SET);
  return write(fd, &s, sizeof(struct record));
}

void PrintOut(int fd, struct sockaddr *addr, size_t addrlen)
{
  printf("Socket [%d] is bound to: \n", fd);
  if (addr->sa_family == AF_INET)
  {
    // Print out the IPV4 address and port

    char astring[INET_ADDRSTRLEN];
    struct sockaddr_in *in4 = (struct sockaddr_in *)(addr);
    inet_ntop(AF_INET, &(in4->sin_addr), astring, INET_ADDRSTRLEN);
    printf(" IPv4 address %s", astring);
    printf(" and port %d\n", ntohs(in4->sin_port));
  }
  else if (addr->sa_family == AF_INET6)
  {
    // Print out the IPV6 address and port

    char astring[INET6_ADDRSTRLEN];
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)(addr);
    inet_ntop(AF_INET6, &(in6->sin6_addr), astring, INET6_ADDRSTRLEN);
    printf("IPv6 address %s", astring);
    printf(" and port %d\n", ntohs(in6->sin6_port));
  }
  else
  {
    printf(" ???? address and port ???? \n");
  }
}

void PrintReverseDNS(struct sockaddr *addr, size_t addrlen)
{
  char hostname[1024]; // ought to be big enough.
  if (getnameinfo(addr, addrlen, hostname, 1024, NULL, 0, 0) != 0)
  {
    sprintf(hostname, "[reverse DNS failed]");
  }
  printf("DNS name: %s \n", hostname);
}

void PrintServerSide(int client_fd, int sock_family)
{
  char hname[1024];
  hname[0] = '\0';

  printf("Server side interface is ");
  if (sock_family == AF_INET)
  {
    // The server is using an IPv4 address.
    struct sockaddr_in srvr;
    socklen_t srvrlen = sizeof(srvr);
    char addrbuf[INET_ADDRSTRLEN];
    getsockname(client_fd, (struct sockaddr *)&srvr, &srvrlen);
    inet_ntop(AF_INET, &srvr.sin_addr, addrbuf, INET_ADDRSTRLEN);
    printf("%s", addrbuf);
    // Get the server's dns name, or return it's IP address as
    // a substitute if the dns lookup fails.
    getnameinfo((const struct sockaddr *)&srvr,
                srvrlen, hname, 1024, NULL, 0, 0);
    printf(" [%s]\n", hname);
  }
  else
  {
    // The server is using an IPv6 address.
    struct sockaddr_in6 srvr;
    socklen_t srvrlen = sizeof(srvr);
    char addrbuf[INET6_ADDRSTRLEN];
    getsockname(client_fd, (struct sockaddr *)&srvr, &srvrlen);
    inet_ntop(AF_INET6, &srvr.sin6_addr, addrbuf, INET6_ADDRSTRLEN);
    printf("%s", addrbuf);
    // Get the server's dns name, or return it's IP address as
    // a substitute if the dns lookup fails.
    getnameinfo((const struct sockaddr *)&srvr,
                srvrlen, hname, 1024, NULL, 0, 0);
    printf(" [%s]\n", hname);
  }
}
