#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "msg.h"
#define BUF 256


// Prototypes
void Usage(char *progname);
int LookupName(char *name,
               unsigned short port,
               struct sockaddr_storage *ret_addr,
               size_t *ret_addrlen);
int Connect(const struct sockaddr_storage *addr,
            const size_t addrlen,
            int *ret_fd);
void getCommand();


int main(int argc, char **argv)
{
  if (argc != 3)
  {
    Usage(argv[0]);
  }

  unsigned short port = 0;
  if (sscanf(argv[2], "%hu", &port) != 1)
  {
    Usage(argv[0]);
  }

  // Get an appropriate sockaddr structure.
  struct sockaddr_storage addr;
  size_t addrlen;
  if (!LookupName(argv[1], port, &addr, &addrlen))
  {
    Usage(argv[0]);
  }

  // Connect to the remote host.
  int socket_fd;
  if (!Connect(&addr, addrlen, &socket_fd))
  {
    Usage(argv[0]);
  }

  // Bytes read from server
  int res;

  struct record *rec = malloc(sizeof(struct record));
  struct msg *message = malloc(sizeof(struct msg));
  struct msg *returnedFromServer = malloc(sizeof(struct msg));
  // Write something to the remote host.
  while (1)
  {
    // first we write
    getCommand(rec, message);
    // printf("%s", message->rd.name);

    if (message->type == 0)
    {
      // quit
      break;
    }
    int wres = write(socket_fd, message, sizeof(struct msg));

    if (wres == 0)
    {
      printf("socket closed prematurely \n");
      close(socket_fd);
      return EXIT_FAILURE;
    }
    if (wres == -1)
    {
      if (errno == EINTR)
        continue;
      printf("socket write failure \n");
      close(socket_fd);
      return EXIT_FAILURE;
    }

    // Read from server
    res = read(socket_fd, returnedFromServer, sizeof(struct msg));
    
    // Error Check
    if (res == 0)
    {
      printf("socket closed prematurely \n");
      close(socket_fd);
      return EXIT_FAILURE;
    }
    if (res == -1)
    {
      if (errno == EINTR)
        continue;
      printf("socket read failure \n");
      close(socket_fd);
      return EXIT_FAILURE;
    }
 
    // If Operation success
    if (returnedFromServer->type == SUCCESS)
    {
      // Check which operation, then print appropriate stuff
      if (message->type == PUT)
      {
        printf("Put success.");
      }
      else if (message->type == GET)
      {
        printf("name: %s\n", returnedFromServer->rd.name);
        printf("id: %d\n", returnedFromServer->rd.id);
      }
    }
    // If operation fail
    else if (returnedFromServer->type == FAIL)
    {
      // Check which operation, then print appropriate stuff
      if (message->type == PUT)
      {
        printf("Put Failed.");
      }
      else if (message->type == GET)
      {
        printf("Get failed");
      }
    }
    else
    {
      perror("something was wrong");
    }
  }

  // Clean up
  free(rec);
  free(message);


  close(socket_fd);
  return EXIT_SUCCESS;
}

// Retrieve command from console
void getCommand(struct record *rec, struct msg *message)
{
  
  int command;

  // Check if command is right, else keep prompting
  while (1)
  {
    printf("\nEnter your choice (1 to put, 2 to get, 0 to quit): ");
    scanf("%d", &command);

    if (command >= 0 && command <= 2)
    {
      break;
    }
  }

  // If quit
  if (command == 0)
  {
    exit(EXIT_SUCCESS);
  }


  char *name = NULL;
  size_t size;
  getline(&name, &size, stdin); 

  // If put, get info
  if (command == 1)
  {
    printf("\nEnter the name: ");
    int len = getline(&name, &size, stdin);

    name[len - 1] = '\0';

    strcpy(rec->name, name);
  }

  printf("Enter id: ");
  int id;
  scanf("%d", &id);
  getline(&name, &size, stdin);


  // Assign vals
  rec->id = id;
  message->rd = *rec;
  message->type = command;
}



void Usage(char *progname)
{
  printf("usage: %s  hostname port \n", progname);
  exit(EXIT_FAILURE);
}

int LookupName(char *name,
               unsigned short port,
               struct sockaddr_storage *ret_addr,
               size_t *ret_addrlen)
{
  struct addrinfo hints, *results;
  int retval;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  // Do the lookup by invoking getaddrinfo().
  if ((retval = getaddrinfo(name, NULL, &hints, &results)) != 0)
  {
    printf("getaddrinfo failed: %s", gai_strerror(retval));
    return 0;
  }

  // Set the port in the first result.
  if (results->ai_family == AF_INET)
  {
    struct sockaddr_in *v4addr =
        (struct sockaddr_in *)(results->ai_addr);
    v4addr->sin_port = htons(port);
  }
  else if (results->ai_family == AF_INET6)
  {
    struct sockaddr_in6 *v6addr =
        (struct sockaddr_in6 *)(results->ai_addr);
    v6addr->sin6_port = htons(port);
  }
  else
  {
    printf("getaddrinfo failed to provide an IPv4 or IPv6 address \n");
    freeaddrinfo(results);
    return 0;
  }

  // Return the first result.
  assert(results != NULL);
  memcpy(ret_addr, results->ai_addr, results->ai_addrlen);
  *ret_addrlen = results->ai_addrlen;

  // Clean up.
  freeaddrinfo(results);
  return 1;
}

int Connect(const struct sockaddr_storage *addr,
            const size_t addrlen,
            int *ret_fd)
{
  // Create the socket.
  int socket_fd = socket(addr->ss_family, SOCK_STREAM, 0);
  if (socket_fd == -1)
  {
    printf("socket() failed: %s", strerror(errno));
    return 0;
  }

  // Connect the socket to the remote host.
  int res = connect(socket_fd,
                    (const struct sockaddr *)(addr),
                    addrlen);
  if (res == -1)
  {
    printf("connect() failed: %s", strerror(errno));
    return 0;
  }

  *ret_fd = socket_fd;
  return 1;
}
