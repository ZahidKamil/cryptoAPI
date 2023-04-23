#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>


#define PORT "8080"
#define MESSAGE "Hello from client pod\n"

int main() {
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    time_t t;
    char *server_service_host;

    server_service_host = getenv("SERVER_SERVICE_HOST");
    if (server_service_host == NULL) {
        fprintf(stderr, "SERVER_SERVICE_HOST environment variable not set.\n");
        exit(EXIT_FAILURE);
    }
    printf("The server service host is: %s\n", server_service_host);

    while (1) {
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if ((rv = getaddrinfo(server_service_host, PORT, &hints, &servinfo)) != 0) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
            exit(1);
        }

        for (p = servinfo; p != NULL; p = p->ai_next) {
            sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (sockfd == -1) {
                perror("client: socket");
                continue;
            }

            if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
                close(sockfd);
                perror("client: connect");
                continue;
            }

            break;
        }

        if (p == NULL) {
            fprintf(stderr, "client: failed to connect\n");
            sleep(5);
            continue;
        }

        printf("Connected to the server...\n");

        char message[] = "Hello from the client!";
        write(sockfd, message, sizeof(message));
        printf("Message sent to the server...\n");

        freeaddrinfo(servinfo);
        close(sockfd);
        sleep(5);
    }

    return 0;
}
