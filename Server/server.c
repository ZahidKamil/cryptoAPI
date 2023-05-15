#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_fd, client_fd, addr_len, read_bytes;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE];

    // Create a socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    printf("Socket created\n");

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(PORT);

    // Bind the socket
    if (bind(server_fd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    printf("Socket bound\n");

    // Start listening
    if (listen(server_fd, 5) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    printf("Server listening\n");

    addr_len = sizeof(client_addr);

    // Continuously accept incoming connections
    while (1) {
        // Accept a client connection
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, (socklen_t *)&addr_len);
        if (client_fd < 0) {
            perror("accept failed");
            exit(EXIT_FAILURE);
        }
        printf("Client connected\n");

        // Read the message from the client
        memset(buffer, 0, BUFFER_SIZE);
        read_bytes = read(client_fd, buffer, BUFFER_SIZE);

        if (read_bytes < 0) {
            perror("read failed");
            close(client_fd);
            continue;
        } else if (read_bytes == 0) {
            printf("Client disconnected\n");
            close(client_fd);
            continue;
        }

        printf("Received message from client: %s\n", buffer);

        // Send message to the client
        char message[] = "Hello from the server!";
        write(client_fd, message, sizeof(message));
        printf("Message sent to the client\n");

        // Close the client socket
        close(client_fd);
    }

    // Close the server socket
    close(server_fd);

    return 0;
}

