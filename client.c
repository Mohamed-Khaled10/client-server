#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int sock;
    struct sockaddr_in server_address;
    char buffer[BUFFER_SIZE] = {0};
    char username[BUFFER_SIZE], password[BUFFER_SIZE];

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Define server address
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY;

    // Connect to server
    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // Receive "Username: " prompt
    read(sock, buffer, BUFFER_SIZE);
    printf("%s", buffer);
    fgets(username, BUFFER_SIZE, stdin);
    send(sock, username, strlen(username), 0);

    // Receive "Password: " prompt
    memset(buffer, 0, BUFFER_SIZE);
    read(sock, buffer, BUFFER_SIZE);
    printf("%s", buffer);
    fgets(password, BUFFER_SIZE, stdin);
    send(sock, password, strlen(password), 0);

    // Receive authentication result
    memset(buffer, 0, BUFFER_SIZE);
    read(sock, buffer, BUFFER_SIZE);
    printf("%s\n", buffer);

    // Send appropriate message to server
    if (strstr(buffer, "Access Granted")) {
        send(sock, "Client has entered the server", strlen("Client has entered the server"), 0);
    } else {
        send(sock, "Client entered wrong credentials", strlen("Client entered wrong credentials"), 0);
    }

    // Close socket
    close(sock);

    return 0;
}
