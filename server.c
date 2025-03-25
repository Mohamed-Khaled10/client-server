#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Function to check credentials from file
int check_credentials(char *username, char *password) {
    FILE *file = fopen("user_credentials.txt", "r");
    if (!file) {
        perror("Error opening credentials file");
        return 0;
    }

    char stored_user[BUFFER_SIZE], stored_pass[BUFFER_SIZE];
    while (fscanf(file, "%s %s", stored_user, stored_pass) != EOF) {
        if (strcmp(username, stored_user) == 0 && strcmp(password, stored_pass) == 0) {
            fclose(file);
            return 1; // Credentials matched
        }
    }

    fclose(file);
    return 0; // No match found
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    char username[BUFFER_SIZE], password[BUFFER_SIZE];

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Define server address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    // Accept client connection
    new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
    if (new_socket < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    // Request username
    send(new_socket, "Username: ", strlen("Username: "), 0);
    read(new_socket, username, BUFFER_SIZE);
    username[strcspn(username, "\n")] = 0; // Remove newline

    // Request password
    send(new_socket, "Password: ", strlen("Password: "), 0);
    read(new_socket, password, BUFFER_SIZE);
    password[strcspn(password, "\n")] = 0; // Remove newline

    // Check credentials
    if (check_credentials(username, password)) {
        send(new_socket, "Access Granted", strlen("Access Granted"), 0);
    } else {
        send(new_socket, "Authentication Failed", strlen("Authentication Failed"), 0);
    }

    // Receive client response
    memset(buffer, 0, BUFFER_SIZE);
    read(new_socket, buffer, BUFFER_SIZE);
    printf("Server: %s\n", buffer); // Print client's response

    // Close sockets
    close(new_socket);
    close(server_fd);

    return 0;
}
