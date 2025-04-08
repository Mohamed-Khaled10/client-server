#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int sock;
    struct sockaddr_in server_address;
    SSL_CTX *ctx;
    SSL *ssl;
    char buffer[BUFFER_SIZE] = {0};
    char username[BUFFER_SIZE], password[BUFFER_SIZE];

    // Initialize SSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create SSL context
    const SSL_METHOD *method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

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

    // Create SSL object
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Receive "Username: " prompt from server
    SSL_read(ssl, buffer, BUFFER_SIZE);
    printf("%s", buffer);
    fgets(username, BUFFER_SIZE, stdin);
    // Remove newline character from username
    username[strcspn(username, "\n")] = 0;
    // Send username to server
    SSL_write(ssl, username, strlen(username));

    // Receive "Password: " prompt from server
    memset(buffer, 0, BUFFER_SIZE);
    SSL_read(ssl, buffer, BUFFER_SIZE);
    printf("%s", buffer);
    fgets(password, BUFFER_SIZE, stdin);
    // Remove newline character from password
    password[strcspn(password, "\n")] = 0;
    // Send password to server
    SSL_write(ssl, password, strlen(password));

    // Receive authentication result from server
    memset(buffer, 0, BUFFER_SIZE);
    SSL_read(ssl, buffer, BUFFER_SIZE);
    printf("%s\n", buffer);

    // Send appropriate message based on authentication result
    if (strstr(buffer, "Access Granted")) {
        SSL_write(ssl, "Client has entered the server", strlen("Client has entered the server"));
    } else {
        SSL_write(ssl, "Client entered wrong credentials", strlen("Client entered wrong credentials"));
    }

    // Close SSL connection and socket
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return 0;
}
