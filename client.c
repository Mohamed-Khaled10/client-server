#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_CREDENTIAL_LENGTH 256

// Function to hash the password using SHA256
void hash_password(const char *password, unsigned char *hashed_password) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_get_digestbyname("SHA256");
    if (!md) {
        fprintf(stderr, "SHA256 algorithm not found\n");
        exit(EXIT_FAILURE);
    }
    if (!mdctx) {
        fprintf(stderr, "Error creating digest context\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        fprintf(stderr, "Error initializing digest\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_DigestUpdate(mdctx, password, strlen(password)) != 1) {
        fprintf(stderr, "Error updating digest\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_DigestFinal_ex(mdctx, hashed_password, NULL) != 1) {
        fprintf(stderr, "Error finalizing digest\n");
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(mdctx);
}

// Function to convert the hashed password to a string
void hash_to_string(const unsigned char *hash, char *hash_string) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_string + (i * 2), "%02x", hash[i]);
    }
    hash_string[SHA256_DIGEST_LENGTH * 2] = '\0';
}

int main() {
    int sock;
    struct sockaddr_in server_address;
    SSL_CTX *ctx;
    SSL *ssl;
    char buffer[BUFFER_SIZE] = {0};
    char username[BUFFER_SIZE], password[BUFFER_SIZE];
    unsigned char hashed_password[SHA256_DIGEST_LENGTH];
    char hashed_password_string[SHA256_DIGEST_LENGTH * 2 + 1];

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
    if (inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        exit(EXIT_FAILURE);
    }

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

    // Hash the password
    hash_password(password, hashed_password);
    hash_to_string(hashed_password, hashed_password_string);
    // Send the hashed password string to the server
    SSL_write(ssl, hashed_password_string, strlen(hashed_password_string));

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
