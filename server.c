#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#define PORT 8080
#define BUFFER_SIZE 1024

SSL_CTX *ctx; // Global SSL context

// Function to hash passwords using SHA-256
void hash_password(const char *password, char *hashed_output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password, strlen(password), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hashed_output + (i * 2), "%02x", hash[i]);
    }
    hashed_output[SHA256_DIGEST_LENGTH * 2] = '\0';
}

// Check credentials from file
int check_credentials(const char *username, const char *password) {
    FILE *file = fopen("user_credentials.txt", "r");
    if (!file) {
        perror("Error opening credentials file");
        return 0;
    }

    char stored_user[BUFFER_SIZE], stored_hashed_pass[BUFFER_SIZE];
    char hashed_password[SHA256_DIGEST_LENGTH * 2 + 1];
    hash_password(password, hashed_password);

    while (fscanf(file, "%s %s", stored_user, stored_hashed_pass) != EOF) {
        if (strcmp(username, stored_user) == 0 && strcmp(hashed_password, stored_hashed_pass) == 0) {
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

// Thread function to handle each client
void *handle_client(void *socket_desc) {
    int client_sock = *(int*)socket_desc;
    char buffer[BUFFER_SIZE] = {0};
    char username[BUFFER_SIZE], password[BUFFER_SIZE];

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_sock);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_sock);
        return NULL;
    }

    SSL_write(ssl, "Username: ", strlen("Username: "));
    SSL_read(ssl, username, BUFFER_SIZE);
    username[strcspn(username, "\n")] = 0;

    SSL_write(ssl, "Password: ", strlen("Password: "));
    SSL_read(ssl, password, BUFFER_SIZE);
    password[strcspn(password, "\n")] = 0;

    if (check_credentials(username, password)) {
        SSL_write(ssl, "Access Granted", strlen("Access Granted"));
    } else {
        SSL_write(ssl, "Authentication Failed", strlen("Authentication Failed"));
    }

    memset(buffer, 0, BUFFER_SIZE);
    SSL_read(ssl, buffer, BUFFER_SIZE);
    printf("Server: %s\n", buffer);

    SSL_free(ssl);
    close(client_sock);
    return NULL;
}

int main() {
    int server_fd, client_sock;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    pthread_t thread_id;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("SSL Server listening on port %d...\n", PORT);

    while (1) {
        client_sock = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (client_sock < 0) {
            perror("Accept failed");
            exit(EXIT_FAILURE);
        }

        if (pthread_create(&thread_id, NULL, handle_client, (void*)&client_sock) < 0) {
            perror("Could not create thread");
            exit(EXIT_FAILURE);
        }

        pthread_detach(thread_id);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}

