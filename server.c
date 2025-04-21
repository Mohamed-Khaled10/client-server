#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <pthread.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_CREDENTIAL_LENGTH 256
#define CREDENTIALS_FILE "user_credentials.txt" // Define the credentials file
#define MAX_CONNECTIONS 10                         // Maximum number of concurrent connections

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
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_DigestUpdate(mdctx, password, strlen(password)) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_DigestFinal_ex(mdctx, hashed_password, NULL) != 1) {
        ERR_print_errors_fp(stderr);
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

// Function to authenticate the user
int authenticate_user(const char *username, const char *hashed_password_string) {
    FILE *fp;
    char file_username[BUFFER_SIZE];
    char file_hashed_password[MAX_CREDENTIAL_LENGTH];
    char line[BUFFER_SIZE * 2]; // Increased buffer size to handle long lines
    int authenticated = 0;

    fp = fopen(CREDENTIALS_FILE, "r");
    if (fp == NULL) {
        perror("Error opening credentials file");
        return -1; // Indicate an error
    }

    while (fgets(line, sizeof(line), fp) != NULL) { // Use sizeof(line)
        // Parse the line from the file
        if (sscanf(line, "%s %s", file_username, file_hashed_password) == 2) {
            // Remove newline characters if present
            file_username[strcspn(file_username, "\n")] = 0;
            file_hashed_password[strcspn(file_hashed_password, "\n")] = 0;

            if (strcmp(username, file_username) == 0 && strcmp(hashed_password_string, file_hashed_password) == 0) {
                authenticated = 1;
                break;
            }
        }
    }
    fclose(fp);
    return authenticated;
}

// Function to handle a single client connection
void *handle_client(void *client_socket_ssl) {
    SSL *ssl = (SSL *)client_socket_ssl;
    char buffer[BUFFER_SIZE] = {0};
    char username[BUFFER_SIZE];
    char hashed_password_string[MAX_CREDENTIAL_LENGTH]; // Receive hashed password as string
    int auth_result;
    int client_sock;

    // Detach the thread, so we don't need to join it later
    pthread_detach(pthread_self());

    if (ssl == NULL) {
        fprintf(stderr, "Error: ssl is NULL in handle_client\n");
        return NULL;
    }

    client_sock = SSL_get_fd(ssl);
    if (client_sock < 0) {
        fprintf(stderr, "Error: SSL_get_fd failed in handle_client\n");
        goto cleanup;
    }

    // Perform SSL handshake
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // Send "Username: " prompt to client
    if (SSL_write(ssl, "Username: ", strlen("Username: ")) <= 0) {
        perror("SSL_write (username prompt) failed");
        goto cleanup;
    }

    // Receive username from client
    memset(buffer, 0, BUFFER_SIZE);
    if (SSL_read(ssl, buffer, BUFFER_SIZE) <= 0) {
        perror("SSL_read (username) failed");
        goto cleanup;
    }
    strcpy(username, buffer);
    username[strcspn(username, "\n")] = 0; // Remove newline
    printf("Received username: %s\n", username);

    // Send "Password: " prompt to client
    if (SSL_write(ssl, "Password: ", strlen("Password: ")) <= 0) {
        perror("SSL_write (password prompt) failed");
        goto cleanup;
    }

    // Receive hashed password from client
    memset(buffer, 0, BUFFER_SIZE);
    if (SSL_read(ssl, buffer, BUFFER_SIZE) <= 0) {
        perror("SSL_read (password) failed");
        goto cleanup;
    }
    strcpy(hashed_password_string, buffer);
    hashed_password_string[strcspn(hashed_password_string, "\n")] = 0; // Remove newline
    printf("Received hashed password: %s\n", hashed_password_string);

    // Authenticate user
    auth_result = authenticate_user(username, hashed_password_string);
    if (auth_result == 1) {
        if (SSL_write(ssl, "Access Granted", strlen("Access Granted")) <= 0) {
            perror("SSL_write (access granted) failed");
            goto cleanup;
        }
        printf("Authentication successful\n");
    } else if (auth_result == 0) {
        if (SSL_write(ssl, "Access Denied", strlen("Access Denied")) <= 0) {
            perror("SSL_write (access denied) failed");
            goto cleanup;
        }
        printf("Authentication failed\n");
    } else {
        if (SSL_write(ssl, "Authentication Error", strlen("Authentication Error")) <= 0) {
            perror("SSL_write (auth error) failed");
            goto cleanup;
        }
        printf("Authentication error\n");
    }

    // Receive message from client
    memset(buffer, 0, BUFFER_SIZE);
    if (SSL_read(ssl, buffer, BUFFER_SIZE) <= 0) {
        perror("SSL_read (message) failed");
        goto cleanup;
    }
    printf("Received message from client: %s\n", buffer);

cleanup:
    // Close SSL connection and socket
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sock);
    }
    //  if (ctx != NULL) {  // Remove this line, it is already freed in main()
    //      SSL_CTX_free(ctx);
    //  }
    return NULL;
}

int main() {
    int sock, client_sock; // Declare client_sock here
    struct sockaddr_in server_address, client_address;
    socklen_t client_address_len;
    SSL_CTX *ctx;
    SSL *ssl;
    pthread_t thread_id;

    // Initialize SSL library
    if (SSL_library_init() != 1) {
        fprintf(stderr, "SSL_library_init failed\n");
        exit(EXIT_FAILURE);
    }
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create SSL context
    const SSL_METHOD *method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "/home/kali/server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "/home/kali/server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_check_private_key(ctx) <= 0) {
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

    // Bind socket to address
    if (bind(sock, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(sock, MAX_CONNECTIONS) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    // Accept connections in a loop
    while (1) {
        client_address_len = sizeof(client_address);
        client_sock = accept(sock, (struct sockaddr *)&client_address, &client_address_len);
        if (client_sock < 0) {
            perror("Accept failed");
            continue; // Go back to accepting connections
        }

        printf("Connection from %s:%d\n", inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));

        // Create SSL object
        ssl = SSL_new(ctx);
        if (ssl == NULL) {
            fprintf(stderr, "SSL_new failed\n");
            close(client_sock);
            continue;
        }
        SSL_set_fd(ssl, client_sock);

        // Create a thread to handle the client
        if (pthread_create(&thread_id, NULL, handle_client, ssl) != 0) {
            perror("pthread_create failed");
            SSL_free(ssl);
            close(client_sock);
            continue; // Go back to accepting connections
        }
        //ssl is passed to the thread
    }

    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}


