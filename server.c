#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <dirent.h>
#include <time.h>

#define PORT 8080
#define BUFFER_SIZE 4096
#define MAX_CREDENTIAL_LENGTH 256
#define CREDENTIALS_FILE "user_credentials.txt"
#define MAX_CONNECTIONS 10
#define RECEIVED_DIR "received_files"
#define SERVER_FILE "server.txt"
#define LOG_FILE "server_log.txt"

// Mutex for thread-safe logging
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function to write to log file
void write_log(const char *username, const char *action) {
    pthread_mutex_lock(&log_mutex);
    
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now = time(NULL);
        char *timestamp = ctime(&now);
        timestamp[strlen(timestamp) - 1] = '\0'; // Remove newline
        fprintf(log_file, "[%s] User '%s': %s\n", timestamp, username, action);
        fclose(log_file);
    }
    
    pthread_mutex_unlock(&log_mutex);
}

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
    char line[BUFFER_SIZE * 2];
    int authenticated = 0;

    fp = fopen(CREDENTIALS_FILE, "r");
    if (fp == NULL) {
        perror("Error opening credentials file");
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "%s %s", file_username, file_hashed_password) == 2) {
            file_username[strcspn(file_username, "\n")] = 0;
            file_hashed_password[strcspn(file_hashed_password, "\n")] = 0;

            if (strcmp(username, file_username) == 0 && 
                strcmp(hashed_password_string, file_hashed_password) == 0) {
                authenticated = 1;
                break;
            }
        }
    }
    fclose(fp);
    return authenticated;
}

// Function to send a file
int send_file(SSL *ssl, const char *filename) {
    char buffer[BUFFER_SIZE];
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return -1;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Send file size
    sprintf(buffer, "%ld", file_size);
    SSL_write(ssl, buffer, strlen(buffer));

    // Wait for client acknowledgment
    SSL_read(ssl, buffer, BUFFER_SIZE);

    // Send file content
    size_t bytes_read;
    size_t total_sent = 0;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        SSL_write(ssl, buffer, bytes_read);
        total_sent += bytes_read;
        printf("\rSending: %.2f%%", (float)total_sent * 100 / file_size);
        fflush(stdout);
    }
    printf("\nSend complete!\n");

    fclose(file);
    return 0;
}

// Function to receive a file
int receive_file(SSL *ssl, const char *filename) {
    char buffer[BUFFER_SIZE];
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Error creating file");
        return -1;
    }

    // Receive file size
    int bytes = SSL_read(ssl, buffer, BUFFER_SIZE);
    buffer[bytes] = '\0';
    long file_size = atol(buffer);

    // Send acknowledgment
    SSL_write(ssl, "OK", 2);

    // Receive file content
    long total_received = 0;
    while (total_received < file_size) {
        bytes = SSL_read(ssl, buffer, BUFFER_SIZE);
        if (bytes <= 0) break;
        fwrite(buffer, 1, bytes, file);
        total_received += bytes;
        printf("\rReceiving: %.2f%%", (float)total_received * 100 / file_size);
        fflush(stdout);
    }
    printf("\nReceive complete!\n");

    fclose(file);
    return 0;
}

// Function to list files
void list_files(SSL *ssl) {
    char file_list[BUFFER_SIZE] = "";
    
    // Add server.txt to the list
    strcat(file_list, "server.txt\n");
    
    // List files in received_files directory
    DIR *dir = opendir(RECEIVED_DIR);
    if (dir != NULL) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_type == DT_REG) { // Regular file
                strcat(file_list, RECEIVED_DIR);
                strcat(file_list, "/");
                strcat(file_list, ent->d_name);
                strcat(file_list, "\n");
            }
        }
        closedir(dir);
    }
    
    SSL_write(ssl, file_list, strlen(file_list));
}

// Function to handle a single client connection
void *handle_client(void *client_socket_ssl) {
    SSL *ssl = (SSL *)client_socket_ssl;
    char buffer[BUFFER_SIZE] = {0};
    char username[BUFFER_SIZE];
    char hashed_password_string[MAX_CREDENTIAL_LENGTH];
    int auth_result;
    int client_sock;

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
    username[strcspn(username, "\n")] = 0;
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
    hashed_password_string[strcspn(hashed_password_string, "\n")] = 0;

    // Authenticate user
    auth_result = authenticate_user(username, hashed_password_string);
    if (auth_result == 1) {
        if (SSL_write(ssl, "Access Granted", strlen("Access Granted")) <= 0) {
            perror("SSL_write (access granted) failed");
            goto cleanup;
        }
        write_log(username, "Authentication successful");
        printf("Authentication successful for user: %s\n", username);

        // Handle file transfer commands
        while (1) {
            memset(buffer, 0, BUFFER_SIZE);
            int bytes = SSL_read(ssl, buffer, BUFFER_SIZE);
            if (bytes <= 0) break;

            buffer[bytes] = '\0';
            printf("Received command from %s: %s\n", username, buffer);

            if (strncmp(buffer, "EXIT", 4) == 0) {
                write_log(username, "Disconnected");
                break;
            } else if (strncmp(buffer, "UPLOAD", 6) == 0) {
                char filepath[BUFFER_SIZE];
                snprintf(filepath, sizeof(filepath), "%s/%s_client.txt", RECEIVED_DIR, username);
                if (receive_file(ssl, filepath) == 0) {
                    write_log(username, "Uploaded file successfully");
                    printf("File received from %s\n", username);
                } else {
                    write_log(username, "Failed to upload file");
                }
            } else if (strncmp(buffer, "DOWNLOAD", 8) == 0) {
                if (send_file(ssl, SERVER_FILE) == 0) {
                    write_log(username, "Downloaded file successfully");
                    printf("File sent to %s\n", username);
                } else {
                    write_log(username, "Failed to download file");
                }
            } else if (strncmp(buffer, "LIST", 4) == 0) {
                list_files(ssl);
                write_log(username, "Listed files");
            }
        }
    } else if (auth_result == 0) {
        if (SSL_write(ssl, "Access Denied", strlen("Access Denied")) <= 0) {
            perror("SSL_write (access denied) failed");
            goto cleanup;
        }
        write_log(username, "Authentication failed");
        printf("Authentication failed for user: %s\n", username);
    } else {
        if (SSL_write(ssl, "Authentication Error", strlen("Authentication Error")) <= 0) {
            perror("SSL_write (auth error) failed");
            goto cleanup;
        }
        write_log(username, "Authentication error");
        printf("Authentication error for user: %s\n", username);
    }

cleanup:
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sock);
    }
    return NULL;
}

int main() {
    int sock, client_sock;
    struct sockaddr_in server_address, client_address;
    socklen_t client_address_len;
    SSL_CTX *ctx;
    SSL *ssl;
    pthread_t thread_id;

    // Create received files directory if it doesn't exist
    mkdir(RECEIVED_DIR, 0755);

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
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
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

    while (1) {
        client_address_len = sizeof(client_address);
        client_sock = accept(sock, (struct sockaddr *)&client_address, &client_address_len);
        if (client_sock < 0) {
            perror("Accept failed");
            continue;
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        // Create new thread for client
        if (pthread_create(&thread_id, NULL, handle_client, ssl) < 0) {
            perror("Could not create thread");
            SSL_free(ssl);
            close(client_sock);
            continue;
        }
    }

    SSL_CTX_free(ctx);
    close(sock);
    return 0;
}
