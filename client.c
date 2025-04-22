#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sendfile.h>

#define PORT 8080
#define BUFFER_SIZE 4096
#define MAX_CREDENTIAL_LENGTH 256
#define CLIENT_FILE "client.txt"
#define SERVER_FILE "server.txt"

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

    // Wait for server acknowledgment
    SSL_read(ssl, buffer, BUFFER_SIZE);

    // Send file content
    size_t bytes_read;
    size_t total_sent = 0;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        SSL_write(ssl, buffer, bytes_read);
        total_sent += bytes_read;
        // Print progress
        printf("\rUploading: %.2f%%", (float)total_sent * 100 / file_size);
        fflush(stdout);
    }
    printf("\nUpload complete!\n");

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
        // Print progress
        printf("\rDownloading: %.2f%%", (float)total_received * 100 / file_size);
        fflush(stdout);
    }
    printf("\nDownload complete!\n");

    fclose(file);
    return 0;
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

    printf("SSL Connection established\n");

    // Receive "Username: " prompt from server
    SSL_read(ssl, buffer, BUFFER_SIZE);
    printf("%s", buffer);
    fgets(username, BUFFER_SIZE, stdin);
    username[strcspn(username, "\n")] = 0;
    SSL_write(ssl, username, strlen(username));

    // Receive "Password: " prompt from server
    memset(buffer, 0, BUFFER_SIZE);
    SSL_read(ssl, buffer, BUFFER_SIZE);
    printf("%s", buffer);
    fgets(password, BUFFER_SIZE, stdin);
    password[strcspn(password, "\n")] = 0;

    // Hash the password
    hash_password(password, hashed_password);
    hash_to_string(hashed_password, hashed_password_string);
    SSL_write(ssl, hashed_password_string, strlen(hashed_password_string));

    // Receive authentication result from server
    memset(buffer, 0, BUFFER_SIZE);
    SSL_read(ssl, buffer, BUFFER_SIZE);
    printf("%s\n", buffer);

    if (strstr(buffer, "Access Granted")) {
        SSL_write(ssl, "Client has entered the server", strlen("Client has entered the server"));
        
        // File transfer loop
        while (1) {
            char command[BUFFER_SIZE];
            
            printf("\nAvailable commands:\n");
            printf("UPLOAD - Upload client.txt to server\n");
            printf("DOWNLOAD - Download server.txt from server\n");
            printf("LIST - List available files\n");
            printf("CAT <filename> - Read file content\n");
            printf("DELETE <filename> - Delete a file\n");
            printf("EXIT - Close connection\n");
            printf("Enter command: ");
            
            fgets(command, BUFFER_SIZE, stdin);
            command[strcspn(command, "\n")] = 0;

            // Send command to server
            SSL_write(ssl, command, strlen(command));

            if (strncmp(command, "EXIT", 4) == 0) {
                printf("Closing connection...\n");
                break;
            } else if (strncmp(command, "UPLOAD", 6) == 0) {
                printf("Uploading %s...\n", CLIENT_FILE);
                if (send_file(ssl, CLIENT_FILE) == 0) {
                    printf("File uploaded successfully\n");
                } else {
                    printf("Failed to upload file\n");
                }
            } else if (strncmp(command, "DOWNLOAD", 8) == 0) {
                printf("Downloading %s...\n", SERVER_FILE);
                if (receive_file(ssl, SERVER_FILE) == 0) {
                    printf("File downloaded successfully\n");
                } else {
                    printf("Failed to download file\n");
                }
            } else if (strncmp(command, "LIST", 4) == 0) {
                // Receive and display file list
                memset(buffer, 0, BUFFER_SIZE);
                int bytes = SSL_read(ssl, buffer, BUFFER_SIZE);
                buffer[bytes] = '\0';
                printf("Files on server:\n%s", buffer);
            } else if (strncmp(command, "CAT", 3) == 0) {
                // Receive and display file content
                memset(buffer, 0, BUFFER_SIZE);
                int bytes = SSL_read(ssl, buffer, BUFFER_SIZE);
                buffer[bytes] = '\0';
                if (strstr(buffer, "Permission denied")) {
                    printf("Permission denied: You don't have permission to read files\n");
                } else if (strstr(buffer, "File not found")) {
                    printf("File not found\n");
                } else {
                    printf("File content:\n%s\n", buffer);
                }
            } else if (strncmp(command, "DELETE", 6) == 0) {
                // Receive delete operation result
                memset(buffer, 0, BUFFER_SIZE);
                int bytes = SSL_read(ssl, buffer, BUFFER_SIZE);
                buffer[bytes] = '\0';
                if (strstr(buffer, "Permission denied")) {
                    printf("Permission denied: You don't have permission to delete files\n");
                } else if (strstr(buffer, "Failed")) {
                    printf("Failed to delete file\n");
                } else {
                    printf("File deleted successfully\n");
                }
            } else {
                // Receive error message
                memset(buffer, 0, BUFFER_SIZE);
                int bytes = SSL_read(ssl, buffer, BUFFER_SIZE);
                buffer[bytes] = '\0';
                printf("Error: %s\n", buffer);
            }
        }
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
