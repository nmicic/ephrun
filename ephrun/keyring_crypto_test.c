/*
 * Copyright (c) 2025 Nenad Micic <nenad@micic.be>
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file for details.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <keyutils.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define MAX_KEY_SIZE 256
#define BUFFER_SIZE 1024
#define IV_SIZE 16

// Function to find key by description
key_serial_t find_key_by_desc(const char* description) {
    key_serial_t key_id;
    
    // Try user keyring first
    key_id = keyctl_search(KEY_SPEC_USER_KEYRING, "user", description, 0);
    if (key_id != -1) {
        printf("Found key in user keyring: %d\n", key_id);
        return key_id;
    }
    
    // Try session keyring
    key_id = keyctl_search(KEY_SPEC_SESSION_KEYRING, "user", description, 0);
    if (key_id != -1) {
        printf("Found key in session keyring: %d\n", key_id);
        return key_id;
    }
    
    return -1;
}

// Function to read key from keyring
int read_key_from_keyring(key_serial_t key_id, unsigned char* key_buffer, size_t* key_size) {
    long ret;
    
    // First, get the key size
    ret = keyctl_read(key_id, NULL, 0);
    if (ret < 0) {
        perror("keyctl_read (size check)");
        return -1;
    }
    
    if (ret > MAX_KEY_SIZE) {
        fprintf(stderr, "Key too large: %ld bytes (max %d)\n", ret, MAX_KEY_SIZE);
        return -1;
    }
    
    // Now read the actual key
    ret = keyctl_read(key_id, (char*)key_buffer, ret);
    if (ret < 0) {
        perror("keyctl_read (actual read)");
        return -1;
    }
    
    *key_size = ret;
    printf("Successfully read key: %zu bytes\n", *key_size);
    
    return 0;
}

// AES encryption function
int aes_encrypt(const unsigned char* plaintext, int plaintext_len,
                const unsigned char* key, const unsigned char* iv,
                unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int ciphertext_len;
    
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;
    
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// AES decryption function
int aes_decrypt(const unsigned char* ciphertext, int ciphertext_len,
                const unsigned char* key, const unsigned char* iv,
                unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintext_len;
    
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// Test crypto operations with the key
int test_crypto_operations(const unsigned char* key, size_t key_size) {
    // Test data
    const char* test_message = "Hello, this is a test message for encryption with keyring key!";
    unsigned char iv[IV_SIZE];
    unsigned char ciphertext[BUFFER_SIZE];
    unsigned char decryptedtext[BUFFER_SIZE];
    int ciphertext_len, decryptedtext_len;
    
    printf("\n=== Crypto Operations Test ===\n");
    printf("Original message: %s\n", test_message);
    printf("Message length: %zu bytes\n", strlen(test_message));
    
    // Generate random IV
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        fprintf(stderr, "Failed to generate IV\n");
        return -1;
    }
    
    printf("Generated IV: ");
    for (size_t i = 0; i < IV_SIZE; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");
    
    // Use first 32 bytes of key for AES-256 (or pad if smaller)
    unsigned char aes_key[32];
    memset(aes_key, 0, sizeof(aes_key));
    
    if (key_size >= 32) {
        memcpy(aes_key, key, 32);
    } else {
        memcpy(aes_key, key, key_size);
        // Simple key stretching - repeat the key
        for (size_t i = key_size; i < 32; i++) {
            aes_key[i] = key[i % key_size];
        }
    }
    
    // Encrypt
    ciphertext_len = aes_encrypt((unsigned char*)test_message, strlen(test_message),
                                 aes_key, iv, ciphertext);
    if (ciphertext_len < 0) {
        fprintf(stderr, "Encryption failed\n");
        return -1;
    }
    
    printf("Encryption successful. Ciphertext length: %d bytes\n", ciphertext_len);
    printf("Ciphertext (hex): ");
    for (size_t i = 0; i < (size_t)ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    
    // Decrypt
    decryptedtext_len = aes_decrypt(ciphertext, ciphertext_len,
                                   aes_key, iv, decryptedtext);
    if (decryptedtext_len < 0) {
        fprintf(stderr, "Decryption failed\n");
        return -1;
    }
    
    // Null terminate the decrypted text
    decryptedtext[decryptedtext_len] = '\0';
    
    printf("Decryption successful. Decrypted length: %d bytes\n", decryptedtext_len);
    printf("Decrypted message: %s\n", (char*)decryptedtext);
    
    // Verify
    if (strcmp(test_message, (char*)decryptedtext) == 0) {
        printf("✓ Encryption/Decryption test PASSED!\n");
        return 0;
    } else {
        printf("✗ Encryption/Decryption test FAILED!\n");
        return -1;
    }
}

int main(int argc, char* argv[]) {
    key_serial_t key_id;
    unsigned char key_buffer[MAX_KEY_SIZE];
    size_t key_size;
    
    printf("=== Keyring Crypto Test Program ===\n");
    
    // Initialize OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    
    if (argc > 1) {
        // Use provided key ID
        key_id = atoi(argv[1]);
        printf("Using provided key ID: %d\n", key_id);
    } else {
        // Search for key by description
        const char* key_desc = "elfdec:prod/hello";
        printf("Searching for key with description: %s\n", key_desc);
        
        key_id = find_key_by_desc(key_desc);
        if (key_id == -1) {
            fprintf(stderr, "Key not found. Make sure to run add_keyring script first.\n");
            fprintf(stderr, "Usage: %s [key_id]\n", argv[0]);
            return 1;
        }
    }
    
    printf("Using key ID: %d\n", key_id);
    
    // Test key existence and get info
    char* desc = NULL;
    if (keyctl_describe_alloc(key_id, &desc) < 0) {
        perror("keyctl_describe_alloc");
        fprintf(stderr, "Failed to describe key %d. Key may not exist or be accessible.\n", key_id);
        return 1;
    }
    
    printf("Key description: %s\n", desc);
    free(desc);
    
    // Read the key from keyring
    if (read_key_from_keyring(key_id, key_buffer, &key_size) != 0) {
        fprintf(stderr, "Failed to read key from keyring\n");
        return 1;
    }
    
    // Perform crypto operations
    printf("\n");
    for (int i = 0; i < 50; i++) printf("=");
    printf("\n");
    printf("Running cryptographic tests...\n");
    for (int i = 0; i < 50; i++) printf("=");
    printf("\n");
    
    if (test_crypto_operations(key_buffer, key_size) != 0) {
        fprintf(stderr, "Crypto operations failed\n");
        return 1;
    }
    
    // Clear sensitive data
    memset(key_buffer, 0, sizeof(key_buffer));
    
    printf("\n");
    for (int i = 0; i < 50; i++) printf("=");
    printf("\n");
    printf("✓ All tests completed successfully!\n");
    
    // Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}
