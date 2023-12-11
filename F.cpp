#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#define MAX_NONCE 10000000000

char* SHA256(const char* text) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, text, strlen(text));
    SHA256_Final(hash, &sha256);

    char* hashed_text = (char*)malloc((SHA256_DIGEST_LENGTH * 2 + 1) * sizeof(char));
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hashed_text[i * 2], "%02x", hash[i]);
    }

    return hashed_text;
}

char* mine(int block_number, const char* transactions, const char* previous_hash, int prefix_zeros) {
    char prefix_str[prefix_zeros + 1];
    memset(prefix_str, '0', prefix_zeros);
    prefix_str[prefix_zeros] = '\0';

    for (unsigned long long nonce = 0; nonce < MAX_NONCE; nonce++) {
        char text[256];
        snprintf(text, sizeof(text), "%d%s%s%llu", block_number, transactions, previous_hash, nonce);
        char* new_hash = SHA256(text);

        if (strncmp(new_hash, prefix_str, prefix_zeros) == 0) {
            printf("Cool! Successfully mined bitcoins with nonce value: %llu\n", nonce);
            return new_hash;
        }

        free(new_hash);
    }

    fprintf(stderr, "Sorry! Could not find it after trying %llu times\n", MAX_NONCE);
    exit(EXIT_FAILURE);
}

int main() {
    const char* transactions = "Baldur->John->20\nLara->Freya->45\n";
    int difficulty = 5;

    time_t start = time(NULL);
    printf("Start mining ... ⛏️\n");

    char* new_hash = mine(6, transactions, "aded354032d0a8e9d9c51995ed73b5a056d5ffe6", difficulty);
    
    double time_spent_on_mining = difftime(time(NULL), start);
    printf("Mining Terminated ⚒️  in %.2f seconds.\n", time_spent_on_mining);
    printf("%s\n", new_hash);

    free(new_hash);

    return EXIT_SUCCESS;
}
