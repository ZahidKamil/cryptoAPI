#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../microECC/uECC.h"

#include "../opt32/crypto_aead.h"
#include "../sha/rfc6234/sha.h"
#include <time.h>

// gcc server.c ../microECC/uECC.c ../opt32/aead.c ../sha/rfc6234/*.c -o bob
#define PORT 8080
#define BUFFER_SIZE 1024

#define IDENTIFIER_LEN 16
#define uECC_BYTES 32
#define SECRET_LEN 32
#define TIMESTAMP sizeof(uint32_t)
#define PREKEY_BUNDLE_SIZE TIMESTAMP + 2*uECC_BYTES + 2*uECC_BYTES + 2*uECC_BYTES + (uECC_BYTES+1)
#define AD_LEN 4*uECC_BYTES
#define MAX_CT_LEN 40
#define SIZE_TO_BOB MAX_CT_LEN + 2*uECC_BYTES + 2*uECC_BYTES +sizeof(double)

void vli_print(uint8_t *vli, unsigned int size) {
    for(unsigned i=0; i<size; ++i) {
        printf("%02X ", (unsigned)vli[i]);
    }
}

void get_shared_key(unsigned char *dh_final, int ikm_len, SHAversion whichSha, const unsigned char *salt, int salt_len, const unsigned char *info,
     int info_len, uint8_t* output_key, int okm_len){
    // int salt_len; //The length of the salt value (a non-secret random value) (ignored if SALT==NULL)
    // int info_len; // The length of optional context and application (ignored if info==NULL)
    // int ikm_len; //The length of the input keying material

    // printf("%d\n", ikm_len);
    if(salt == NULL) salt_len = 0;
    if(info == NULL) info_len = 0;


    if(hkdf(whichSha,salt,salt_len,dh_final,ikm_len,info,info_len,output_key,okm_len) != 0)
    {
        fprintf(stderr, "\nHKDF is invalid\n");
    }
}


void hex_encode(const uint8_t *input, size_t input_len, uint8_t *output) {
    const char hex_chars[] = "0123456789ABCDEF";
    for (size_t i = 0; i < input_len; ++i) {
        uint8_t value = input[i];
        output[i * 2] = hex_chars[value >> 4];
        output[i * 2 + 1] = hex_chars[value & 0x0F];
    }
    output[input_len * 2] = '\0'; // Null-terminate the output string
}

void generate_key_bundle(const uint8_t* bob_id_public_key, const uint8_t* bob_spk_public_key, const uint8_t* bob_spk_signature, 
                         const uint8_t* bob_spk_compress_key, uint8_t* prekey_bundle)
{
    // uint32_t timestamp_start = (uint32_t)time(NULL);
    // // TIMESTAMP + 2*uECC_BYTES + 2*uECC_BYTES + 2*uECC_BYTES + (uECC_BYTES+1)
    // memcpy(prekey_bundle, &timestamp_start, TIMESTAMP);
    memcpy(prekey_bundle, bob_id_public_key, 2*uECC_BYTES);
    memcpy(prekey_bundle + 2*uECC_BYTES, bob_spk_public_key, 2*uECC_BYTES);
    memcpy(prekey_bundle + 2*uECC_BYTES + 2*uECC_BYTES , bob_spk_signature, 2*uECC_BYTES);
    memcpy(prekey_bundle + 2*uECC_BYTES + 2*uECC_BYTES + 2*uECC_BYTES, bob_spk_compress_key, uECC_BYTES+1);
}

void extract_from_alice(const uint8_t* bundle, uint8_t* ciphertext_alice, unsigned long long* ct_len, uint8_t* test_alice_public, 
                        uint8_t* test_alice_ephemeral, double* time_in_alice)
{
    memcpy(ciphertext_alice, bundle, MAX_CT_LEN);
    memcpy(ct_len, bundle + MAX_CT_LEN, sizeof(unsigned long long));
    memcpy(test_alice_public, bundle + MAX_CT_LEN + sizeof(unsigned long long), 2*uECC_BYTES);
    memcpy(test_alice_ephemeral, bundle + MAX_CT_LEN + sizeof(unsigned long long) + 2*uECC_BYTES, 2*uECC_BYTES);
    memcpy(time_in_alice, bundle + MAX_CT_LEN + sizeof(unsigned long long) + 2*uECC_BYTES + 2*uECC_BYTES, sizeof(double));
}

typedef enum SECPVersion {
    SECP160r1, SECP192r1, SECP224r1, SECP256r1, SECP256k1
}SECPVersion;

uECC_Curve SecpCurve(enum SECPVersion whichSecp)
{
    switch(whichSecp){
        case SECP160r1: return uECC_secp160r1();
        case SECP192r1: return uECC_secp192r1();
        case SECP224r1: return uECC_secp224r1();
        case SECP256r1: return uECC_secp256r1();
        default:
        case SECP256k1: return uECC_secp256k1();
    }
}

int custom_rng(uint8_t *dest, unsigned size) {
    for (unsigned i = 0; i < size; ++i) {
        dest[i] = (uint8_t) rand();
    }
    return 1; // Return 1 if the random data was generated successfully
}

int main() {
    int server_fd, client_fd, addr_len, read_bytes;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE];

    // Create a socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    printf("Socket created\n");

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(PORT);

    // Bind the socket
    if (bind(server_fd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    printf("Socket bound\n");

    // Start listening
    if (listen(server_fd, 5) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    printf("Server listening\n");

    addr_len = sizeof(client_addr);

    // Continuously accept incoming connections
    while (1) {
        // Accept a client connection
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, (socklen_t *)&addr_len);
        if (client_fd < 0) {
            perror("accept failed");
            exit(EXIT_FAILURE);
        }
        printf("Client connected\n");

        // Read the message from the client
        memset(buffer, 0, BUFFER_SIZE);
        read_bytes = read(client_fd, buffer, BUFFER_SIZE);

        if (read_bytes < 0) {
            perror("read failed");
            close(client_fd);
            continue;
        } else if (read_bytes == 0) {
            printf("Client disconnected\n");
            close(client_fd);
            continue;
        }

        printf("Received message from client: %s\n", buffer);

        // Send message to the client
        char message[] = "Hello from the server!";
        write(client_fd, message, sizeof(message));
        printf("Message sent to the client\n");


        uint8_t bob_spk_private_key[uECC_BYTES] = {0};
        uint8_t bob_id_private_key[uECC_BYTES] = {0};

        uint32_t timestamp_at_bob;
        uint32_t timestamp_end_bob;

        uint8_t bob_id_public_key[uECC_BYTES*2] = {0};
        uint8_t bob_spk_public_key[uECC_BYTES*2] = {0};
        uint8_t bob_spk_signature[uECC_BYTES*2] = {0};
        uint8_t bob_spk_compress_key[uECC_BYTES+1] = {0};

        uint8_t test_alice_public[uECC_BYTES*2] = {0};
        uint8_t test_alice_ephemeral[uECC_BYTES*2] = {0};

        uint8_t dh1_bob[SECRET_LEN] = {0};
        uint8_t dh2_bob[SECRET_LEN] = {0};
        uint8_t dh3_bob[SECRET_LEN] = {0};

        uint8_t dh_final_bob[96];

        uint8_t hex_hkdf_output_alice[128]; 
        uint8_t hex_hkdf_output_bob[128]; 
        uint8_t prekey_bundle[PREKEY_BUNDLE_SIZE] = {0};

        // Hexadecimal encoding buffers for the authentication tag
        uint8_t test_alice_public_key_hex[uECC_BYTES*2 + 1] = {0};
        uint8_t bob_id_public_key_hex[uECC_BYTES*2 + 1] = {0};
        uint8_t ad_bob[AD_LEN] = {0};

        uint8_t alice_to_bob[SIZE_TO_BOB] = {0};

        uint8_t ct_from_alice[MAX_CT_LEN] = {0}; 
        unsigned char decrypted[MAX_CT_LEN]; // Output buffer for decrypted message
        unsigned long long decrypted_len = MAX_CT_LEN; // Length of the decrypted message
        unsigned char nonce_bob[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        // Seed the random number generator
        srand((unsigned) time(NULL));

        // Set the custom RNG function
        uECC_set_rng(custom_rng);

        uECC_Curve curves = uECC_secp256k1();

        /************************************************************************************************************************
         * GENERATING KEY PAIRS */
        //Generate SignedPreKey Pair for bob 
        if (!uECC_make_key(bob_spk_public_key, bob_spk_private_key, curves)) {
            printf("uECC_make_key() failed\n");
            return 1;
        }
        //Generating long-term Identity Key pair for Bob
        if (!uECC_make_key(bob_id_public_key, bob_id_private_key, curves)) {
            printf("uECC_make_key() failed\n");
            return 1;
        }

        /************************************************************************************************************************
         * SIGNING AND VERIFYING KEYS */
        if (!uECC_sign(bob_id_private_key, bob_spk_public_key, sizeof(bob_spk_public_key), bob_spk_signature, curves)) {
            printf("uECC_sign() failed\n");
            return 1;
        }

        if (!uECC_verify(bob_id_public_key, bob_spk_public_key, sizeof(bob_spk_public_key), bob_spk_signature, curves)) {
            printf("Bob's prekey signature is valid.\n");
            return 1;
        }
        uECC_compress(bob_spk_public_key, bob_spk_compress_key,curves);
        generate_key_bundle(bob_id_public_key, bob_spk_public_key, bob_spk_signature, bob_spk_compress_key, prekey_bundle);

        write(client_fd, prekey_bundle, PREKEY_BUNDLE_SIZE);
        printf("Sending prekey bundle\n");

        /****************************************************************************************************************
         * RECEIVING FROM ALICE
        */
        double time_diff_alice_to_bob;
        unsigned long long ct_from_alice_len = MAX_CT_LEN;

        memset(alice_to_bob, 0, SIZE_TO_BOB);
        read_bytes = read(client_fd, alice_to_bob, SIZE_TO_BOB);

        if (read_bytes < 0) {
            perror("read failed");
            close(client_fd);
            continue;
        } else if (read_bytes == 0) {
            printf("Client disconnected\n");
            close(client_fd);
            continue;
        }

        printf("Received AEAD from Alice\n");

        extract_from_alice(alice_to_bob, ct_from_alice, &ct_from_alice_len, test_alice_public, test_alice_ephemeral, &time_diff_alice_to_bob);
        timestamp_at_bob = (uint32_t)time(NULL);

        /************************************************************************************************************************
             * COMPUTING DH EXCHANGES FOR BOB */
            //DH1 = DH(IKA, SPKB)
            if (!uECC_shared_secret(test_alice_public, bob_spk_private_key, dh1_bob, curves)) {
                printf("shared_secret(1) failed (2)\n");
                return 1;
            }
            //DH2 = DH(EKA, IKB)
            if (!uECC_shared_secret(test_alice_ephemeral, bob_id_private_key, dh2_bob, curves)) {
                printf("shared_secret(2) failed (2)\n");
                return 1;
            }
            //DH3 = DH(EKA, SPKB)
            if (!uECC_shared_secret(test_alice_ephemeral, bob_spk_private_key, dh3_bob, curves)) {
                printf("shared_secret(3) failed (2)\n");
                return 1;
            }

            //Concatenating all the diffie-helman exchanges for Bob
            for(int j=0; j<96;j++)
            {
                if(j<32) dh_final_bob[j] = dh1_bob[j]; 
                if(j>=32 && j< 64)  dh_final_bob[j] = dh2_bob[j%32]; 
                if(j>=64)  dh_final_bob[j] = dh3_bob[j%32]; 
            }

            /******************************************************************************
             * AUTHENTICATION TAG FOR BOB
            */
            // hex_encode(test_alice_public, 2*uECC_BYTES, test_alice_public_key_hex);
            // hex_encode(bob_id_public_key, 2*uECC_BYTES, bob_id_public_key_hex);
            memcpy(ad_bob, test_alice_public, 2*uECC_BYTES);
            memcpy(ad_bob + 2*uECC_BYTES, bob_id_public_key, 2*uECC_BYTES);

            /************************************************************************************************************************
             * OBTAINING THE SYMMETRIC KEY FOR BOB */

            get_shared_key(dh_final_bob, 96, SHA256, NULL, 0, NULL, 0, hex_hkdf_output_bob, 128);

            /******************************************************************************
             * SYMMETRIC KEY DECRYPTION FOR BOB
            */

            // Decryption
            uint8_t decrypted_check[MAX_CT_LEN] = {0};
            unsigned long long decrypted_len_check = MAX_CT_LEN; 
            int ret = crypto_aead_decrypt(
                decrypted_check, &decrypted_len_check, NULL, ct_from_alice, ct_from_alice_len, ad_bob, AD_LEN, nonce_bob, hex_hkdf_output_bob
            );

            if (ret == 0) {
                printf("Decrypted Message: %.*s\n", (int)decrypted_len_check, decrypted_check);
            } else {
                printf("Decryption failed\n");
                return 1;
            }
            printf("At end\n");
            timestamp_end_bob = (uint32_t)time(NULL);
            double time_diff_in_bob = difftime(timestamp_end_bob, timestamp_at_bob);
            printf("Total time: %0.3f\n", time_diff_alice_to_bob + time_diff_in_bob);


        // Close the client socket
        close(client_fd);
    }

    // Close the server socket
    close(server_fd);

    return 0;
}

