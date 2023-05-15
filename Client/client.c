#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include "../microECC/uECC.h"

#include "../opt32/crypto_aead.h"
#include "../sha/rfc6234/sha.h"
#include <time.h>

// gcc client.c ../uECC.c ../opt32/aead.c ../sha/rfc6234/*.c -o client
#define PORT "8080"
#define MESSAGE "Hello from client pod\n"
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

void extract_key_bundle(const uint8_t* prekey_bundle, uint8_t* test_bob_public, uint8_t* test_bob_spk,
    uint8_t* test_bob_signature, uint8_t* test_bob_compress)
{
    // memcpy(timestamp, prekey_bundle, TIMESTAMP);
    memcpy(test_bob_public, prekey_bundle, 2*uECC_BYTES);
    memcpy(test_bob_spk, prekey_bundle + 2*uECC_BYTES, 2*uECC_BYTES);
    memcpy(test_bob_signature, prekey_bundle + 2*uECC_BYTES + 2*uECC_BYTES, 2*uECC_BYTES);
    memcpy(test_bob_compress, prekey_bundle + 2*uECC_BYTES + 2*uECC_BYTES + 2*uECC_BYTES, uECC_BYTES+1);

}

void send_to_bob(const uint8_t* ciphertext_alice, const unsigned long long* ct_len, const uint8_t* alice_id_public_key,
                const uint8_t* alice_ephemeral_public_key, const double* time_in_alice, uint8_t* bundle)
{

    memcpy(bundle, ciphertext_alice, MAX_CT_LEN);
    memcpy(bundle + MAX_CT_LEN, ct_len, sizeof(unsigned long long));
    memcpy(bundle + MAX_CT_LEN + sizeof(unsigned long long), alice_id_public_key, 2*uECC_BYTES);
    memcpy(bundle + MAX_CT_LEN + sizeof(unsigned long long) + 2*uECC_BYTES, alice_ephemeral_public_key, 2*uECC_BYTES);
    memcpy(bundle + MAX_CT_LEN + sizeof(unsigned long long) + 2*uECC_BYTES + 2*uECC_BYTES, time_in_alice, sizeof(double));
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
    int sockfd;
    int no_times_comm = 0;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    time_t t;
    char *server_service_host;

    server_service_host = getenv("SERVER_SERVICE_HOST");
    if (server_service_host == NULL) {
        fprintf(stderr, "SERVER_SERVICE_HOST environment variable not set.\n");
        exit(EXIT_FAILURE);
    }
    printf("The server service host is: %s\n", server_service_host);

    while (1) {
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if ((rv = getaddrinfo(server_service_host, PORT, &hints, &servinfo)) != 0) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
            exit(1);
        }

        for (p = servinfo; p != NULL; p = p->ai_next) {
            sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (sockfd == -1) {
                perror("client: socket");
                continue;
            }

            if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
                close(sockfd);
                perror("client: connect");
                continue;
            }

            break;
        }

        if (p == NULL) {
            fprintf(stderr, "client: failed to connect\n");
            sleep(5);
            continue;
        }

        printf("Connected to the server...\n");

        char message[] = "Hello from the client!";
        write(sockfd, message, sizeof(message));
        printf("Message sent to the server...\n");

        // Receive message from the server
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        ssize_t numBytes = read(sockfd, buffer, sizeof(buffer));
        if (numBytes < 0) {
            perror("Error receiving message from server");
        }

        uint8_t alice_id_private_key[uECC_BYTES] = {0};
        uint8_t alice_ephemeral_private_key[uECC_BYTES] = {0};
        uint8_t alice_id_public_key[uECC_BYTES*2] = {0};
        uint8_t alice_ephemeral_public_key[uECC_BYTES*2] = {0};

        uint32_t timestamp_at_alice;
        uint32_t timestamp_end_alice;

        uint8_t test_bob_public[uECC_BYTES*2] = {0};
        uint8_t test_bob_spk[uECC_BYTES*2] = {0};
        uint8_t test_bob_signature[uECC_BYTES*2] = {0};
        uint8_t test_bob_compress[uECC_BYTES+1] = {0};
        uint8_t bob_spk_uncompress_key[uECC_BYTES*2] = {0};

        uint8_t dh1_alice[SECRET_LEN] = {0};
        uint8_t dh2_alice[SECRET_LEN] = {0};
        uint8_t dh3_alice[SECRET_LEN] = {0};

        uint8_t dh_final_alice[96];
        uint8_t hex_hkdf_output_alice[128]; 
    
        uint8_t prekey_bundle[PREKEY_BUNDLE_SIZE] = {0};

        // Hexadecimal encoding buffers for the authentication tag
        uint8_t alice_id_public_key_hex[uECC_BYTES*2 + 1] = {0};
        uint8_t test_bob_public_key_hex[uECC_BYTES*2 + 1] = {0};
        uint8_t ad_alice[AD_LEN] = {0};

        uint8_t alice_to_bob[SIZE_TO_BOB] = {0};

        uint8_t ct_alice[MAX_CT_LEN] = {0}; // Output buffer for ciphertext
        unsigned long long ct_len_alice = MAX_CT_LEN; // Length of the ciphertext
        unsigned char pt[] = "Hello Bob!\0"; // Message to be encrypted
        unsigned long long pt_len = strlen((char*)pt); // Length of the plaintext
        unsigned char nonce_alice[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

        // Seed the random number generator
        srand((unsigned) time(NULL));

        // Set the custom RNG function
        uECC_set_rng(custom_rng);

        uECC_Curve curves = uECC_secp256k1();

        //Generate long-term Identity Key pair for Alice
        if (!uECC_make_key(alice_id_public_key, alice_id_private_key, curves)) {
            perror("uECC_make_key() failed\n");
            return 1;
        }
        //Generate Ephemeral Pair for Alice
        if (!uECC_make_key(alice_ephemeral_public_key, alice_ephemeral_private_key, curves)) {
            perror("uECC_make_key() failed\n");
            return 1;
        }

        //receive prekey bundle
        memset(prekey_bundle, 0, PREKEY_BUNDLE_SIZE);
        ssize_t numBytes = read(sockfd, prekey_bundle, PREKEY_BUNDLE_SIZE);
        if (numBytes < 0) {
            perror("Error receiving prekey bundle from server");
        }

        printf("Receiving prekey bundle\n");
        extract_key_bundle(prekey_bundle, test_bob_public, test_bob_spk, test_bob_signature, test_bob_compress);
        no_times_comm += 1;
        timestamp_at_alice = (uint32_t)time(NULL);

        //After sending to Alice
        uECC_decompress(test_bob_compress, bob_spk_uncompress_key,curves);
        
        // Verify that the decompressed key is identical to the original key
        if(memcmp(test_bob_spk, bob_spk_uncompress_key, 2*uECC_BYTES) == 0) {
            printf("compressed key = original key.\n");
        } else {
            perror("Bob's prekey could not be decompressed.\n");
        }

        // Alice verifies the prekey signature using the compressed prekey
        if(uECC_verify(test_bob_public, bob_spk_uncompress_key, 2*uECC_BYTES, test_bob_signature,curves)) {
            printf("Bob's prekey signature is valid.\n");
        } else {
            printf("Bob's prekey signature is invalid.\n");
        }

        /************************************************************************************************************************
         * COMPUTING DH EXCHANGES FOR ALICE */
        //DH1 = DH(IKA, SPKB)
        if (!uECC_shared_secret(test_bob_spk, alice_id_private_key, dh1_alice, curves)) {
            perror("shared_secret() failed (1)\n");
            return 1;
        }
        //DH2 = DH(EKA, IKB) 
        if (!uECC_shared_secret(test_bob_public, alice_ephemeral_private_key, dh2_alice, curves)) {
            perror("shared_secret() failed (2)\n");
            return 1;
        }
        //DH3 = DH(EKA, SPKB)
        if (!uECC_shared_secret(test_bob_spk, alice_ephemeral_private_key, dh3_alice, curves)) {
            perror("shared_secret() failed (2)\n");
            return 1;
        }


        //Concatenating all the diffie-helman exchanges for Alice
        for(int j=0; j<96;j++)
        {
            if(j<32) dh_final_alice[j] = dh1_alice[j]; 
            if(j>=32 && j< 64)  dh_final_alice[j] = dh2_alice[j%32]; 
            if(j>=64)  dh_final_alice[j] = dh3_alice[j%32]; 
        }

        /************************************************************************************************************************
         * OBTAINING THE SYMMETRIC KEY FOR ALICE */
        get_shared_key(dh_final_alice, 96, SHA256, NULL, 0, NULL, 0, hex_hkdf_output_alice, 128);


        /******************************************************************************
         * AUTHENTICATION TAG FOR ALICE*/

        // hex_encode(alice_id_public_key, 2*uECC_BYTES, alice_id_public_key_hex);
        // hex_encode(test_bob_public, 2*uECC_BYTES, test_bob_public_key_hex);
        memcpy(ad_alice, alice_id_public_key, 2*uECC_BYTES);
        memcpy(ad_alice + 2*uECC_BYTES, test_bob_public, 2*uECC_BYTES);
        /******************************************************************************************
         * SYMMETRIC KEY ENCRYPTION FOR ALICE
        */

        int ret = crypto_aead_encrypt(ct_alice, &ct_len_alice, pt, pt_len, ad_alice, AD_LEN, NULL, nonce_alice, hex_hkdf_output_alice);

        if (ret == 0) {
            printf("\nCiphertext:\n");
            for (unsigned int i = 0; i < ct_len_alice; ++i) {
                printf("%02X ", ct_alice[i]);
            }
            printf("\n");
        } else {
            perror("Encryption failed\n");
            return 1;
        }

        timestamp_end_alice = (uint32_t)time(NULL);
        double time_diff_in_alice = difftime(timestamp_end_alice, timestamp_at_alice);
        send_to_bob(ct_alice, &ct_len_alice, alice_id_public_key, alice_ephemeral_public_key, &time_diff_in_alice, alice_to_bob);
        write(sockfd, alice_to_bob, SIZE_TO_BOB);
        printf("AEAD bundle sent to server\n");
        freeaddrinfo(servinfo);
        close(sockfd);
        sleep(5);
    }

    return 0;
}
