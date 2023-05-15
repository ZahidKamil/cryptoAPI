#include "microECC/uECC.h"

#include <stdio.h>
#include <string.h>
#include "opt32/crypto_aead.h"
#include "sha/rfc6234/sha.h"
#include <stdlib.h>
#include <time.h>

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

void generate_random_bytes(unsigned char *buffer, size_t size) {
    // Set the seed value
    srand(time(0));

    // Generate random bytes
    for (size_t i = 0; i < size; i++) {
        buffer[i] = (unsigned char) rand();
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

int main(){
    uint8_t alice_id_private_key[uECC_BYTES] = {0};
    uint8_t alice_ephemeral_private_key[uECC_BYTES] = {0};
    uint8_t bob_spk_private_key[uECC_BYTES] = {0};
    uint8_t bob_id_private_key[uECC_BYTES] = {0};

    uint8_t alice_id_public_key[uECC_BYTES*2] = {0};
    uint8_t alice_ephemeral_public_key[uECC_BYTES*2] = {0};
    uint8_t bob_spk_uncompress_key[uECC_BYTES*2] = {0};


    uint32_t timestamp_at_alice;
    uint32_t timestamp_end_alice;
    uint32_t timestamp_at_bob;
    uint32_t timestamp_end_bob;
    uint8_t bob_id_public_key[uECC_BYTES*2] = {0};
    uint8_t bob_spk_public_key[uECC_BYTES*2] = {0};
    uint8_t bob_spk_signature[uECC_BYTES*2] = {0};
    uint8_t bob_spk_compress_key[uECC_BYTES+1] = {0};
    
    
    uint8_t test_bob_public[uECC_BYTES*2] = {0};
    uint8_t test_bob_spk[uECC_BYTES*2] = {0};
    uint8_t test_bob_signature[uECC_BYTES*2] = {0};
    uint8_t test_bob_compress[uECC_BYTES+1] = {0};

    uint8_t test_alice_public[uECC_BYTES*2] = {0};
    uint8_t test_alice_ephemeral[uECC_BYTES*2] = {0};

    
    uint8_t hash[32] = {0};

    uint8_t dh1_alice[SECRET_LEN] = {0};
    uint8_t dh1_bob[SECRET_LEN] = {0};
    uint8_t dh2_alice[SECRET_LEN] = {0};
    uint8_t dh2_bob[SECRET_LEN] = {0};
    uint8_t dh3_alice[SECRET_LEN] = {0};
    uint8_t dh3_bob[SECRET_LEN] = {0};

    uint8_t dh_final_alice[96];
    uint8_t dh_final_bob[96];

    uint8_t hex_hkdf_output_alice[128]; 
    uint8_t hex_hkdf_output_bob[128]; 
    uint8_t prekey_bundle[PREKEY_BUNDLE_SIZE] = {0};

    // Hexadecimal encoding buffers for the authentication tag
    uint8_t alice_id_public_key_hex[uECC_BYTES*2 + 1] = {0};
    uint8_t test_bob_public_key_hex[uECC_BYTES*2 + 1] = {0};
    uint8_t ad_alice[AD_LEN] = {0};

    uint8_t test_alice_public_key_hex[uECC_BYTES*2 + 1] = {0};
    uint8_t bob_id_public_key_hex[uECC_BYTES*2 + 1] = {0};
    uint8_t ad_bob[AD_LEN] = {0};

    uint8_t alice_to_bob[SIZE_TO_BOB] = {0};

    uint8_t ct_alice[MAX_CT_LEN] = {0}; // Output buffer for ciphertext
    unsigned long long ct_len_alice = MAX_CT_LEN; // Length of the ciphertext
    unsigned char pt[] = "Hello Bob!\0"; // Message to be encrypted
    unsigned long long pt_len = strlen((char*)pt); // Length of the plaintext
    unsigned char nonce_alice[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

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
    
    printf("Testing 256 different key pairs\n");
    for (int i = 0; i < 1; ++i) {
        printf(".");
        fflush(stdout);
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
        //Generate long-term Identity Key pair for Alice
        if (!uECC_make_key(alice_id_public_key, alice_id_private_key, curves)) {
            printf("uECC_make_key() failed\n");
            return 1;
        }
        //Generate Ephemeral Pair for Alice
        if (!uECC_make_key(alice_ephemeral_public_key, alice_ephemeral_private_key, curves)) {
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
        // if(!sign_prekey(bob_id_private_key,  bob_id_public_key, bob_spk_public_key, bob_spk_signature, bob_spk_compress_key, curves)) {
        //         printf("Not working\n");
        //     }
        generate_key_bundle(bob_id_public_key, bob_spk_public_key, bob_spk_signature, bob_spk_compress_key, prekey_bundle);
        extract_key_bundle(prekey_bundle, test_bob_public, test_bob_spk, test_bob_signature, test_bob_compress);
        
        timestamp_at_alice = (uint32_t)time(NULL);

        if(memcmp(test_bob_public, bob_id_public_key, 2*uECC_BYTES) == 0) {
            printf("same.\n");
        } else {
            printf("not same.\n");
        }
        //After sending to Alice
        uECC_decompress(test_bob_compress, bob_spk_uncompress_key,curves);
        
        // Verify that the decompressed key is identical to the original key
        if(memcmp(test_bob_spk, bob_spk_uncompress_key, 2*uECC_BYTES) == 0) {
            printf("compressed key = original key.\n");
        } else {
            printf("Bob's prekey could not be decompressed.\n");
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
            printf("shared_secret() failed (1)\n");
            return 1;
        }
        //DH2 = DH(EKA, IKB) 
        if (!uECC_shared_secret(test_bob_public, alice_ephemeral_private_key, dh2_alice, curves)) {
            printf("shared_secret() failed (2)\n");
            return 1;
        }
        //DH3 = DH(EKA, SPKB)
        if (!uECC_shared_secret(test_bob_spk, alice_ephemeral_private_key, dh3_alice, curves)) {
            printf("shared_secret() failed (2)\n");
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
            printf("Encryption failed\n");
            return 1;
        }

        timestamp_end_alice = (uint32_t)time(NULL);
        double time_diff_in_alice = difftime(timestamp_end_alice, timestamp_at_alice);
        send_to_bob(ct_alice, &ct_len_alice, alice_id_public_key, alice_ephemeral_public_key, &time_diff_in_alice, alice_to_bob);
        /************************************************************************************************************************
         * BOB RECEIVES ALICE'S MESSAGE
        */
        double time_diff_alice_to_bob;
        unsigned long long ct_from_alice_len = MAX_CT_LEN;
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
        
        if (memcmp(hex_hkdf_output_alice, hex_hkdf_output_bob, 128) == 0) {
            printf("\nsame key\n");
        }

        if(memcmp(nonce_alice, nonce_bob, 16) == 0)
        {
            printf("same nonce\n");
        }


        /******************************************************************************
         * SYMMETRIC KEY DECRYPTION FOR BOB
        */

        // Decryption
        uint8_t decrypted_check[MAX_CT_LEN] = {0};
        unsigned long long decrypted_len_check = MAX_CT_LEN; 
        ret = crypto_aead_decrypt(
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
        printf("Total time: %0.3f", time_diff_in_alice + time_diff_alice_to_bob);
        /************************************************************************************************************************
         * VERIFYING DH EXCHANGES FOR ALICE AND BOB TO ENSURE THEY HAVE THE SAME VALUES */
        if ((memcmp(dh1_alice, dh1_bob, sizeof(dh1_alice)) != 0) &&
            (memcmp(dh2_alice, dh2_bob, sizeof(dh2_alice)) != 0) &&
            (memcmp(dh3_alice, dh3_bob, sizeof(dh3_alice)) != 0)) {
            printf("Shared secrets are not identical!\n");
            printf("dh1_alice = ");
            vli_print(dh1_alice, 32);
            printf("\n");
            printf("dh1_bob = ");
            vli_print(dh1_bob, 32);
            printf("\n");
            printf("dh2_alice = ");
            vli_print(dh2_alice, 32);
            printf("\n");
            printf("dh2_bob = ");
            vli_print(dh2_bob, 32);
            printf("\n");
            printf("dh3_alice1 = ");
            vli_print(dh3_alice, 32);
            printf("\n");
            printf("dh1_bob = ");
            vli_print(dh1_bob, 32);
            printf("\n");
        }


        //Comparing if the diffie helman exchanges are the same for both Alice and Bob
        if (memcmp(dh_final_alice, dh_final_bob, 96) != 0) {
            printf("Shared secrets are not identical!\n");
            printf("dh_final_alice= ");
            vli_print(dh_final_alice, 96);
            printf("\n");
            printf("dh_final_bob = ");
            vli_print(dh_final_bob, 96);
        }


        if (memcmp(hex_hkdf_output_alice, hex_hkdf_output_bob, 128) != 0) {
            printf("hex_hkdf output not identical!\n");
            printf("hex_hkdf_output_alice= ");
            vli_print(hex_hkdf_output_alice, 128);
            printf("\n");
            printf("hex_hkdf_output_bob = ");
            vli_print(hex_hkdf_output_bob, 128);
        }

        if(memcmp(ad_alice, ad_bob, AD_LEN)!=0) {
            printf("\nAD not identical\n");
            vli_print(ad_alice, AD_LEN);
            printf("\n\n");
            vli_print(ad_bob, AD_LEN);
        }

        if(memcmp(test_alice_public_key_hex, alice_id_public_key_hex, 65)!=0)
        {
            vli_print(test_alice_public_key_hex, 65);
            vli_print(alice_id_public_key_hex, 65);
        }
    }
    printf("\n");

    printf("Done!");
}

// gcc test_x3dh_copy.c uECC.c opt32/aead.c sha/rfc6234/*.c -o test_x3dh_copy