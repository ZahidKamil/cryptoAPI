#include<stdio.h>
#include "crypto_aead.h"
#include <string.h>

// void encrypt(const unsigned char *m, unsigned long long mlen, const unsigned char *k, char* c, unsigned long long* c_length)
// {
//     // unsigned long long c_length = 80;                                                                      // ciphertext length
//     // unsigned char c[c_length];                                                                             // ciphertext
//     unsigned long long *clen = c_length;                                                                  // ciphertext length pointer
//     const unsigned char ad[] = {0x00};                                                                     // associated data
//     unsigned long long adlen = sizeof(ad);                                                                 // associated data length
//     const unsigned char *nsec;                                                                             // secret message number
//     const unsigned char npub[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B}; // public message number

//     crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k);

//     printf("Ciphertext = ");
//     for (int i = 0; i < *c_length; i++)
//     {
//         printf("%02X|", c[i]);
//     }
// }

// int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
//                         const unsigned char* m, unsigned long long mlen,
//                         const unsigned char* ad, unsigned long long adlen,
//                         const unsigned char* nsec, const unsigned char* npub,
//                         const unsigned char* k)

#define MAX_CT_LEN 20
int main() {
    unsigned char key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    unsigned char nonce[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    unsigned char m[] = "Hello Bob!"; // Message to be encrypted
    unsigned long long m_len = strlen((char*)m); // Length of the message

    unsigned char pt[] = {0x00}; // Message to be encrypted
    unsigned long long pt_len = 0; // Length of the message

    unsigned char ad[] = {0x00};
    unsigned long long ad_len = 0;

    unsigned char ct[MAX_CT_LEN]; // Output buffer for ciphertext
    unsigned long long ct_len= MAX_CT_LEN; // Length of the ciphertext

    // Call the encryption function
    int ret = crypto_aead_encrypt(
        ct, &ct_len, pt, pt_len, ad, ad_len, NULL, nonce, key
    );

    if (ret == 0) {
        printf("Ciphertext:\n");
        for (unsigned int i = 0; i < ct_len; ++i) {
            printf("%02X ", ct[i]);
        }
        printf("\n");
    } else {
        printf("Encryption failed\n");
    }

    return 0;
}


