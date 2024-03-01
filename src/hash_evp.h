#include <openssl/evp.h>

#define SHA256_BLOCK_LENGTH		64
#define SHA256_DIGEST_LENGTH	32

#ifndef NOPROTO
void SHA256Init(EVP_MD_CTX *mdctx);
void SHA256Update(EVP_MD_CTX *mdctx, const char *message, unsigned int siglen);
void SHA256Final(EVP_MD_CTX *mdctx, uint8_t *digest);
#else
void SHA256Init();
void SHA256Update();
void SHA256Final();
#endif