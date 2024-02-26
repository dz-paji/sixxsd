#include <openssl/evp.h>

#ifndef NOPROTO
void SHA256Init(EVP_MD_CTX *mdctx);
void SHA256Update(EVP_MD_CTX *mdctx, const char *message, unsigned int siglen);
void SHA256Final(EVP_MD_CTX *mdctx, char *digest);
#else
void SHA256Init();
void SHA256Update();
void SHA256Final();
#endif