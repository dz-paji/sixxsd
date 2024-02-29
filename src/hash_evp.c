#include "hash_evp.h"
#include <stdio.h>
#include <string.h>

void SHA256Init(EVP_MD_CTX *mdctx)
{
    const EVP_MD *md;
    OpenSSL_add_all_digests();
    md = EVP_get_digestbyname("sha256");
    EVP_DigestInit_ex(mdctx, md, NULL);
}

void SHA256Update(EVP_MD_CTX *mdctx, const char *message, unsigned int siglen)
{
    EVP_DigestUpdate(mdctx, message, siglen);
}

void SHA256Final(EVP_MD_CTX *mdctx, char *digest)
{
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        for (i = 0; i < md_len; i++) {
        snprintf(digest + (i * 2), 3, "%02x", md_value[i]);
    }
    EVP_cleanup();
}