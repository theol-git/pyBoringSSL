
#define BORINGSSL_PREFIX BSSL
#include "boringssl_prefix_symbols.h"

#include "openssl/ssl.h"
#include "brotli/decode.h"


int DecompressBrotliCert(SSL* ssl,
                         CRYPTO_BUFFER** out,
                         size_t uncompressed_len,
                         const uint8_t* in,
                         size_t in_len) {
  uint8_t* data;
  CRYPTO_BUFFER* decompressed = CRYPTO_BUFFER_alloc(&data, uncompressed_len);
  if (!decompressed) {
    printf("allocate decompress failed.\n");
    return 0;
  }

  size_t output_size = uncompressed_len;
  if (BrotliDecoderDecompress(in_len, in, &output_size, data) != BROTLI_DECODER_RESULT_SUCCESS ||
      output_size != uncompressed_len) {
    printf("decompress failed.\n");
    return 0;
  }
  // printf("decompress success.\n");

  *out = decompressed;
  return 1;
}

int SetCompression(SSL_CTX *ctx) {
    return SSL_CTX_add_cert_compression_alg(ctx, 2, 0, &DecompressBrotliCert);
}
