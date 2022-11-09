import os
from os.path import join

from cffi import FFI

root = os.path.dirname(os.path.abspath(__file__))


ffibuilder = FFI()

# set_source() gives the name of the python extension module to
# produce, and some C source code as a string.  This C code needs
# to make the declarated functions, types and globals available,
# so it is often just the "#include".
ffibuilder.set_source(
    "boringssl",
    """
        #include "openssl/ssl.h" 
        #include "openssl/pool.h"
        #include "openssl/stack.h"
        #include "openssl/x509.h"
        #include "openssl/x509v3.h"
        #include "openssl/asn1.h"
        
        #include "brotli/decode.h"
        #include "common/constants.h"
        #include "common/platform.h"
        #include "common/context.h"
        #include "common/transform.h"
        
        int SetCompression(SSL_CTX *ctx);
        char* get_alt_names(X509 *certificate);
        
        
struct asn1_object_st {
  char *sn;
  char *ln;
  int nid;
  int length;
  unsigned char *data;
  int flags;
};

// X509_EXTENSION 
struct X509_extension_st {
  ASN1_OBJECT *object;
  ASN1_BOOLEAN critical;
  ASN1_OCTET_STRING *value;
} ;
    """,
    include_dirs=[
        join(root, "brotli", "c"),
        join(root, "brotli", "c", "include"),
        join(root, "boringssl", "include"),
    ],
    library_dirs=[
        "build/boringssl/ssl",
        "build/boringssl/crypto",
        "build/boringssl/decrepit",
        "build/brotli",
        "build/cert_decompress",
        "build/getpeercert",
    ],
    libraries=[
        "brotlicommon-static",
        "brotlidec-static",

        'bssl',
        'bcrypto',
        "decrepit",

        "cert_decompress",
        "getpeercert",
    ],
    extra_compile_args=[])

ffibuilder.cdef("""
    typedef ... SSL_METHOD;
    const SSL_METHOD *TLS_method(void);
    typedef ... SSL_CTX;
    SSL_CTX * SSL_CTX_new(const SSL_METHOD * method);

    void SSL_CTX_set_grease_enabled(SSL_CTX *ctx, int enabled);
    int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);
    int SSL_CTX_set_alpn_protos(SSL_CTX *ssl, const uint8_t *protos, unsigned protos_len);
    void SSL_CTX_enable_ocsp_stapling(SSL_CTX *ctx);
    void SSL_CTX_enable_signed_cert_timestamps(SSL_CTX *ctx);
    int SSL_CTX_set_verify_algorithm_prefs(SSL_CTX *ctx,
                                                      const uint16_t *prefs,
                                                      size_t num_prefs);
    int SSL_CTX_set_min_proto_version(SSL_CTX *ctx, uint16_t version);

    typedef ... SSL;
    int SSL_get_error(const SSL *ssl, int ret_code);
    SSL *SSL_new(SSL_CTX *ctx);
    int SSL_do_handshake(SSL *ssl);

    int SSL_set_tlsext_host_name(SSL *ssl, const char *name);

    int SSL_add_application_settings(SSL *ssl, const uint8_t *proto,
                                                size_t proto_len,
                                                const uint8_t *settings,
                                                size_t settings_len);
    void SSL_get0_alpn_selected(const SSL *ssl,
                                           const uint8_t **out_data,
                                           unsigned *out_len);
    int SSL_connect(SSL *ssl);
    typedef ... BIO;
    typedef ... BIO_METHOD;
    const BIO_METHOD *BIO_s_mem(void);
    BIO *BIO_new_socket(int fd, int close_flag);
    void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio);

    int SSL_write(SSL *ssl, const void *buf, int num);
    int SSL_read(SSL *ssl, void *buf, int num);
    int SSL_shutdown(SSL *ssl);
    void SSL_free(SSL *ssl);
    
    typedef ... X509;
    X509 *SSL_get_peer_certificate(const SSL *ssl);
    struct stack_st_X509 *SSL_get_peer_cert_chain(const SSL *ssl);
    struct stack_st_X509 *SSL_get_peer_full_cert_chain(const SSL *ssl);
    
    typedef ... X509_NAME;
    X509_NAME *X509_get_issuer_name(const X509 *x509);
    X509_NAME *X509_get_subject_name(const X509 *x509);
    char *X509_NAME_oneline(const X509_NAME *a, char *buf, int size);

typedef struct X509_extension_st X509_EXTENSION;
X509_EXTENSION *X509_get_ext(const X509 *x, int loc);

    typedef ... CBB;
    typedef ... CRYPTO_BUFFER;
    CRYPTO_BUFFER *CRYPTO_BUFFER_alloc(uint8_t **out_data, size_t len);
    
    #define BROTLI_NUM_BLOCK_LEN_SYMBOLS 26
    
    typedef struct {
      uint16_t offset;
      uint8_t nbits;
    } BrotliPrefixCodeRange;
    
                     
typedef struct asn1_object_st ASN1_OBJECT;
typedef struct asn1_string_st ASN1_OCTET_STRING;

    /* "Soft-private", it is exported, but not "advertised" as API. */
    extern const BrotliPrefixCodeRange _kBrotliPrefixCodeRanges[BROTLI_NUM_BLOCK_LEN_SYMBOLS];
    extern const uint8_t _kBrotliContextLookupTable[2048];
    
    void* BrotliDefaultAllocFunc(void* opaque, size_t size);
    
    typedef ... BrotliTransforms;
    int BrotliTransformDictionaryWord(
        uint8_t* dst, const uint8_t* word, int len,
        const BrotliTransforms* transforms, int transform_idx);
    typedef ... BrotliSharedDictionary;
    void BrotliSharedDictionaryDestroyInstance(BrotliSharedDictionary* dict);


    typedef enum {
      /** Decoding error, e.g. corrupted input or memory allocation problem. */
      BROTLI_DECODER_RESULT_ERROR = 0,
      /** Decoding successfully completed. */
      BROTLI_DECODER_RESULT_SUCCESS = 1,
      /** Partially done; should be called again with more input. */
      BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT = 2,
      /** Partially done; should be called again with more output. */
      BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT = 3
    } BrotliDecoderResult;

    BrotliDecoderResult BrotliDecoderDecompress(
        size_t encoded_size,
        const uint8_t encoded_buffer[],
        size_t* decoded_size,
        uint8_t decoded_buffer[]);
        
    int SetCompression(SSL_CTX *ctx);             
    
    //typedef ... stack_st_X509_EXTENSION;
    int X509V3_extensions_print(BIO *out, const char *title,
                                           const struct stack_st_X509_EXTENSION *exts,
                                           unsigned long flag, int indent);
    void *X509_get_ext_d2i(const X509 *x509, int nid,
                                      int *out_critical, int *out_idx);
    char* get_alt_names(X509 *certificate);
""")

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
