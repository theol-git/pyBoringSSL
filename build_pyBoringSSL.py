import os
from os.path import join
import sys

from cffi import FFI

root = os.path.dirname(os.path.abspath(__file__))


ffibuilder = FFI()

libraries = [
        "brotlicommon-static",
        "brotlidec-static",

        'bssl',
        'bcrypto',
        "decrepit",

        "cert_decompress",
        "getpeercert",
    ]
if sys.platform == "win32":
    libraries.append("advapi32")

# set_source() gives the name of the python extension module to
# produce, and some C source code as a string.  This C code needs
# to make the declarated functions, types and globals available,
# so it is often just the "#include".
ffibuilder.set_source(
    "boringssl",
    """
    
        #define BORINGSSL_PREFIX BSSL
        #include "boringssl_prefix_symbols.h"
        
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
        int test_add_int(int a, int b);
        
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
        join(root, "build", "boringssl", "symbol_prefix_include"),
    ],
    library_dirs=[
        "build/boringssl/ssl",
        "build/boringssl/crypto",
        "build/boringssl/decrepit",
        "build/brotli",
        "build/cert_decompress",
        "build/getpeercert",
    ],
    libraries=libraries,
    extra_compile_args=[])

ffibuilder.cdef("""
    void free(void *ptr);

    typedef ... SSL_METHOD;
    const SSL_METHOD *BSSL_TLS_method(void);
    typedef ... SSL_CTX;
    SSL_CTX * BSSL_SSL_CTX_new(const SSL_METHOD * method);

    void BSSL_SSL_CTX_set_grease_enabled(SSL_CTX *ctx, int enabled);
    int BSSL_SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);
    int BSSL_SSL_CTX_set_alpn_protos(SSL_CTX *ssl, const uint8_t *protos, unsigned protos_len);
    void BSSL_SSL_CTX_enable_ocsp_stapling(SSL_CTX *ctx);
    void BSSL_SSL_CTX_enable_signed_cert_timestamps(SSL_CTX *ctx);
    int BSSL_SSL_CTX_set_verify_algorithm_prefs(SSL_CTX *ctx,
                                                      const uint16_t *prefs,
                                                      size_t num_prefs);
    int BSSL_SSL_CTX_set_min_proto_version(SSL_CTX *ctx, uint16_t version);

    typedef ... SSL;
    int BSSL_SSL_get_error(const SSL *ssl, int ret_code);
    SSL *BSSL_SSL_new(SSL_CTX *ctx);
    int BSSL_SSL_do_handshake(SSL *ssl);

    int BSSL_SSL_set_tlsext_host_name(SSL *ssl, const char *name);

    int BSSL_SSL_add_application_settings(SSL *ssl, const uint8_t *proto,
                                                size_t proto_len,
                                                const uint8_t *settings,
                                                size_t settings_len);
    void BSSL_SSL_get0_alpn_selected(const SSL *ssl,
                                           const uint8_t **out_data,
                                           unsigned *out_len);
    int BSSL_SSL_connect(SSL *ssl);
    typedef ... BIO;
    typedef ... BIO_METHOD;
    const BIO_METHOD *BSSL_BIO_s_mem(void);
    BIO *BSSL_BIO_new_socket(int fd, int close_flag);
    void BSSL_SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio);

    int BSSL_SSL_write(SSL *ssl, const void *buf, int num);
    int BSSL_SSL_read(SSL *ssl, void *buf, int num);
    int BSSL_SSL_shutdown(SSL *ssl);
    void BSSL_SSL_free(SSL *ssl);
    
    typedef ... X509;
    X509 *BSSL_SSL_get_peer_certificate(const SSL *ssl);
    struct stack_st_X509 *BSSL_SSL_get_peer_cert_chain(const SSL *ssl);
    struct stack_st_X509 *BSSL_SSL_get_peer_full_cert_chain(const SSL *ssl);
    
    typedef ... X509_NAME;
    X509_NAME *BSSL_X509_get_issuer_name(const X509 *x509);
    X509_NAME *BSSL_X509_get_subject_name(const X509 *x509);
    char *BSSL_X509_NAME_oneline(const X509_NAME *a, char *buf, int size);

typedef struct X509_extension_st X509_EXTENSION;
X509_EXTENSION *BSSL_X509_get_ext(const X509 *x, int loc);

    //typedef ... BSSL_CBB;
    typedef ... CRYPTO_BUFFER;
    CRYPTO_BUFFER *BSSL_CRYPTO_BUFFER_alloc(uint8_t **out_data, size_t len);
    
    #define BROTLI_NUM_BLOCK_LEN_SYMBOLS 26
    
    typedef struct {
      uint16_t offset;
      uint8_t nbits;
    } BrotliPrefixCodeRange;
    
                     
typedef struct asn1_object_st BSSL_ASN1_OBJECT;
typedef struct asn1_string_st BSSL_ASN1_OCTET_STRING;

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
    int BSSL_X509V3_extensions_print(BIO *out, const char *title,
                                           const struct stack_st_X509_EXTENSION *exts,
                                           unsigned long flag, int indent);
    void *BSSL_X509_get_ext_d2i(const X509 *x509, int nid,
                                      int *out_critical, int *out_idx);
    char* get_alt_names(X509 *certificate);
    
    int test_add_int(int a, int b);
""")

if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "generate_only":
        ffibuilder.emit_c_code("cffi_boringssl/boringssl.c")
    else:
        ffibuilder.compile(verbose=True)
