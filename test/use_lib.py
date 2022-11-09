from boringssl import lib as bssl, ffi


method = bssl.TLS_method()
ctx = bssl.SSL_CTX_new(method)
