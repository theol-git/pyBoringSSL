
all: libcert_decompress.a


libcert_decompress.a: cert_decompress.c
	gcc -c -fPIC -I../boringssl/include -I../brotli/include cert_decompress.c -o cert_decompress.o
	ar rc libcert_decompress.a cert_decompress.o


clean:
	rm -rf *.o *.so core *.a
