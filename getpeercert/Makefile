
all: libgetpeercert.a


libgetpeercert.a: x509_getpeercert.c
	gcc -c -fPIC -I../boringssl/include -I/home/micheal/miniconda3/envs/pyBoringSSL/include/ x509_getpeercert.c -o x509_getpeercert.o
	ar rc libgetpeercert.a x509_getpeercert.o


clean:
	rm -rf *.o *.so core *.a
