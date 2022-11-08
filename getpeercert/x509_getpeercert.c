
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <string.h>

#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

#define X509_NAME_MAXLEN 256

int buffer_add(char* buf, char **buf_point, int buf_size, char *add_string) {
    int buf_used_num;
    int left_size;
    int add_string_len;

    buf_used_num = *buf_point - buf;
    if (buf_used_num < 0) {
        // printf("buf_used_num error.\n");
        return -1;
    } else if (buf_used_num > 0) {
        **buf_point = ';';
        *buf_point += 1;
        buf_used_num += 1;
    }

    left_size = buf_size - buf_used_num;
    add_string_len = strlen(add_string);
    if (left_size < add_string_len) {
        printf("left_size %d, add_string_len:%d.\n", left_size, add_string_len);
        return -1;
    }

    memcpy(*buf_point, add_string, add_string_len);
    *buf_point += add_string_len;
    // printf("buf: %p, p:point:%p\n", buf, buf_point);
    return add_string_len;
}

char* get_alt_names(X509 *certificate) {
    int j;
    BIO *biobuf = NULL;
    GENERAL_NAMES *names = NULL;
    GENERAL_NAME *name;

    char buf[2048];
    char *vptr;
    int len;

    char *tmp_name;
    int alt_name_max_size;
    char *alt_names = NULL;
    char *alt_name_p;

    alt_name_max_size = 1024;
    alt_names = (char*)malloc(alt_name_max_size);
    alt_name_p = alt_names;

    names = (GENERAL_NAMES *)X509_get_ext_d2i(certificate, NID_subject_alt_name, NULL, NULL);
    if (names == NULL) {
        goto fail;
    }

    for(j = 0; j < sk_GENERAL_NAME_num(names); j++) {
        /* get a rendering of each name in the set of names */
        int gntype;
        ASN1_STRING *as = NULL;

        name = sk_GENERAL_NAME_value(names, j);
        gntype = name->type;
        switch (gntype) {
        case GEN_DIRNAME:
            break;

        case GEN_EMAIL:
        case GEN_DNS:
        case GEN_URI:
            switch (gntype) {
            case GEN_EMAIL:
                as = name->d.rfc822Name;
                break;
            case GEN_DNS:
                as = name->d.dNSName;
                break;
            case GEN_URI:
                as = name->d.uniformResourceIdentifier;
                break;
            }
            tmp_name = (char *)ASN1_STRING_get0_data(as);
            // printf("uri: %s\n", tmp_name);
            buffer_add(alt_names, &alt_name_p, alt_name_max_size, tmp_name);
            break;

        case GEN_RID:
            break;

        case GEN_IPADD:
            break;

        default:
            switch (gntype) {
                /* check for new general name type */
                case GEN_OTHERNAME:
                case GEN_X400:
                case GEN_EDIPARTY:
                case GEN_RID:
                    break;
                default:
                    break;
            }
            (void) BIO_reset(biobuf);
            GENERAL_NAME_print(biobuf, name);
            len = BIO_gets(biobuf, buf, sizeof(buf)-1);
            if (len < 0) {
                goto fail;
            }
            vptr = strchr(buf, ':');
            if (vptr == NULL) {
                goto fail;
            }

            // printf("default: %s\n", buf);

            buffer_add(alt_names, &alt_name_p, alt_name_max_size, buf);
            break;
        }

    }
    sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);

    fail:
        *alt_name_p = 0x0;
        return alt_names;
}
