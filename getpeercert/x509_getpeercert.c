
#define PY_SSIZE_T_CLEAN
#include <python3.10/Python.h>

#include <string.h>

#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

#define X509_NAME_MAXLEN 256

int try_decode_certificate(X509 *certificate) {
    int j;
    BIO *biobuf = NULL;
    GENERAL_NAMES *names = NULL;
    GENERAL_NAME *name;
    char buf[2048];
    char *vptr;
    int len;

    names = (GENERAL_NAMES *)X509_get_ext_d2i(certificate, NID_subject_alt_name, NULL, NULL);

    if (names == NULL) {
        return 0;
    }


    for(j = 0; j < sk_GENERAL_NAME_num(names); j++) {
        /* get a rendering of each name in the set of names */
        int gntype;
        ASN1_STRING *as = NULL;

        name = sk_GENERAL_NAME_value(names, j);
        gntype = name->type;
        switch (gntype) {
        case GEN_DIRNAME:
            printf("gen_dirname\n");
            /* we special-case DirName as a tuple of
               tuples of attributes */
//
//            t = PyTuple_New(2);
//            if (t == NULL) {
//                goto fail;
//            }
//
//            v = PyUnicode_FromString("DirName");
//            if (v == NULL) {
//                Py_DECREF(t);
//                goto fail;
//            }
//            PyTuple_SET_ITEM(t, 0, v);

//            v = _create_tuple_for_X509_NAME(name->d.dirn);
//            if (v == NULL) {
//                Py_DECREF(t);
//                goto fail;
//            }
//            PyTuple_SET_ITEM(t, 1, v);
            break;

        case GEN_EMAIL:
        case GEN_DNS:
        case GEN_URI:
            /* GENERAL_NAME_print() doesn't handle NULL bytes in ASN1_string
               correctly, CVE-2013-4238 */
//            t = PyTuple_New(2);
//            if (t == NULL)
//                goto fail;
            switch (gntype) {
            case GEN_EMAIL:
//                v = PyUnicode_FromString("email");
                as = name->d.rfc822Name;
                break;
            case GEN_DNS:
//                v = PyUnicode_FromString("DNS");
                as = name->d.dNSName;
                break;
            case GEN_URI:
//                v = PyUnicode_FromString("URI");
                as = name->d.uniformResourceIdentifier;
                break;
            }
            printf("uri: %s\n", (char *)ASN1_STRING_get0_data(as));
//            if (v == NULL) {
//                Py_DECREF(t);
//                goto fail;
//            }
//            PyTuple_SET_ITEM(t, 0, v);
//            v = PyUnicode_FromStringAndSize((char *)ASN1_STRING_get0_data(as),
//                                            ASN1_STRING_length(as));
//            if (v == NULL) {
//                Py_DECREF(t);
//                goto fail;
//            }
//            PyTuple_SET_ITEM(t, 1, v);
            break;

        case GEN_RID:
//            t = PyTuple_New(2);
//            if (t == NULL)
//                goto fail;
//
//            v = PyUnicode_FromString("Registered ID");
//            if (v == NULL) {
//                Py_DECREF(t);
//                goto fail;
//            }
//            PyTuple_SET_ITEM(t, 0, v);

            len = i2t_ASN1_OBJECT(buf, sizeof(buf)-1, name->d.rid);
            if (len < 0) {
//                Py_DECREF(t);
//                _setSSLError(state, NULL, 0, __FILE__, __LINE__);
//                goto fail;
            } else if (len >= (int)sizeof(buf)) {
//                v = PyUnicode_FromString("<INVALID>");
                printf("invalid\n");
            } else {
                printf("rid: %s\n", buf);
//                v = PyUnicode_FromStringAndSize(buf, len);
            }
//            if (v == NULL) {
//                Py_DECREF(t);
//                goto fail;
//            }
//            PyTuple_SET_ITEM(t, 1, v);
            break;

        case GEN_IPADD:
            /* OpenSSL < 3.0.0 adds a trailing \n to IPv6. 3.0.0 removed
             * the trailing newline. Remove it in all versions
             */
//            t = PyTuple_New(2);
//            if (t == NULL)
//                goto fail;
//
//            v = PyUnicode_FromString("IP Address");
//            if (v == NULL) {
//                Py_DECREF(t);
//                goto fail;
//            }
//            PyTuple_SET_ITEM(t, 0, v);

            if (name->d.ip->length == 4) {
                unsigned char *p = name->d.ip->data;
//                v = PyUnicode_FromFormat(
//                    "%d.%d.%d.%d",
//                    p[0], p[1], p[2], p[3]
//                );
            } else if (name->d.ip->length == 16) {
                /* PyUnicode_FromFormat() does not support %X */
                unsigned char *p = name->d.ip->data;
                len = sprintf(
                    buf,
                    "%X:%X:%X:%X:%X:%X:%X:%X",
                    p[0] << 8 | p[1],
                    p[2] << 8 | p[3],
                    p[4] << 8 | p[5],
                    p[6] << 8 | p[7],
                    p[8] << 8 | p[9],
                    p[10] << 8 | p[11],
                    p[12] << 8 | p[13],
                    p[14] << 8 | p[15]
                );
//                v = PyUnicode_FromStringAndSize(buf, len);
            } else {
//                v = PyUnicode_FromString("<invalid>");
            }

//            if (v == NULL) {
//                Py_DECREF(t);
//                goto fail;
//            }
//            PyTuple_SET_ITEM(t, 1, v);
            break;

        default:
            /* for everything else, we use the OpenSSL print form */
            switch (gntype) {
                /* check for new general name type */
                case GEN_OTHERNAME:
                case GEN_X400:
                case GEN_EDIPARTY:
                case GEN_RID:
                    break;
                default:
//                    if (PyErr_WarnFormat(PyExc_RuntimeWarning, 1,
//                                         "Unknown general name type %d",
//                                         gntype) == -1) {
//                        goto fail;
//                    }
                    break;
            }
            (void) BIO_reset(biobuf);
            GENERAL_NAME_print(biobuf, name);
            len = BIO_gets(biobuf, buf, sizeof(buf)-1);
            if (len < 0) {
//                _setSSLError(state, NULL, 0, __FILE__, __LINE__);
                goto fail;
            }
            vptr = strchr(buf, ':');
            if (vptr == NULL) {
//                PyErr_Format(PyExc_ValueError,
//                             "Invalid value %.200s",
//                             buf);
                goto fail;
            }

            printf("default: %s\n", buf);
//            t = PyTuple_New(2);
//            if (t == NULL)
//                goto fail;
//            v = PyUnicode_FromStringAndSize(buf, (vptr - buf));
//            if (v == NULL) {
//                Py_DECREF(t);
//                goto fail;
//            }
//            PyTuple_SET_ITEM(t, 0, v);
//            v = PyUnicode_FromStringAndSize((vptr + 1),
//                                            (len - (vptr - buf + 1)));
//            if (v == NULL) {
//                Py_DECREF(t);
//                goto fail;
//            }
//            PyTuple_SET_ITEM(t, 1, v);
            break;
        }

        /* and add that rendering to the list */

//        if (PyList_Append(peer_alt_names, t) < 0) {
//            Py_DECREF(t);
//            goto fail;
//        }
//        Py_DECREF(t);
    }
    sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
//    ASN1_INTEGER *serialNumber;
//    char buf[2048];
//    int len, result;
//    const ASN1_TIME *notBefore, *notAfter;
//    PyObject *pnotBefore, *pnotAfter;
//
//    retval = PyDict_New();
//    if (retval == NULL)
//        return NULL;
//
//    peer = _create_tuple_for_X509_NAME(
//        state,
//        X509_get_subject_name(certificate));
//    if (peer == NULL)
//        goto fail0;
//    if (PyDict_SetItemString(retval, (const char *) "subject", peer) < 0) {
//        Py_DECREF(peer);
//        goto fail0;
//    }
//    Py_DECREF(peer);
//
//    issuer = _create_tuple_for_X509_NAME(
//        state,
//        X509_get_issuer_name(certificate));
//    if (issuer == NULL)
//        goto fail0;
//    if (PyDict_SetItemString(retval, (const char *)"issuer", issuer) < 0) {
//        Py_DECREF(issuer);
//        goto fail0;
//    }
//    Py_DECREF(issuer);
//
//    version = PyLong_FromLong(X509_get_version(certificate) + 1);
//    if (version == NULL)
//        goto fail0;
//    if (PyDict_SetItemString(retval, "version", version) < 0) {
//        Py_DECREF(version);
//        goto fail0;
//    }
//    Py_DECREF(version);
//
//    /* get a memory buffer */
//    biobuf = BIO_new(BIO_s_mem());
//    if (biobuf == NULL) {
//        PyErr_SetString(state->PySSLErrorObject, "failed to allocate BIO");
//        goto fail0;
//    }
//
//    (void) BIO_reset(biobuf);
//    serialNumber = X509_get_serialNumber(certificate);
//    /* should not exceed 20 octets, 160 bits, so buf is big enough */
//    i2a_ASN1_INTEGER(biobuf, serialNumber);
//    len = BIO_gets(biobuf, buf, sizeof(buf)-1);
//    if (len < 0) {
//        _setSSLError(state, NULL, 0, __FILE__, __LINE__);
//        goto fail1;
//    }
//    sn_obj = PyUnicode_FromStringAndSize(buf, len);
//    if (sn_obj == NULL)
//        goto fail1;
//    if (PyDict_SetItemString(retval, "serialNumber", sn_obj) < 0) {
//        Py_DECREF(sn_obj);
//        goto fail1;
//    }
//    Py_DECREF(sn_obj);
//
//    (void) BIO_reset(biobuf);
//    notBefore = X509_get0_notBefore(certificate);
//    ASN1_TIME_print(biobuf, notBefore);
//    len = BIO_gets(biobuf, buf, sizeof(buf)-1);
//    if (len < 0) {
//        _setSSLError(state, NULL, 0, __FILE__, __LINE__);
//        goto fail1;
//    }
//    pnotBefore = PyUnicode_FromStringAndSize(buf, len);
//    if (pnotBefore == NULL)
//        goto fail1;
//    if (PyDict_SetItemString(retval, "notBefore", pnotBefore) < 0) {
//        Py_DECREF(pnotBefore);
//        goto fail1;
//    }
//    Py_DECREF(pnotBefore);
//
//    (void) BIO_reset(biobuf);
//    notAfter = X509_get0_notAfter(certificate);
//    ASN1_TIME_print(biobuf, notAfter);
//    len = BIO_gets(biobuf, buf, sizeof(buf)-1);
//    if (len < 0) {
//        _setSSLError(state, NULL, 0, __FILE__, __LINE__);
//        goto fail1;
//    }
//    pnotAfter = PyUnicode_FromStringAndSize(buf, len);
//    if (pnotAfter == NULL)
//        goto fail1;
//    if (PyDict_SetItemString(retval, "notAfter", pnotAfter) < 0) {
//        Py_DECREF(pnotAfter);
//        goto fail1;
//    }
//    Py_DECREF(pnotAfter);
//
//    /* Now look for subjectAltName */
//
//    peer_alt_names = _get_peer_alt_names(state, certificate);
//    if (peer_alt_names == NULL)
//        goto fail1;
//    else if (peer_alt_names != Py_None) {
//        if (PyDict_SetItemString(retval, "subjectAltName",
//                                 peer_alt_names) < 0) {
//            Py_DECREF(peer_alt_names);
//            goto fail1;
//        }
//        Py_DECREF(peer_alt_names);
//    }
//
//    /* Authority Information Access: OCSP URIs */
//    obj = _get_aia_uri(certificate, NID_ad_OCSP);
//    if (obj == NULL) {
//        goto fail1;
//    } else if (obj != Py_None) {
//        result = PyDict_SetItemString(retval, "OCSP", obj);
//        Py_DECREF(obj);
//        if (result < 0) {
//            goto fail1;
//        }
//    }
//
//    obj = _get_aia_uri(certificate, NID_ad_ca_issuers);
//    if (obj == NULL) {
//        goto fail1;
//    } else if (obj != Py_None) {
//        result = PyDict_SetItemString(retval, "caIssuers", obj);
//        Py_DECREF(obj);
//        if (result < 0) {
//            goto fail1;
//        }
//    }
//
//    /* CDP (CRL distribution points) */
//    obj = _get_crl_dp(certificate);
//    if (obj == NULL) {
//        goto fail1;
//    } else if (obj != Py_None) {
//        result = PyDict_SetItemString(retval, "crlDistributionPoints", obj);
//        Py_DECREF(obj);
//        if (result < 0) {
//            goto fail1;
//        }
//    }
//
//    BIO_free(biobuf);
//    return retval;
//
//  fail1:
//    if (biobuf != NULL)
//        BIO_free(biobuf);
//  fail0:
//    Py_XDECREF(retval);
    return 1;

  fail:
    return -1;
}

static PyObject *
_asn1obj2py(const ASN1_OBJECT *name, int no_name)
{
    char buf[X509_NAME_MAXLEN];
    char *namebuf = buf;
    int buflen;
    PyObject *name_obj = NULL;

    buflen = OBJ_obj2txt(namebuf, X509_NAME_MAXLEN, name, no_name);
    if (buflen < 0) {
        return NULL;
    }
    /* initial buffer is too small for oid + terminating null byte */
    if (buflen > X509_NAME_MAXLEN - 1) {
        /* make OBJ_obj2txt() calculate the required buflen */
        buflen = OBJ_obj2txt(NULL, 0, name, no_name);
        /* allocate len + 1 for terminating NULL byte */
        namebuf = PyMem_Malloc(buflen + 1);
        if (namebuf == NULL) {
            PyErr_NoMemory();
            return NULL;
        }
        buflen = OBJ_obj2txt(namebuf, buflen + 1, name, no_name);
        if (buflen < 0) {
            goto done;
        }
    }
    if (!buflen && no_name) {
        Py_INCREF(Py_None);
        name_obj = Py_None;
    }
    else {
        name_obj = PyUnicode_FromStringAndSize(namebuf, buflen);
    }

  done:
    if (buf != namebuf) {
        PyMem_Free(namebuf);
    }
    return name_obj;
}
static PyObject *
_create_tuple_for_attribute(
                            ASN1_OBJECT *name, ASN1_STRING *value)
{
    Py_ssize_t buflen;
    PyObject *pyattr;
    PyObject *pyname = _asn1obj2py(name, 0);

    if (pyname == NULL) {
        return NULL;
    }

    if (ASN1_STRING_type(value) == V_ASN1_BIT_STRING) {
        buflen = ASN1_STRING_length(value);
        pyattr = Py_BuildValue("Ny#", pyname, ASN1_STRING_get0_data(value), buflen);
    } else {
        unsigned char *valuebuf = NULL;
        buflen = ASN1_STRING_to_UTF8(&valuebuf, value);
        if (buflen < 0) {
            Py_DECREF(pyname);
            return NULL;
        }
        pyattr = Py_BuildValue("Ns#", pyname, valuebuf, buflen);
        OPENSSL_free(valuebuf);
    }
    return pyattr;
}

static PyObject *
_create_tuple_for_X509_NAME (X509_NAME *xname)
{
    PyObject *dn = NULL;    /* tuple which represents the "distinguished name" */
    PyObject *rdn = NULL;   /* tuple to hold a "relative distinguished name" */
    PyObject *rdnt;
    PyObject *attr = NULL;   /* tuple to hold an attribute */
    int entry_count = X509_NAME_entry_count(xname);
    X509_NAME_ENTRY *entry;
    ASN1_OBJECT *name;
    ASN1_STRING *value;
    int index_counter;
    int rdn_level = -1;
    int retcode;

    dn = PyList_New(0);
    if (dn == NULL)
        return NULL;
    /* now create another tuple to hold the top-level RDN */
    rdn = PyList_New(0);
    if (rdn == NULL)
        goto fail0;

    for (index_counter = 0;
         index_counter < entry_count;
         index_counter++)
    {
        entry = X509_NAME_get_entry(xname, index_counter);

        /* check to see if we've gotten to a new RDN */
        if (rdn_level >= 0) {
            if (rdn_level != X509_NAME_ENTRY_set(entry)) {
                /* yes, new RDN */
                /* add old RDN to DN */
                rdnt = PyList_AsTuple(rdn);
                Py_DECREF(rdn);
                if (rdnt == NULL)
                    goto fail0;
                retcode = PyList_Append(dn, rdnt);
                Py_DECREF(rdnt);
                if (retcode < 0)
                    goto fail0;
                /* create new RDN */
                rdn = PyList_New(0);
                if (rdn == NULL)
                    goto fail0;
            }
        }
        rdn_level = X509_NAME_ENTRY_set(entry);

        /* now add this attribute to the current RDN */
        name = X509_NAME_ENTRY_get_object(entry);
        value = X509_NAME_ENTRY_get_data(entry);
        attr = _create_tuple_for_attribute(name, value);

        fprintf(stderr, "RDN attribute %s: %s\n",
            PyBytes_AS_STRING(PyTuple_GET_ITEM(attr, 0)),
            PyBytes_AS_STRING(PyTuple_GET_ITEM(attr, 1)));

        if (attr == NULL)
            goto fail1;
        retcode = PyList_Append(rdn, attr);
        Py_DECREF(attr);
        if (retcode < 0)
            goto fail1;
    }
    /* now, there's typically a dangling RDN */
    if (rdn != NULL) {
        if (PyList_GET_SIZE(rdn) > 0) {
            rdnt = PyList_AsTuple(rdn);
            Py_DECREF(rdn);
            if (rdnt == NULL)
                goto fail0;
            retcode = PyList_Append(dn, rdnt);
            Py_DECREF(rdnt);
            if (retcode < 0)
                goto fail0;
        }
        else {
            Py_DECREF(rdn);
        }
    }

    /* convert list to tuple */
    rdnt = PyList_AsTuple(dn);
    Py_DECREF(dn);
    if (rdnt == NULL)
        return NULL;
    return rdnt;

  fail1:
    Py_XDECREF(rdn);

  fail0:
    Py_XDECREF(dn);
    return NULL;
}

static PyObject *
_get_aia_uri(X509 *certificate, int nid) {
    PyObject *lst = NULL, *ostr = NULL;
    int i, result;
    AUTHORITY_INFO_ACCESS *info;

    info = X509_get_ext_d2i(certificate, NID_info_access, NULL, NULL);
    if (info == NULL)
        return Py_None;
    if (sk_ACCESS_DESCRIPTION_num(info) == 0) {
        AUTHORITY_INFO_ACCESS_free(info);
        return Py_None;
    }

    if ((lst = PyList_New(0)) == NULL) {
        goto fail;
    }

    for (i = 0; i < sk_ACCESS_DESCRIPTION_num(info); i++) {
        ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(info, i);
        ASN1_IA5STRING *uri;

        if ((OBJ_obj2nid(ad->method) != nid) ||
                (ad->location->type != GEN_URI)) {
            continue;
        }
        uri = ad->location->d.uniformResourceIdentifier;
        ostr = PyUnicode_FromStringAndSize((char *)uri->data,
                                           uri->length);
        if (ostr == NULL) {
            goto fail;
        }
        result = PyList_Append(lst, ostr);
        Py_DECREF(ostr);
        if (result < 0) {
            goto fail;
        }
    }
    AUTHORITY_INFO_ACCESS_free(info);

    /* convert to tuple or None */
    if (PyList_Size(lst) == 0) {
        Py_DECREF(lst);
        return Py_None;
    } else {
        PyObject *tup;
        tup = PyList_AsTuple(lst);
        Py_DECREF(lst);
        return tup;
    }

  fail:
    AUTHORITY_INFO_ACCESS_free(info);
    Py_XDECREF(lst);
    return NULL;
}

static PyObject *
_get_crl_dp(X509 *certificate) {
    STACK_OF(DIST_POINT) *dps;
    int i, j;
    PyObject *lst, *res = NULL;

    dps = X509_get_ext_d2i(certificate, NID_crl_distribution_points, NULL, NULL);

    if (dps == NULL)
        return Py_None;

    lst = PyList_New(0);
    if (lst == NULL)
        goto done;

    for (i=0; i < sk_DIST_POINT_num(dps); i++) {
        DIST_POINT *dp;
        STACK_OF(GENERAL_NAME) *gns;

        dp = sk_DIST_POINT_value(dps, i);
        if (dp->distpoint == NULL) {
            /* Ignore empty DP value, CVE-2019-5010 */
            continue;
        }
        gns = dp->distpoint->name.fullname;

        for (j=0; j < sk_GENERAL_NAME_num(gns); j++) {
            GENERAL_NAME *gn;
            ASN1_IA5STRING *uri;
            PyObject *ouri;
            int err;

            gn = sk_GENERAL_NAME_value(gns, j);
            if (gn->type != GEN_URI) {
                continue;
            }
            uri = gn->d.uniformResourceIdentifier;
            ouri = PyUnicode_FromStringAndSize((char *)uri->data,
                                               uri->length);
            if (ouri == NULL)
                goto done;

            err = PyList_Append(lst, ouri);
            Py_DECREF(ouri);
            if (err < 0)
                goto done;
        }
    }

    /* Convert to tuple. */
    res = (PyList_GET_SIZE(lst) > 0) ? PyList_AsTuple(lst) : Py_None;

  done:
    Py_XDECREF(lst);
    CRL_DIST_POINTS_free(dps);
    return res;
}

static PyObject *
_get_peer_alt_names (X509 *certificate) {

    /* this code follows the procedure outlined in
       OpenSSL's crypto/x509v3/v3_prn.c:X509v3_EXT_print()
       function to extract the STACK_OF(GENERAL_NAME),
       then iterates through the stack to add the
       names. */

    int j;
    PyObject *peer_alt_names = Py_None;
    PyObject *v = NULL, *t;
    GENERAL_NAMES *names = NULL;
    GENERAL_NAME *name;
    BIO *biobuf = NULL;
    char buf[2048];
    char *vptr;
    int len;

    if (certificate == NULL)
        return peer_alt_names;

    /* get a memory buffer */
    biobuf = BIO_new(BIO_s_mem());
    if (biobuf == NULL) {
        return NULL;
    }

    names = (GENERAL_NAMES *)X509_get_ext_d2i(
        certificate, NID_subject_alt_name, NULL, NULL);
    if (names != NULL) {
        if (peer_alt_names == Py_None) {
            peer_alt_names = PyList_New(0);
            if (peer_alt_names == NULL)
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
                /* we special-case DirName as a tuple of
                   tuples of attributes */

                t = PyTuple_New(2);
                if (t == NULL) {
                    goto fail;
                }

                v = PyUnicode_FromString("DirName");
                if (v == NULL) {
                    Py_DECREF(t);
                    goto fail;
                }
                PyTuple_SET_ITEM(t, 0, v);

                v = _create_tuple_for_X509_NAME(name->d.dirn);
                if (v == NULL) {
                    Py_DECREF(t);
                    goto fail;
                }
                PyTuple_SET_ITEM(t, 1, v);
                break;

            case GEN_EMAIL:
            case GEN_DNS:
            case GEN_URI:
                /* GENERAL_NAME_print() doesn't handle NULL bytes in ASN1_string
                   correctly, CVE-2013-4238 */
                t = PyTuple_New(2);
                if (t == NULL)
                    goto fail;
                switch (gntype) {
                case GEN_EMAIL:
                    v = PyUnicode_FromString("email");
                    as = name->d.rfc822Name;
                    break;
                case GEN_DNS:
                    v = PyUnicode_FromString("DNS");
                    as = name->d.dNSName;
                    break;
                case GEN_URI:
                    v = PyUnicode_FromString("URI");
                    as = name->d.uniformResourceIdentifier;
                    break;
                }
                if (v == NULL) {
                    Py_DECREF(t);
                    goto fail;
                }
                PyTuple_SET_ITEM(t, 0, v);
                v = PyUnicode_FromStringAndSize((char *)ASN1_STRING_get0_data(as),
                                                ASN1_STRING_length(as));
                if (v == NULL) {
                    Py_DECREF(t);
                    goto fail;
                }
                PyTuple_SET_ITEM(t, 1, v);
                break;

            case GEN_RID:
                t = PyTuple_New(2);
                if (t == NULL)
                    goto fail;

                v = PyUnicode_FromString("Registered ID");
                if (v == NULL) {
                    Py_DECREF(t);
                    goto fail;
                }
                PyTuple_SET_ITEM(t, 0, v);

                len = i2t_ASN1_OBJECT(buf, sizeof(buf)-1, name->d.rid);
                if (len < 0) {
                    Py_DECREF(t);
                    goto fail;
                } else if (len >= (int)sizeof(buf)) {
                    v = PyUnicode_FromString("<INVALID>");
                } else {
                    v = PyUnicode_FromStringAndSize(buf, len);
                }
                if (v == NULL) {
                    Py_DECREF(t);
                    goto fail;
                }
                PyTuple_SET_ITEM(t, 1, v);
                break;

            case GEN_IPADD:
                /* OpenSSL < 3.0.0 adds a trailing \n to IPv6. 3.0.0 removed
                 * the trailing newline. Remove it in all versions
                 */
                t = PyTuple_New(2);
                if (t == NULL)
                    goto fail;

                v = PyUnicode_FromString("IP Address");
                if (v == NULL) {
                    Py_DECREF(t);
                    goto fail;
                }
                PyTuple_SET_ITEM(t, 0, v);

                if (name->d.ip->length == 4) {
                    unsigned char *p = name->d.ip->data;
                    v = PyUnicode_FromFormat(
                        "%d.%d.%d.%d",
                        p[0], p[1], p[2], p[3]
                    );
                } else if (name->d.ip->length == 16) {
                    /* PyUnicode_FromFormat() does not support %X */
                    unsigned char *p = name->d.ip->data;
                    len = sprintf(
                        buf,
                        "%X:%X:%X:%X:%X:%X:%X:%X",
                        p[0] << 8 | p[1],
                        p[2] << 8 | p[3],
                        p[4] << 8 | p[5],
                        p[6] << 8 | p[7],
                        p[8] << 8 | p[9],
                        p[10] << 8 | p[11],
                        p[12] << 8 | p[13],
                        p[14] << 8 | p[15]
                    );
                    v = PyUnicode_FromStringAndSize(buf, len);
                } else {
                    v = PyUnicode_FromString("<invalid>");
                }

                if (v == NULL) {
                    Py_DECREF(t);
                    goto fail;
                }
                PyTuple_SET_ITEM(t, 1, v);
                break;

            default:
                /* for everything else, we use the OpenSSL print form */
                switch (gntype) {
                    /* check for new general name type */
                    case GEN_OTHERNAME:
                    case GEN_X400:
                    case GEN_EDIPARTY:
                    case GEN_RID:
                        break;
                    default:
                        if (PyErr_WarnFormat(PyExc_RuntimeWarning, 1,
                                             "Unknown general name type %d",
                                             gntype) == -1) {
                            goto fail;
                        }
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
                    PyErr_Format(PyExc_ValueError,
                                 "Invalid value %.200s",
                                 buf);
                    goto fail;
                }
                t = PyTuple_New(2);
                if (t == NULL)
                    goto fail;
                v = PyUnicode_FromStringAndSize(buf, (vptr - buf));
                if (v == NULL) {
                    Py_DECREF(t);
                    goto fail;
                }
                PyTuple_SET_ITEM(t, 0, v);
                v = PyUnicode_FromStringAndSize((vptr + 1),
                                                (len - (vptr - buf + 1)));
                if (v == NULL) {
                    Py_DECREF(t);
                    goto fail;
                }
                PyTuple_SET_ITEM(t, 1, v);
                break;
            }

            /* and add that rendering to the list */

            if (PyList_Append(peer_alt_names, t) < 0) {
                Py_DECREF(t);
                goto fail;
            }
            Py_DECREF(t);
        }
        sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
    }
    BIO_free(biobuf);
    if (peer_alt_names != Py_None) {
        v = PyList_AsTuple(peer_alt_names);
        Py_DECREF(peer_alt_names);
        return v;
    } else {
        return peer_alt_names;
    }


  fail:
    if (biobuf != NULL)
        BIO_free(biobuf);

    if (peer_alt_names != Py_None) {
        Py_XDECREF(peer_alt_names);
    }

    return NULL;
}

PyObject *decode_certificate(X509 *certificate) {
    PyObject *retval = NULL;
    BIO *biobuf = NULL;
    PyObject *peer;
    PyObject *peer_alt_names = NULL;
    PyObject *issuer;
    PyObject *version;
    PyObject *sn_obj;
    PyObject *obj;
    ASN1_INTEGER *serialNumber;
    char buf[2048];
    int len, result;
    const ASN1_TIME *notBefore, *notAfter;
    PyObject *pnotBefore, *pnotAfter;

    printf("decode start\n");
    retval = PyDict_New();
    printf("PyDict_New %p\n", retval);
    if (retval == NULL)
        return NULL;
//
//    peer = _create_tuple_for_X509_NAME(X509_get_subject_name(certificate));
//    if (peer == NULL)
//        goto fail0;
//
//    if (PyDict_SetItemString(retval, (const char *) "subject", peer) < 0) {
//        Py_DECREF(peer);
//        goto fail0;
//    }
//    Py_DECREF(peer);
//
//    issuer = _create_tuple_for_X509_NAME(
//        X509_get_issuer_name(certificate));
//    if (issuer == NULL)
//        goto fail0;
//    if (PyDict_SetItemString(retval, (const char *)"issuer", issuer) < 0) {
//        Py_DECREF(issuer);
//        goto fail0;
//    }
//    Py_DECREF(issuer);
//
//    version = PyLong_FromLong(X509_get_version(certificate) + 1);
//    if (version == NULL)
//        goto fail0;
//    if (PyDict_SetItemString(retval, "version", version) < 0) {
//        Py_DECREF(version);
//        goto fail0;
//    }
//    Py_DECREF(version);
//
//    /* get a memory buffer */
//    biobuf = BIO_new(BIO_s_mem());
//    if (biobuf == NULL) {
//        goto fail0;
//    }
//
//    (void) BIO_reset(biobuf);
//    serialNumber = X509_get_serialNumber(certificate);
//    /* should not exceed 20 octets, 160 bits, so buf is big enough */
//    i2a_ASN1_INTEGER(biobuf, serialNumber);
//    len = BIO_gets(biobuf, buf, sizeof(buf)-1);
//    if (len < 0) {
//        goto fail1;
//    }
//    sn_obj = PyUnicode_FromStringAndSize(buf, len);
//    if (sn_obj == NULL)
//        goto fail1;
//    if (PyDict_SetItemString(retval, "serialNumber", sn_obj) < 0) {
//        Py_DECREF(sn_obj);
//        goto fail1;
//    }
//    Py_DECREF(sn_obj);
//
//    (void) BIO_reset(biobuf);
//    notBefore = X509_get0_notBefore(certificate);
//    ASN1_TIME_print(biobuf, notBefore);
//    len = BIO_gets(biobuf, buf, sizeof(buf)-1);
//    if (len < 0) {
//        goto fail1;
//    }
//    pnotBefore = PyUnicode_FromStringAndSize(buf, len);
//    if (pnotBefore == NULL)
//        goto fail1;
//    if (PyDict_SetItemString(retval, "notBefore", pnotBefore) < 0) {
//        Py_DECREF(pnotBefore);
//        goto fail1;
//    }
//    Py_DECREF(pnotBefore);
//
//    (void) BIO_reset(biobuf);
//    notAfter = X509_get0_notAfter(certificate);
//    ASN1_TIME_print(biobuf, notAfter);
//    len = BIO_gets(biobuf, buf, sizeof(buf)-1);
//    if (len < 0) {
//        goto fail1;
//    }
//    pnotAfter = PyUnicode_FromStringAndSize(buf, len);
//    if (pnotAfter == NULL)
//        goto fail1;
//    if (PyDict_SetItemString(retval, "notAfter", pnotAfter) < 0) {
//        Py_DECREF(pnotAfter);
//        goto fail1;
//    }
//    Py_DECREF(pnotAfter);

    /* Now look for subjectAltName */
    printf("start get altname \n");
    peer_alt_names = _get_peer_alt_names(certificate);
    if (peer_alt_names == NULL)
        goto fail1;
    else if (peer_alt_names != Py_None) {
        if (PyDict_SetItemString(retval, "subjectAltName",
                                 peer_alt_names) < 0) {
            Py_DECREF(peer_alt_names);
            goto fail1;
        }
        Py_DECREF(peer_alt_names);
    }

    /* Authority Information Access: OCSP URIs */
    obj = _get_aia_uri(certificate, NID_ad_OCSP);
    if (obj == NULL) {
        goto fail1;
    } else if (obj != Py_None) {
        result = PyDict_SetItemString(retval, "OCSP", obj);
        Py_DECREF(obj);
        if (result < 0) {
            goto fail1;
        }
    }

    obj = _get_aia_uri(certificate, NID_ad_ca_issuers);
    if (obj == NULL) {
        goto fail1;
    } else if (obj != Py_None) {
        result = PyDict_SetItemString(retval, "caIssuers", obj);
        Py_DECREF(obj);
        if (result < 0) {
            goto fail1;
        }
    }

    /* CDP (CRL distribution points) */
    obj = _get_crl_dp(certificate);
    if (obj == NULL) {
        goto fail1;
    } else if (obj != Py_None) {
        result = PyDict_SetItemString(retval, "crlDistributionPoints", obj);
        Py_DECREF(obj);
        if (result < 0) {
            goto fail1;
        }
    }

    BIO_free(biobuf);
    return retval;

  fail1:
    printf("fail1\n");
    if (biobuf != NULL)
        BIO_free(biobuf);
  fail0:
    printf("fail0\n");
    Py_XDECREF(retval);
    return NULL;
}

PyObject *getpeercert(SSL* ssl) {
    X509 *certificate;
    PyObject *cert;
    PyGILState_STATE state;  // Needed for PyGILState_Ensure() and PyGILState_Release()
    state = PyGILState_Ensure();


    printf("start\n");
    certificate = SSL_get_peer_certificate(ssl);
    printf("decode\n");
    try_decode_certificate(certificate);
    cert = decode_certificate(certificate);

    // Release the GIL
    PyGILState_Release(state);
    return cert;
}
