/*
 * Fluffy: library-level checks for wildcard (glob) lookups.
 *
 * - X509_load_crl_file() expands a glob, loads every matching PEM CRL file
 *   and tolerates matches that hold no CRL (here: an empty file).
 * - CONF_get1_default_config_file() honours OPENSSL_CONF, and never returns
 *   the unexpanded wildcard OPENSSLDIR pattern.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "testutil.h"

#if !defined(_WIN32) && !defined(OPENSSL_SYS_VMS)
#include <glob.h>
#include <unistd.h>

static const char *crl_pattern;
static int crl_expected;

static int test_crl_file_glob(void)
{
    X509_STORE *st = NULL;
    X509_LOOKUP *lu;
    STACK_OF(X509_OBJECT) *objs = NULL;
    int i, ncrl = 0, ret = 0;

    if (!TEST_ptr(st = X509_STORE_new())
        || !TEST_ptr(lu = X509_STORE_add_lookup(st, X509_LOOKUP_file())))
        goto err;
    if (!TEST_int_eq(X509_load_crl_file(lu, crl_pattern, X509_FILETYPE_PEM),
            crl_expected))
        goto err;
    if (!TEST_ptr(objs = X509_STORE_get1_objects(st)))
        goto err;
    for (i = 0; i < sk_X509_OBJECT_num(objs); i++)
        if (X509_OBJECT_get_type(sk_X509_OBJECT_value(objs, i)) == X509_LU_CRL)
            ncrl++;
    if (!TEST_int_eq(ncrl, crl_expected))
        goto err;
    ret = 1;
err:
    sk_X509_OBJECT_pop_free(objs, X509_OBJECT_free);
    X509_STORE_free(st);
    return ret;
}

static int test_default_config_override(void)
{
    static const char override[] = "/fluffy/override/does-not-exist.cnf";
    char *file = NULL;
    int ret;

    if (!TEST_int_eq(setenv("OPENSSL_CONF", override, 1), 0))
        return 0;
    ret = TEST_ptr(file = CONF_get1_default_config_file())
        && TEST_str_eq(file, override);
    OPENSSL_free(file);
    return ret;
}

static int test_default_config_wildcard(void)
{
    static const char etc[] = "/etc/ssl/" "openssl.cnf";
    const char *area = X509_get_default_cert_area();
    char *file = NULL, *pat = NULL, *expected = NULL;
    const char *branch;
    glob_t gbuf = { 0 };
    size_t gi, len;
    int ret = 0;

    if (!TEST_int_eq(unsetenv("OPENSSL_CONF"), 0)
        || !TEST_ptr(area))
        goto err;
    len = strlen(area) + sizeof("/openssl.cnf");
    if (!TEST_ptr(pat = OPENSSL_malloc(len)))
        goto err;
    BIO_snprintf(pat, len, "%s/openssl.cnf", area);

    /* The documented Fluffy lookup order. */
    if (access(etc, R_OK) == 0) {
        branch = "readable /etc/ssl/openssl.cnf";
        expected = OPENSSL_strdup(etc);
    } else if (strpbrk(pat, "*?[") == NULL) {
        branch = "non-wildcard OPENSSLDIR";
        expected = OPENSSL_strdup(pat);
    } else {
        branch = "wildcard OPENSSLDIR, no readable match: /etc/ssl fallback";
        if (glob(pat, GLOB_NOESCAPE, NULL, &gbuf) == 0) {
            for (gi = 0; gi < gbuf.gl_pathc; gi++) {
                if (access(gbuf.gl_pathv[gi], R_OK) == 0) {
                    branch = "wildcard OPENSSLDIR, first readable match";
                    expected = OPENSSL_strdup(gbuf.gl_pathv[gi]);
                    break;
                }
            }
        }
        if (expected == NULL)
            expected = OPENSSL_strdup(etc);
    }
    if (!TEST_ptr(expected)
        || !TEST_ptr(file = CONF_get1_default_config_file()))
        goto err;
    TEST_info("OPENSSLDIR=%s, case: %s, got %s", area, branch, file);
    if (!TEST_str_eq(file, expected))
        goto err;
    /* Never the literal pattern itself (unless it is a real file). */
    if (strpbrk(pat, "*?[") != NULL && access(pat, F_OK) != 0
        && !TEST_str_ne(file, pat))
        goto err;
    ret = 1;
err:
    globfree(&gbuf);
    OPENSSL_free(file);
    OPENSSL_free(expected);
    OPENSSL_free(pat);
    return ret;
}

OPT_TEST_DECLARE_USAGE("crl-glob-pattern expected-crl-count\n")

int setup_tests(void)
{
    const char *n;

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }
    if (!TEST_ptr(crl_pattern = test_get_argument(0))
        || !TEST_ptr(n = test_get_argument(1)))
        return 0;
    crl_expected = atoi(n);

    ADD_TEST(test_crl_file_glob);
    ADD_TEST(test_default_config_override);
    ADD_TEST(test_default_config_wildcard);
    return 1;
}

#else

int setup_tests(void)
{
    TEST_note("glob(3) lookups are not available on this platform");
    return 1;
}

#endif
