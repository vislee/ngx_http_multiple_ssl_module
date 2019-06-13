
/*
 * Copyright (C) vislee
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>



typedef struct {
    ngx_flag_t                   multiple_ssl_enable;
    ngx_str_t                    multiple_ssl_cert_path;
    ngx_array_t                 *multiple_ssl_servernames;
} ngx_http_multiple_ssl_srv_conf_t;


static void *ngx_http_multiple_ssl_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_multiple_ssl_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
static int ngx_http_multiple_ssl_cert_handler(ngx_ssl_conn_t *ssl_conn, int *ad,
    void *arg);
static int ngx_http_multiple_ssl_set_der_certificate(ngx_ssl_conn_t *ssl_conn,
    ngx_str_t *cert, ngx_str_t *key);
#endif


static ngx_command_t ngx_http_multiple_ssl_commands[] = {

    { ngx_string("multiple_ssl"),
      NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_multiple_ssl_srv_conf_t, multiple_ssl_enable),
      NULL },

    { ngx_string("multiple_ssl_cert_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_multiple_ssl_srv_conf_t, multiple_ssl_cert_path),
      NULL },

    { ngx_string("multiple_ssl_servernames"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_multiple_ssl_srv_conf_t, multiple_ssl_servernames),
      NULL },

    ngx_null_command
};



static ngx_http_module_t ngx_http_multiple_ssl_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    ngx_http_multiple_ssl_create_srv_conf,  /* create server configuration */
    ngx_http_multiple_ssl_merge_srv_conf,   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};



ngx_module_t ngx_http_multiple_ssl_module = {
    NGX_MODULE_V1,
    &ngx_http_multiple_ssl_module_ctx,  /* module context */
    ngx_http_multiple_ssl_commands,     /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};



static void *
ngx_http_multiple_ssl_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_multiple_ssl_srv_conf_t  *mscf;

    mscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_multiple_ssl_srv_conf_t));
    if (mscf == NULL) {
        return NULL;
    }

    mscf->multiple_ssl_enable = NGX_CONF_UNSET;

    return mscf;
}



static char *
ngx_http_multiple_ssl_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_multiple_ssl_srv_conf_t *prev = parent;
    ngx_http_multiple_ssl_srv_conf_t *conf = child;
    ngx_http_ssl_srv_conf_t  *sscf;

    ngx_conf_merge_value(conf->multiple_ssl_enable,
                         prev->multiple_ssl_enable, 0);

    ngx_conf_merge_str_value(conf->multiple_ssl_cert_path,
                             prev->multiple_ssl_cert_path, "");

    if (conf->multiple_ssl_servernames == NULL) {
        conf->multiple_ssl_servernames = prev->multiple_ssl_servernames;
    }

    if (conf->multiple_ssl_enable) {

        sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
        if (sscf == NULL || sscf->ssl.ctx == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "multiple ssl no ssl configured for the server");

            return NGX_CONF_ERROR;
        }

        if (ngx_conf_full_name(cf->cycle, &conf->multiple_ssl_cert_path, 0) != NGX_OK) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "multiple ssl ngx_conf_full_name multiple_ssl_cert_path error");

            return NGX_CONF_ERROR;
        }

        if (conf->multiple_ssl_cert_path.len <= 1) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "multiple ssl no cert path for the server");

            return NGX_CONF_ERROR;
        }

        ngx_log_error(NGX_LOG_INFO, cf->log, 0, "multiple ssl enable ON");

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        if (SSL_CTX_set_tlsext_servername_callback(sscf->ssl.ctx,
            ngx_http_multiple_ssl_cert_handler) == 0)
        {
            ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                "The SNI is not available, multiple ssl ignore.");
        }
#else
        ngx_log_error(NGX_LOG_WARN, cf->log, 0, "The SNI is invalid");
#endif

    }

    return NGX_CONF_OK;
}


#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

static int
ngx_http_multiple_ssl_cert_handler(ngx_ssl_conn_t *ssl_conn, int *ad, void *arg)
{
    ngx_connection_t           *c;
    ngx_http_connection_t      *hc;
    const char                 *servername;
    ngx_uint_t                  i;
    ngx_str_t                   cert;
    ngx_str_t                   key;
    ngx_str_t                   host;
    ngx_keyval_t               *sn_cert;

    ngx_http_multiple_ssl_srv_conf_t   *mscf;


    c = ngx_ssl_get_connection(ssl_conn);
    if (c == NULL) {
        return 0;
    }

    hc = c->data;
    if (NULL == hc) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                   "multiple ssl connection data hc NULL");
        return 0;
    }

    servername = SSL_get_servername(ssl_conn, TLSEXT_NAMETYPE_host_name);
    if (servername == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "multiple ssl SSL_get_servername NULL");

        return SSL_TLSEXT_ERR_NOACK;
    }

    host.len = ngx_strlen(servername);
    if (host.len == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
            "multiple ssl servername len == 0");

        return SSL_TLSEXT_ERR_NOACK;
    }

    host.data = (u_char *) servername;
    ngx_log_error(NGX_LOG_INFO, c->log, 0, "multiple ssl servername \"%V\"", &host);

    mscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_multiple_ssl_module);
    if (NULL == mscf) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "multiple ssl mscf NULL");
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (!mscf->multiple_ssl_enable) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
            "multiple ssl multiple_ssl_enable OFF");

        return SSL_TLSEXT_ERR_NOACK;
    }

    cert.len = 0;

    if (mscf->multiple_ssl_servernames != NULL) {

        sn_cert = mscf->multiple_ssl_servernames->elts;
        for (i = 0; i < mscf->multiple_ssl_servernames->nelts; i++) {

            cert.len = 0;

            if (sn_cert[i].key.len == host.len
                && ngx_strncmp(sn_cert[i].key.data, host.data, host.len) == 0)
            {
                cert = sn_cert[i].value;
                break;
            }

            if (sn_cert[i].key.len > 2
                && sn_cert[i].key.data[0] == '*' && sn_cert[i].key.data[1] == '.'
                && host.len > sn_cert[i].key.len - 1
                && ngx_strncmp(host.data + (host.len - sn_cert[i].key.len + 1),
                    sn_cert[i].key.data + 1, sn_cert[i].key.len - 1) == 0)
            {
                cert = sn_cert[i].value;
                break;
            }
        }
    }

    if (cert.len == 0) {
        cert.len = host.len + ngx_strlen(".crt");
        cert.data = ngx_pnalloc(c->pool, cert.len);
        if (NULL == cert.data) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "multiple ssl ngx_pnalloc cert.data NULL");
            return SSL_TLSEXT_ERR_NOACK;
        }
        ngx_memzero(cert.data, cert.len);
        ngx_sprintf(cert.data, "%V.crt", &host);
    }

    if (ngx_get_full_name(c->pool, (ngx_str_t *) &mscf->multiple_ssl_cert_path, &cert) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "multiple ssl ngx_get_full_name error. servername:\"%V\"", &host);

        return SSL_TLSEXT_ERR_NOACK;
    }

    key.len = cert.len;
    key.data = ngx_pnalloc(c->pool, key.len + 1);
    ngx_memcpy(key.data, cert.data, key.len + 1);
    key.data[key.len - 1] = 'y';
    key.data[key.len - 2] = 'e';
    key.data[key.len - 3] = 'k';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "multiple ssl cert %V", &cert);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "multiple ssl key %V", &key);

    if (0 != access((const char *)cert.data, F_OK|R_OK)) {
        ngx_log_debug1(NGX_LOG_WARN, c->log, 0, "multiple ssl cert [%V] not exists or not read", &cert);
        return SSL_TLSEXT_ERR_NOACK;
    }

    ngx_http_multiple_ssl_set_der_certificate(ssl_conn, &cert, &key);

    return SSL_TLSEXT_ERR_OK;
}


static int
ngx_http_multiple_ssl_set_der_certificate(ngx_ssl_conn_t *ssl_conn, ngx_str_t *cert, ngx_str_t *key)
{
    BIO               *bio = NULL;
    X509              *x509 = NULL;
    u_long             n;

    bio = BIO_new_file((char *) cert->data, "r");
    if (bio == NULL) {
        return NGX_ERROR;
    }

    x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
        BIO_free(bio);
        return NGX_ERROR;
    }

    SSL_certs_clear(ssl_conn);

    if (SSL_use_certificate(ssl_conn, x509) == 0) {
        X509_free(x509);
        BIO_free(bio);
        return NGX_ERROR;
    }

#if 0
    if (SSL_set_ex_data(ssl_conn, ngx_ssl_certificate_index, x509) == 0) {
        X509_free(x509);
        BIO_free(bio);
        return NGX_ERROR;
    }
#endif

    X509_free(x509);
    x509 = NULL;

    /* read rest of the chain */
    for ( ;; ) {
        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (x509 == NULL) {
            n = ERR_peek_last_error();

            if (ERR_GET_LIB(n) == ERR_LIB_PEM
                && ERR_GET_REASON(n) == PEM_R_NO_START_LINE)
            {
                ERR_clear_error();
                break;
            }

            BIO_free(bio);
            return NGX_ERROR;
        }

#ifdef SSL_CTRL_CHAIN_CERT
        if (SSL_add0_chain_cert(ssl_conn, x509) == 0) {
            X509_free(x509);
            BIO_free(bio);
            return NGX_ERROR;
        }
#else
        if (SSL_add_extra_chain_cert(ssl_conn, x509) == 0) {
            X509_free(x509);
            BIO_free(bio);
            return NGX_ERROR;
        }
#endif
    }

    BIO_free(bio);
    bio = NULL;


    if (SSL_use_PrivateKey_file(ssl_conn, (char *) key->data,
                                        SSL_FILETYPE_PEM) != 1)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif
