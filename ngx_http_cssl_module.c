
/*
 * Copyright (C) leevon@yeah.net
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>



typedef struct {
    ngx_flag_t                   cssl_enable;
    ngx_str_t                    cssl_cert_path;
} ngx_http_cssl_srv_conf_t;


static void *ngx_http_cssl_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_cssl_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static int ngx_http_cssl_cert_handler(ngx_ssl_conn_t *ssl_conn, void *data);
static int ngx_http_cssl_set_der_certificate(ngx_ssl_conn_t *ssl_conn, ngx_str_t *cert, ngx_str_t *key);


static ngx_command_t ngx_http_cssl_commands[] = {

    { ngx_string("cssl_ssl"),
      NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_cssl_srv_conf_t, cssl_enable),
      NULL },

    { ngx_string("cssl_cert_path"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_cssl_srv_conf_t, cssl_cert_path),
      NULL },

    ngx_null_command
};



static ngx_http_module_t ngx_http_cssl_module_ctx = {
    NULL,                              /* preconfiguration */
    NULL,                              /* postconfiguration */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    ngx_http_cssl_create_srv_conf,     /* create server configuration */
    ngx_http_cssl_merge_srv_conf,       /* merge server configuration */

    NULL,                              /* create location configuration */
    NULL                               /* merge location configuration */
};



ngx_module_t ngx_http_cssl_module = {
    NGX_MODULE_V1,
    &ngx_http_cssl_module_ctx,          /* module context */
    ngx_http_cssl_commands,             /* module directives */
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
ngx_http_cssl_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_cssl_srv_conf_t  *cscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cssl_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    cscf->cssl_enable = NGX_CONF_UNSET;

    return cscf;
}



static char *
ngx_http_cssl_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cssl_srv_conf_t *prev = parent;
    ngx_http_cssl_srv_conf_t *conf = child;
    ngx_http_ssl_srv_conf_t  *sscf;

    ngx_conf_merge_value(conf->cssl_enable,
                         prev->cssl_enable, 0);
    ngx_conf_merge_str_value(conf->cssl_cert_path,
                             prev->cssl_cert_path, "");

    if (conf->cssl_enable) {
        sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
        if (sscf == NULL || sscf->ssl.ctx == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "cssl no ssl configured for the server");

            return NGX_CONF_ERROR;
        }
        if (conf->cssl_cert_path.len <= 1) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "cssl no ssl path for the server");
            return NGX_CONF_ERROR;
        }

        ngx_log_error(NGX_LOG_INFO, cf->log, 0, "cssl enable ON");

        SSL_CTX_set_cert_cb(sscf->ssl.ctx, ngx_http_cssl_cert_handler, NULL);
    }

    return NGX_CONF_OK;
}



static int
ngx_http_cssl_cert_handler(ngx_ssl_conn_t *ssl_conn, void *data)
{
    ngx_connection_t           *c;
    ngx_http_connection_t      *hc;
    const char                 *servername;
    ngx_str_t                   cert;
    ngx_str_t                   key;
    ngx_http_cssl_srv_conf_t   *cscf;
    ngx_str_t                   host;


    c = ngx_ssl_get_connection(ssl_conn);
    if (c == NULL) {
        return 0;
    }

    hc = c->data;
    if (NULL == hc) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                   "cssl connection data hc NULL");
        return 0;
    }

    servername = SSL_get_servername(ssl_conn, TLSEXT_NAMETYPE_host_name);
    if (servername == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "cssl SSL server name NULL");
        return 1;
    }


    host.len = ngx_strlen(servername);
    if (host.len == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "cssl host len == 0");
        return 1;
    }
    host.data = (u_char *) servername;
    ngx_log_error(NGX_LOG_INFO, c->log, 0, "cssl servername \"%V\"", &host);

    cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_cssl_module);
    if (NULL == cscf) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "cssl cscf NULL");
        return 1;
    }

    if (!cscf->cssl_enable) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "cssl cssl_enable OFF");
        return 1;
    }

    cert.len = cscf->cssl_cert_path.len + 2 + host.len + ngx_strlen(".cert.der");
    key.len = cscf->cssl_cert_path.len + 2 + host.len + ngx_strlen(".key.der");
    cert.data = ngx_pnalloc(c->pool, cert.len);
    if (NULL == cert.data) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "cssl cert.data NULL");
        return 1;
    }
    ngx_memzero(cert.data, cert.len);
    ngx_sprintf(cert.data, "%V/%V.cert.der", &cscf->cssl_cert_path, &host);
    *(cert.data+cert.len) = 0;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "cssl cert %V", &cert);

    key.data = ngx_pnalloc(c->pool, key.len+1);
    if (NULL == key.data) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "cssl key.data NULL");
        return 1;
    }
    ngx_memzero(key.data, key.len);
    ngx_sprintf(key.data, "%V/%V.key.der", &cscf->cssl_cert_path, &host);
    *(key.data+key.len) = 0;

    if (0 != access((const char *)cert.data, F_OK|R_OK)) {
        ngx_log_debug1(NGX_LOG_WARN, c->log, 0, "cssl cert [%V] not exists or not read", &cert);
        return 1;
    }

    ngx_http_cssl_set_der_certificate(ssl_conn, &cert, &key);
    return 1;
}


static int
ngx_http_cssl_set_der_certificate(ngx_ssl_conn_t *ssl_conn, ngx_str_t *cert, ngx_str_t *key)
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

        if (SSL_add0_chain_cert(ssl_conn, x509) == 0) {
            X509_free(x509);
            BIO_free(bio);
            return NGX_ERROR;
        }
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

