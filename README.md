Name
====

[![Build Status](https://travis-ci.org/vislee/ngx_http_multiple_ssl_module.svg?branch=master)](https://travis-ci.org/vislee/ngx_http_multiple_ssl_module)
[![Coverage Status](https://coveralls.io/repos/github/vislee/ngx_http_multiple_ssl_module/badge.svg?branch=master)](https://coveralls.io/github/vislee/ngx_http_multiple_ssl_module?branch=master)

ngx_http_multiple_ssl_module - Enable Dynamic Load Multiple SSL On Virtual Host Using SNI.

Table of Contents
=================
* [Name](#name)
* [Status](#status)
* [Install](#install)
* [Example Configuration](#example-configuration)
* [Directives](#directives)
    * [multiple_ssl](#multiple_ssl)
    * [multiple_ssl_cert_path](#multiple_ssl_cert_path)
    * [multiple_ssl_servernames](#multiple_ssl_servernames)
* [Author](#author)
* [Copyright and License](#copyright-and-license)


Status
======
The module is currently in active development.

Install
=======

```sh
./configure --prefix=/usr/local/nginx --with-http_ssl_module --add-module=github.com/vislee/ngx_http_multiple_ssl_module
```

[Back to TOC](#table-of-contents)


Example Configuration
====================

```nginx
    server {
        listen       443 ssl default;
        server_name  -;

        ssl_certificate      cert.pem;
        ssl_certificate_key  cert.key;

        multiple_ssl on;
        multiple_ssl_cert_path ./conf/;
        multiple_ssl_servernames *.vis.com vis.com.crt;
        multiple_ssl_servernames www.vislee.com vis.com.crt;

        ssl_session_cache    shared:SSL:1m;
        ssl_session_timeout  5m;

        ssl_ciphers  HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers  on;

        location / {
            proxy_pass http://127.0.0.1;
        }
    }
```


Directives
==========

multiple_ssl
------------
**syntax:** *multiple_ssl <on|off>*

**default:** *off*

**context:** *server*

Enable Dynamic load multiple certificates.

multiple_ssl_cert_path
----------------------
**syntax:** *multiple_ssl_cert_path path*

**default:** *no*

**context:** *http,server*

Specify the certificate path.

  The default cert file format:

  ```

  hostname.crt

  hostname.key

  ```

multiple_ssl_servernames
------------------------
**syntax:** *multiple_ssl_servernames servername crt*

**default:** *no*

**context:** *server*

Specify the mapping of servername and certificate.

[Back to TOC](#table-of-contents)


Author
======

wenqiang li(vislee)

[Back to TOC](#table-of-contents)

Copyright and License
=====================

This module is licensed under the BSD license.

Copyright (C) 2014-2019, by vislee.

All rights reserved.

[Back to TOC](#table-of-contents)