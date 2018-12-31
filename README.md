Name
====

ngx_http_multiple_ssl_module - Enable Multiple SSL On One IP Using SNI through Virtual Host.

Table of Contents
=================
* [Name](#name)
* [Status](#status)
* [Install](#install)
* [Example Configuration](#example-configuration)
* [Directives](#directives)
    * [security_rule](#security_rule)
    * [security_loc_rule](#security_loc_rule)
* [Author](#author)
* [Copyright and License](#copyright-and-license)


Status
======
The ngx_http_waf_module is currently in active development.

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
        multiple_ssl_cert_path /tmp/nginx/conf/;

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

multiple_ssl_cert_path
----------------------
**syntax:** *multiple_ssl_cert_path path*

**default:** *no*

**context:** *server*

  cert file format:

  ```

  hostname.cert.der

  hostname.key.der

  ```


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