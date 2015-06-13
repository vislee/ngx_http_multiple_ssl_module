# ngx_http_cssl_module

该模块依赖openssl-1.0.1以上版本, `wget https://www.openssl.org/source/openssl-1.0.2a.tar.gz`
使用该模块需要浏览器支持sni。



证书文件名：

```

hostname.cert.der

hostname.key.der

```


配置：
```

cssl_ssl on|off;

# 证书路径
cssl_cert_path /opt/cert;


```