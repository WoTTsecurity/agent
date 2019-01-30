# Using WoTT with Nginx

WoTT can be used to cryptographically authenticate a client connecting to an Nginx server. This is useful as it essentially replaces the need for credentials. Instead, you can whitelist devices based on the WoTT Device ID.

Before we begin, we need to install the WoTT agent on the server running Nginx. You can do this either

Let's say we have an appserver running on localhost:8000 and we then want t

@TODO finish


```
upstream appserver {
    server localhost:8000;
}

server {
    server_name mtls.mydomain.c;
    listen 443 ssl;

    if ($ssl_client_verify != "SUCCESS") { return 403; }

    ssl_certificate /opt/wott/certs/client.crt;
    ssl_certificate_key /opt/wott/certs/client.key;
    ssl_client_certificate /opt/wott/certs/cert-bundle.crt;
    ssl_verify_depth 2;
    ssl_verify_client on;

    location / {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header SSL_Client $ssl_client_s_dn;
        proxy_set_header SSL_Client_Verify $ssl_client_verify;
        proxy_pass http://appserver;
    }
}
```
