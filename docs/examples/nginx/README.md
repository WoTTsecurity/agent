# Using WoTT with Nginx

WoTT can be used to cryptographically authenticate a client connecting to an Nginx server. This is useful as it essentially replaces the need for credentials. Instead, you can whitelist devices based on the WoTT Device ID.

Before we begin, we need to install the WoTT cert-bundle installed on the Nginx server. You can retrieve this directly using the WoTT API:

```
$ curl -s https://api.wott.io/v0.2/ca-bundle | jq -r '.ca_bundle' > /path/to/cert-bundle.crt
```

In addition, you also need a valid SSL certificate installed on the server. You can either use our existing provider, or retrieve one for free from [Let's Encrypt](https://letsencrypt.org/).

Now, let's say we have an appserver running on localhost:8000 and that we want to protect using mTLS. Using the [ssl_client_certificate](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_client_certificate) stanza in Nginx, we're able to block all connections that fail to provide a valid certificate (i.e. not signed by the WoTT CA).

Here's how a minimal config would look like:

```
upstream appserver {
    server localhost:8000;
}

server {
    server_name mtls.mydomain.com;
    listen 443 ssl;

    # mTLS block for WoTT
    if ($ssl_client_verify != "SUCCESS") { return 403; }
    ssl_client_certificate /path/to/cert-bundle.crt;
    ssl_verify_depth 2;
    ssl_verify_client on;

    # This can be a Let's Encrypt certificate
    ssl_certificate     /etc/ssl/mydomain.com.crt;
    ssl_certificate_key /etc/ssl/mydomain.com.key;

    location / {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header SSL_Client $ssl_client_s_dn;
        proxy_set_header SSL_Client_Verify $ssl_client_verify;
        proxy_pass http://appserver;
    }
}
```

There are a few things to point out here:

 * You can use a regular SSL certificate (for instance issued by Let's Encrypt) here as the Nginx will only use it to verify the client's keys.
 * In the above configuration **any** device with a valid WoTT device certificate would be able to access the service. You can create a whitelist of approved devices either inside your appserver (by using the `SSL_CLIENT` header) or directly in Nginx using something like Lua.


