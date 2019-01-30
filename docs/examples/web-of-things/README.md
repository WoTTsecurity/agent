# Securing Web of Things with WoTT

## Hardware requirements

 * A Raspberry Pi (ideally two)
 * A PC running macOS or Linux

### Pre-requisites

 * Install the Dockerized version of the WoTT agent on your Raspberry Pi(s) ([installation instruction](https://github.com/WoTTsecurity/agent/blob/master/docs/alternative_installation_methods.md#installation-docker-runtime))
 * If you're connecting from a PC instead of between the two Raspberry Pis, you also need `curl` installed along with Docker.

### Setup

Build and launch the Web of Things docker container:
```
$ mkdir -p ~/src
$ cd ~/src
$ git clone git@github.com:vpetersson/webofthings.js.git
$ cd webofthings.js
$ git checkout ES6-compatibility
$ docker build -t webofthings .
$ docker run -td \
    --name wott-wot \
    -e SECURE=0 \
    --net wott \
    -p 127.0.0.1:8484:8484 \
    webofthings
```

We can now extract the API token by running:

```
$ docker logs wott-wot | grep Token
My API Token is: Y
```

Let's verify that we're able to connect to the end point locally:

```
$ curl -w "\n" -H "Authorization: Y" localhost:8484
[...]
```
Expose the Web of Things service over a secure port:

```
$ cd ~/src/agent/examples/web-of-things
$ ./tunnel-server.sh
```

We can now verify the mTLS connection locally using OpenSSL:

```
$ openssl s_client \
    -connect localhost:8443 \
    -cert /opt/wott/certs/client.crt \
    -key /opt/wott/certs/client.key \
    -CAfile /opt/wott/certs/ca.crt
[...]
```

We can now connect to the remote server using `curl`. (Note that we do need to add the `--resolve` line and map the WoTT hostname to the IP of the Pi):

```
$ curl -w "\n" \
    --resolve 'X.d.wott.local:8443:192.168.10.10' \
    --cacert /opt/wott/certs/ca.crt \
    --cert /opt/wott/certs/client.crt \
    --key /opt/wott/certs/client.key \
    https://X.d.wott.local:8443
```

Alternatively, if you do not want to alter your hosts file, you can do accomplish the same thing in a Docker container:
```
$ docker run -ti --rm \
    --add-host x.d.wott.local:192.168.10.10 \
    -v /opt/wott/certs:/opt/wott/certs:ro \
    wott-agent bash
```

Once inside the container, you can now run the same `curl` command as above.

The third way to accomplish the same thing is to establish a permanent tunnel between the two nodes. This allows you to offload the mTLS to this tunnel and talk plain text to a local service. To get started with this, we first need to export a few environment variables:

```
$ export WOTT_SERVER_ID=x.d.wott.local
$ export WOTT_SERVER_PORT=8443
$ export WOTT_SERVER_IP=192.168.10.10
$ ./examples/web-of-things/tunnel-client.sh
```

Assuming the you were able to establish the connection and get the tunnel up and running, you should now be able to interact with the remote service using localhost:8080 as follows:

```
$ curl -w "\n" -H "Authorization: Bearer Y" localhost:8080
```
