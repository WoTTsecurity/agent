## Securing Web of Things with WoTT

### Pre-requisites

 * Web of Things installed and running on a Raspberry Pi
 * Docker installed on the Raspberry Pi
 * A device or computer with `curl` installed along with the WoTT agent

### Setup

Install the WoTT agent on the device:

```
$ mkdir -p ~/src
$ cd ~/src
$ git clone git@github.com:WoTTsecurity/agent.git
$ cd agent/agent
$ ./run.sh
```

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
$ curl -w "\n" -H "Authorization: Bearer Y" localhost:8484
[...]
```


Expose the Web of Things service over a secure port:

```
$ cd ~/src/agent/web-of-things
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

We can now connect to the remote server using `curl`. However, in order to run it locally, you need to add an entry to your `/etc/hosts` file to map the remote device hostname (xyx.d.wott.local to the local IP. Once you've done this, you can run:

```
$ curl -w "\n"
    --cacert /opt/wott/certs/ca.crt
    --cert /opt/wott/certs/client.crt
    --key /opt/wott/certs/client.key
    https://x.d.wott.local:8443
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
