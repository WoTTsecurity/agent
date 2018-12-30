## Securing Web of Things with WoTT

### Pre-requisites

 * Web of Things installed and running on a Raspberry Pi
 * Docker installed on the Raspberry Pi
 * A device or computer with `curl` installed along with the WoTT agent

### Setup

Install the WoTT agent on the device:

```
$ ./agent/run.sh
```

Build and launch the Web of Things docker container:
```
$ mkdir ~/src
$ cd ~/src
$ git clone git@github.com:vpetersson/webofthings.js.git
$ cd webofthings.js
$ git checkout ES6-compatibility
$ docker build -t webofthings .
$ docker run -t --name wott-wot --net wott -d -p 127.0.0.1:8484:8484 webofthings
```

Expose the Web of Things service over a secure port:

```
$ docker run -d \
    -v /opt/wott/certs:/opt/wott/certs \
    -p 0.0.0.0:8443:8443 \
    wott-agent ghostunnel server \
    --listen 0.0.0.0:8443 \
    --target wott-wot:8484 \
    --keystore /opt/wott/certs/client.crt \
    --cacert /opt/wott/certs/ca.crt \
    --allow-cn *.d.wott.local
```
