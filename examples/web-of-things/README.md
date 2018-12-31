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

Expose the Web of Things service over a secure port:

```
$ cd ~/src/agent/web-of-things
$ ./tunnel.sh
```
