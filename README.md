# WoTT IoT Agent

## Pre-requisites

* A Raspberry Pi 2 or newer with Raspbian
* [Docker CE installed](https://docs.docker.com/install/linux/docker-ce/debian/)
  * It is advised that you also run `sudo usermod -aG docker pi` in order to run docker as the user pi without the need for `sudo`
## Building

To build the docker container, simply run:

```
$ mkdir -p ~/src
$ cd ~/src
$ git clone https://github.com/WoTTsecurity/agent.git
$ cd agent/agent
$ docker network create wott
$ ./run.sh
```

You can now find out the device hostname by running:

```
$ docker logs wott-agent | grep hostname
Got hostname: x.d.wott.local
```


### Note on the build process

* The build process is utilizing [multi-stage docker build](https://docs.docker.com/develop/develop-images/multistage-build/) to make sure we don't need to include all tools in the runtime environment.
* `cfssl` and `ghostunnel` will not compile on the same Go version, so we need to use separate versions later. This will likely be resolved upstream, but for the time being, we use a multi-stage process to mitigate this.
