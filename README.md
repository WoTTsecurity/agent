# WoTT IoT Agent

## Building

To build the docker container, simply run:

```
$ cd agent
$ docker create network wott
$ ./run.sh
```

### Note on the build process

* The build process is utilizing [multi-stage docker build](https://docs.docker.com/develop/develop-images/multistage-build/) to make sure we don't need to include all tools in the runtime environment.
* `cfssl` and `ghostunnel` will not compile on the same Go version, so we need to use separate versions later. This will likely be resolved upstream, but for the time being, we use a multi-stage process to mitigate this.
