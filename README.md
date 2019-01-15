# WoTT IoT Agent


## Snap runtime (recommended)

### Pre-requisites

* A Raspberry Pi 2 or newer with Raspbian or Ubuntu Core

### Installing

If you're using Raspbian, follow [these instructions](https://docs.snapcraft.io/installing-snap-on-raspbian/6754) first to install `snapd`.

Once you have `snapd` installed (included if you are using Ubuntu Core), simply install the WoTT agent by running:

```
$ snap install wott-agent
$ snap start wott-agent
```

You can now find your device's WoTT ID by running:

```
$ wott-agent.whoami
```

It's also worth noting that the certificates can be found on disk within the folder `/var/snap/wott-agent/current`.

## Docker runtime

### Pre-requisites

* A Raspberry Pi 2 or newer with Raspbian
* [Docker CE installed](https://docs.docker.com/install/linux/docker-ce/debian/)
  * It is advised that you also run `sudo usermod -aG docker pi` in order to run docker as the user pi without the need for `sudo`

### Building

To build the docker container, simply run:

```
$ mkdir -p ~/src
$ cd ~/src
$ git clone https://github.com/WoTTsecurity/agent.git
$ cd agent
$ docker network create wott
$ ./bin/run.sh
```

You can now find out the device's WoTT ID by running:

```
$ docker logs wott-agent | grep wott
Got WoTT ID: x.d.wott.local
```

#### Note on the build process

* The build process is utilizing [multi-stage docker build](https://docs.docker.com/develop/develop-images/multistage-build/) to make sure we don't need to include all tools in the runtime environment.


### Python runtime (advanced)

It is possible to run the WoTT agent without Docker. To do this on a Raspbian Stretch device, run the following command:

```
$ git clone https://github.com/WoTTsecurity/agent.git
$ cd agent
$ sudo apt-get install python3 python3-pip python3-virtualenv
$ virtualenv -p python3 ~/.wott-venv
$ source ~/.wott-venv/bin/activate
$ pip install -r requirements.txt
$ python setup.py install
```

You now have all the dependencies installed (with the exception of `ghostunnel`, which is used for end-to-end tunnels).

To start the agent, you just need to run:

```
$ sudo ~/.wott-venv/bin/python wott-agent
```

