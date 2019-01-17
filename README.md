# WoTT IoT Agent

**WARNING:** This software is yet not ready for production.

## What is this?

**tl;dr** Let's Encrypt for IoT (with more bells and whistles).

The goals for WoTT Agent is to do two things:

 * Simplify encryption of device communication
 * Provide cryptographic identity of sender (such that the receiver can trust that the sender is who it claims to be)

The first build-block we need in order to facilitate encrypted communication between two peers is a cryptographic certificate [1]. This is provisioned automatically through the WoTT agent. At its core, this serves both as the means to enable encrypted communication, as well as each unique device’s identity.

With the certificate installed on the device, we’re able to establish connections to devices and services and cryptographically prove we are whom we claim to be [2]. It’s worth pointing out that this is different than how say your browser works. In such scenario, you as the client (i.e. the browser) verifies that the remote server (e.g. https://www.google.com) is indeed the being served from Google’s server and not an impersonator. There is however no way for Google to cryptographically know that you are who are (which is why you need to login in order to access your email). With WoTT however, we’re able to add this piece, which essentially means that there is no longer a need for username and passwords, since we can cryptographically prove that the client/user is indeed who he/she/it claims to be.

[1] We do this by issuing an x509 certificate from our own Certificate Authority (CA).
[2] This is done using something called Mutual TLS, or mTLS for short.


## Installation: Snap runtime (recommended)

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

For more information, see the [examples](https://github.com/WoTTsecurity/agent/tree/master/examples), in particular the [Simple WebApp example](https://github.com/WoTTsecurity/agent/tree/master/examples/simple-webapp).


## Installation: Docker runtime

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


## Installation:  Python runtime (advanced)

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
