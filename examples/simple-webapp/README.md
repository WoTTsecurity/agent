# A simple WebApp example

## Introduction

In the following example, we'll walk you through how to secure a simple WebApp using WoTT.

Before you begin, you need two devices with the WoTT Snap installed. This can be either two Raspberry Pis, or a Raspberry Pi and a desktop computer running Linux.

The first thing that we will do is to setup a simple Python WebApp on a Raspberry Pi.

## Setting up the WebApp

```
$ apt-get update && apt-get install -y python3 python3-pip curl
$ mkdir ~/wott-webapp-example
$ cd ~/wott-webapp-example
$ curl -O app.py https://raw.githubusercontent.com/WoTTsecurity/agent/master/examples/simple-webapp/app.py
$ curl -O requirements.txt https://raw.githubusercontent.com/WoTTsecurity/agent/master/examples/simple-webapp/requirements.txt
$ pip3 install -r requirements.txt
$ python3 app.py
[...]
```

You now have a very simple webserver running on your Raspberry Pi. We can test it by running the following in another session:

```
$ curl http://localhost:8080
Hello from WoTT!
```

This webserver is however insecure. The traffic to it is fully unencrypted. When communicating on within the same device, this isn't a major security problem, but as soon as the communication leaves the local device (such as over the network, or even worse, over the internet), this is a big problem. It's then prone to a number of attacks, such as eavesdropping and impersonation attacks.

Let's solve secure this service using the WoTT agent. To do this, we can either by creating a tunnel between the agent and server, or using the WoTT certificates directly in the client (such as in `curl`.). In this example, we'll opt for the former option (i.e. a tunnel).

## Setting up the server

While still leaving the session with our WebApp running, run the following command:

```
$ wott-agent.server
[...]
```

This will create a secure reverse proxy that redirects incoming traffic on port 8443 to the WebApp we started earlier (which is listening on localhost:8080). This will also automagically secure the service using mTLS. Hence, this means that not only is the connection encrypted and secure, it also doubles as a replacement for credentials since we can cryptographically identify the device making the request.

By default, the example allow will allow all clients with a valid certificate signed by WoTT. If we want to lock down the service further, we can for set a policy such that only a given device can access it using:

```
$ CONNECTION_POLICY='--allow-cn=x.d.wott.local' wott-agent.server
[...]
```

## Setting up the client

With the server up and running, we can now move on to the client. This should be another device (either another Raspberry Pi, or a desktop running Linux).

In order to connect to the server, we need to know the following:

 * The IP of the device running the server
 * The WoTT ID of the server (y.d.wott.local)

Once we have this information, all we need to do is to start the client by running:

```
$ export TARGET_IP=192.168.a.b
$ export TARGET_WOTT_ID=y.d.wott.local
$ wott-agent.client
[...]
```

Assuming you don't get any errors, there should now be an established secure tunnel between the client and server. The client is now proxying any request coming in on 127.0.0.1:8080 securely to the remote server (using mTLS).

To verify this, we can now make the same request as we did above using `curl` and get the same result:

```
$ curl http://localhost:8080
Hello from WoTT!
```

## Closing notes

We have now proven how easy it is to setup a secure connection between two devices using WoTT. The WebApp above can simply be replaced with any other application. Just be mindful of that you should always bind your WebApp to on localhost to prevent it from being exposed to the world insecurely.
