# Another simple WebApp example

## Introduction

In a previous example we introduced you to setting up a [Simple WebApp](https://github.com/WoTTsecurity/agent/tree/master/docs/examples/simple-webapp) using mTLS to provide security. In this example, we'll be using the same WebApp but using HTTP Basic Auth instead. 

As with the previous example, you will need two devices with the WoTT Agent installed that are either a Raspberry Pi or a Debian machine. For this example, you will also need to have set up your devices on the [WoTT Dashboard](dash.wott.io)

*In order to set the WebApp up, you will be following similar instructions.*

## Setting up the WebApp

(directly cloned and adapted from simple web app)

```
$ apt update && apt install -y python3 python3-pip curl
$ mkdir ~/wott-webapp-auth-example
$ cd ~/wott-webapp-auth-example
$ curl -o app.py https://raw.githubusercontent.com/WoTTsecurity/agent/master/docs/examples/simple-webapp-auth/app.py
$ curl -o requirements.txt https://raw.githubusercontent.com/WoTTsecurity/agent/master/docs/examples/simple-webapp-auth/requirements.txt
$ pip3 install -r requirements.txt
$ python3 app.py
[...]
```

*I'm not sure if this will work yet*

Once again, to test your connection on your server device, run:

``` 
$ curl http://localhost:8080
Hello from WoTT!

```

