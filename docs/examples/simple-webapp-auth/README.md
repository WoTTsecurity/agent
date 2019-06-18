# Another simple WebApp example

My Simple WebApp
Web App Credentials
username:password

curl command for logging in via terminal"
curl http://username:password@serverIP:port

## Introduction

In a previous example we introduced you to setting up a [Simple WebApp](https://github.com/WoTTsecurity/agent/tree/master/docs/examples/simple-webapp) using mTLS to provide security. This is one of a few ways to secure connection between a client and a server.

In this example, we'll be using another simple WebApp that instead uses HTTP Basic Auth to verify login and access.

You will need 1 device (Raspberry Pi or Debian Machine) with the WoTT Agent installed and have it registered to the [WoTT Dashboard](dash.wott.io) and a web browser to access it (either on a different device or the same one).

## Using WoTT Dashboard

WoTT provides an online client that you can interface with to register your WoTT Agent enabled devices. We strongly encourage you to do so in the interests of protecting your IoT devices. 

For this example, you will need to have the WoTT Dash set up, so if you haven't done so already, register with the link above and enrol your devices (done during the initial installation of the WoTT agent). If you already have done this, just log into the dashboard with your username and password.


## Adding Credentials


Once you have your devices enrolled, you need to navigate to the Credentials page in the Dashboard. You will need to add a credential to use to access the WebApp later. 
The credential subheaders may seem a little confusing. In essence, `Name` refers to the name of the application you need credentials for. In our case, it's the simple WebApp. The `Key` is how the application then queries its credentials with `Value` referring to the actual contents of the key (the secure bit). 
For our example, add a credential of the following layout:

```
Name: my_simple_web_app
Key: web_app_credentials
Value: username:password

```

In place of `username:password` you can enter your own username and password but it is sufficient for this demonstration to leave it as is. 

The credentials are now ready to be used on all your WoTT enabled devices. On your server device, you will now need to relaunch the WoTT Agent to download the new credentials:

``` 
$ sudo service wott-agent restart

```
There will now be a JSON file in your WoTT agent's credentials with your information which the app will parse and process. 

**Note:** If you change the name of credentials, you will need to edit the name JSON file within the app as it currently assumes you have named it `my_simple_web_app` as per instructions.

## Setting up the WebApp

As with the other example, you will need to download the WebApp files into a new directory. Use `sudo` where necessary. 

```
$ apt update && apt install -y python3 python3-pip curl
$ mkdir ~/wott-webapp-auth-example
$ cd ~/wott-webapp-auth-example
$ curl -o app.py https://raw.githubusercontent.com/WoTTsecurity/agent/master/docs/examples/simple-webapp-auth/app.py
$ curl -o requirements.txt https://raw.githubusercontent.com/WoTTsecurity/agent/master/docs/examples/simple-webapp-auth/requirements.txt
$ pip3 install -r requirements.txt
$ sudo python3 app.py

```

This will start your app on the server 127.0.0.1 at port 8080. You should receive a response like so:

```
* Serving Flask app "app" (lazy loading)
* Environment: production
  WARNING: Do not use for the development server in a production environment.
  Use a production WSGI server instead.
* Debug mode: Off
* Running on http://127.0.0.1:8080/ (Press CTRL+C to quit)

```

Launch http://127.0.0.1:8080/ on your browser's device. Here you'll be prompted to enter a username and password. 
