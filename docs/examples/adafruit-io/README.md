# Using Adafruit IO with WoTT Credentials

example from adafruit 
https://adafruit-io-python-client.readthedocs.io/en/latest/feed-sharing.html#usage-example


## Introduction

[Adafruit IO](https://io.adafruit.com) is a free cloud service interested in making IoT accessible to everyone through presenting data in a useful and user-friendly way. Services that they provide include linking your IoT devices to Twitter and weather services. You can also use Adafruit IO to monitor and control temperature sensitive devices; or to change the colours of an RGB lightbulb through their user-friendly dashboard. These are just a few examples of how you can utilise Adafruit's IO.

We're interested in Adafruit IO as it provides a means for us to communicate with our IoT devices via messages through either an MQTT or HTTP service. WWe can therefore interact with Adafruit's services and use our WoTT provided credentials to secure it.

For this example you will need a device with the WoTT agent installed and a browser. You will also need an Adafruit IO account as well as a WoTT dash account. We will show you to set these up later in the guide if you haven't done so already. You should also have `curl` installed.

## Installing and setting up to use Adafruit IO

The first thing you will need to do, is to [sign up](https://accounts.adafruit.com/users/sign_up) for Adafruit IO so you can access their [dashboard](https://io.adafruit.com/). Familiarise yourself with their [basic guides](https://learn.adafruit.com/series/adafruit-io-basics). For this example, we will be creating a 'Feed.' First however, you will need to have the Adafruit IO client downloaded on your system. We will be using their Python client. 

To install: 

```
$ apt update && apt install -y python3 python3-pip curl
$ pip3 install adafruit-io
```
Now we're all set up, we can create a feed to later call via MQTT.


## Creating a Feed for MQTT messaging

Login to the Adafruit IO dashboard. Navigate to the 'Feeds' page on the left-hand side menu. Hover over actions and select 'Create a New Feed.' The feed acts as a channel or datastream through which your device connets to Adafruit. We are going to create a feed that connects the devices via MQTT. In other words, the feed becomes the topic from which messages are either published/subscribed to.

![create feed](https://github.com/WoTTsecurity/agent/blob/master/docs/examples/adafruit-io/adafruit-add.png)

The feed name refers to the type of data you are observing- for example temperature or humidity. To keep things simple, we are just going to observe data and name the feed 'data feed.' The description is supposed to provide some more in-depth information about the feed. When using sensor data, this is going to be something like temperature or humidity, however for this exmaple we are just dealing with very basic pub/sub messages, so our data type is generic. 

![name feed](https://github.com/WoTTsecurity/agent/blob/master/docs/examples/adafruit-io/feed-details.png)

**Note:** it is possible to create the feeds using a simple python application. If you prefer a more codified style of set up, you can follow [this](https://adafruit-io-python-client.readthedocs.io/en/latest/feeds.html) guide.

## Creating credentials in WoTT dash

In order to call the Adafruit API via HTTP access, it requires a key. You can find this key on the left-hand side of your Adafruit dasboard as you did with 'Feeds' under `AIO key`. You will be brought to a page akin to this:

![aio key](https://github.com/WoTTsecurity/agent/blob/master/docs/examples/adafruit-io/aio-key-modal.png)

These are your unique Adafruit details. We can add these to WoTT's dashboard as a new credential where the value is your personal username followed by the `Active Key` value. To do so, you will need to login or create an account for the [WoTT dash](https://dash.wott.io).

![wott dash](https://github.com/WoTTsecurity/agent/blob/master/docs/examples/adafruit-io/wott-login.png)

If you already have the WoTT dash and have registered your devices, you can skip ahead to inputting the credentials of the device. Otherwise, register your WoTT agent device to the dash by obtaining the Device ID and Claim Token by doing the following commands on said device:

``` 
$ wott-agent whoami
$ wott-aget claim-token
```

and pasting the output into the 'Claim Device' segment of the WoTT dash. This device is now claimed and registered to the WoTT dash. You can view the list of your claimed devices on the main dashboard. Navigate to your newly registered device and add a new tag, `adafruit` to it. Through these tags, WoTT identifies which devices specific credentials are intended for.

![adafruit tags](https://github.com/WoTTsecurity/agent/blob/master/docs/examples/adafruit-io/adafruit-tags.png)

Now that we are all set up, we need to create the credentials with the Adafruit information. Navigate to the 'Credentials' page of the WoTT dash and a new credential. Input the following into the fields:

```
Name = adafruit_aio
Key = credentials
Value = username:key
Tags = adafruit
```

using your relevant information from the Adafruit AIO key.
Note the `adafruit` tag here. Ensure that the device you will be downloading the credentials on has a matching tag.

To download the credential, restart the WoTT Agent by running:

```
$ sudo service wott-agent restart
```
There will now be a JSON file on your system containing your credentials. 

## Setting up Adafruit feed sharing with an MQTT Client

We have included a modified example of the Adafruit feed sharing tutorial in this guide which utilises WoTT's credentials rather than hard coding your details into the application. To run the example:

```
$ mkdir ~/wott-adafruit-mqtt-example
$ cd ~/wott-adafruit-mqtt-example
$ curl -o mqtt_shared_feeds.py https://raw.githubusercontent.com/WoTTsecurity/agent/master/docs/adafruit-io/mqtt_shared_feeds.py
$ sudo python3 mqtt_shared_feeds.py
```


