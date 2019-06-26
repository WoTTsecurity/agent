# Using Adafruit IO with WoTT Credentials

example from adafruit 
https://adafruit-io-python-client.readthedocs.io/en/latest/feed-sharing.html#usage-example


## Introduction

[Adafruit IO](https://io.adafruit.com) is a free cloud service interested in making IoT accessible to everyone through presenting data in a useful and user-friendly way. Services that they provide include linking your IoT devices to Twitter and weather services. You can also use Adafruit IO to monitor and control temperature sensitive devices; or to change the colours of an RGB lightbulb through their user-friendly dashboard. These are just a few examples of how you can utilise Adafruit's IO.

We're interested in Adafruit IO as it provides a means for us to communicate with our IoT devices via messages through either an MQTT or HTTP service. WWe can therefore interact with Adafruit's services and use our WoTT provided credentials to secure it.

The first thing you will need to do, is to [sign up](https://accounts.adafruit.com/users/sign_up) for Adafruit IO so you can access their [dashboard](https://io.adafruit.com/). Familiarise yourself with their [basic guides](https://learn.adafruit.com/series/adafruit-io-basics). To start, we will need to create a 'Feed.'

For this example, you will need a device with the WoTT Agent installed. 

## Creating a Feed for MQTT messaging

Login to the Adafruit IO dashboard. Navigate to the 'Feeds' page on the left-hand side menu. Hover over actions and select 'Create a New Feed.' The feed acts as a channel or datastream through which your device connets to Adafruit. We are going to create a feed that connects the devices via MQTT. In other words, the feed becomes the topic from which messages are either published/subscribed to.

![create feed](https://github.com/WoTTsecurity/agent/blob/master/docs/examples/adafruit-io/adafruit-add.png)

The feed name refers to the type of data you are observing- for example temperature or humidity. To keep things simple, we are just going to observe data and name the feed 'data feed.' The description is supposed to provide some more in-depth information about the feed. When using sensor data, this is going to be something like temperature or humidity, however for this exmaple we are just dealing with very basic pub/sub messages, so our data type is generic. 

![name feed](https://github.com/WoTTsecurity/agent/blob/master/docs/examples/adafruit-io/feed-details.png)

**Note:** it is possible to create the feeds using a simple python application. If you prefer a more codified style of set up, you can follow [this](https://adafruit-io-python-client.readthedocs.io/en/latest/feeds.html) guide.

## Creating credentials

In order to call the Adafruit API via HTTP access, it requires a key. You can find this key on your Adafruit dasboard under `AIO key`. We can add this to WoTT's dashboard as a new credential where the value is your username followed by the key value. Input something like this:

```
Name = adafruit_aio
Key = credentials
Value = username:key
Tags = adafruit
```

and add an appropriate tag, we have chosen `adafruit`. Ensure that the device you will be downloading this certificate on has the correct tag.


