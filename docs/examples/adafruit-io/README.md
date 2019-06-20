# Using Adafruit IO with WoTT Credentials

(https://learn.adafruit.com/welcome-to-adafruit-io)

## Introduction

[Adafruit IO](https://io.adafruit.com) is a free cloud service interested in making IoT accessible to everyone through presenting data in a useful and user-friendly way. Services that they provide include linking your IoT devices to Twitter and weather services. You can also use Adafruit IO to monitor and control temperature sensitive devices; or to change the colours of an RGB lightbulb through their user-friendly dashboard. These are just a few examples of how you can utilise Adafruit's IO.

We're interested in Adafruit IO as it provides a means for us to communicate with our IoT devices via messages through either an MQTT or HTTP service. WWe can therefore interact with Adafruit's services and use our WoTT provided credentials to secure it.

The first thing you will need to do, is to [sign up](https://accounts.adafruit.com/users/sign_up) for Adafruit IO so you can access their [dashboard](https://io.adafruit.com/). Familiarise yourself with their [basic guides](https://learn.adafruit.com/series/adafruit-io-basics). To start, we will need to create a 'Feed.'

## Creating a Feed for MQTT messaging

Login to the Adafruit IO dashboard. Navigate to the 'Feeds' page on the left-hand side menu. Hover over actions and select 'Create a New Feed.' The feed acts as a channel or datastream through which your device connets to Adafruit. We are going to create a feed that connects the devices via MQTT. In other words, the feed becomes the topic from which messages are either published/subscribed to.

The feed name refers to the type of data you are observing- for example temperature or humidity. To keep things simple, we are just going to observe data and name the feed 'data feed.' For the desc



