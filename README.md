[![CircleCI](https://circleci.com/gh/WoTTsecurity/agent.svg?style=svg)](https://circleci.com/gh/WoTTsecurity/agent) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/9e165c20e9b04d62a15d1ff7c4736878)](https://www.codacy.com/app/vpetersson/agent)

# WoTT IoT Agent

**WARNING:** WoTT is currently in beta. Use in production at your own risk.

---

IoT is becoming a global phenomenom. Virtually any device can now be connected to the internet from smart TVs to fridges with many developers looking to develop their own IoT technology. However with more connectivity comes more security risks; with IoT devices providing more gateways for network attacks and fraudulent access (see [these](https://www.bbc.co.uk/news/technology-38364077) [news](https://www.bbc.co.uk/news/technology-48664251) articles). 

## What is the WoTT Agent and what does it do?

**TL;DR:** Providing simplified security for IoT developers

WoTT aims to reduce that vulnerability by providing the security for you so that you can focus on your development. We want IoT developers to be able to develop their technology comfortable in the knowledge that their devices are secure from end-to-end. 

To do this, WoTT provides a few things:

 * Simplified encryption of device communication
 * Cryptographic identity for your devices (verifying the identity of an accessing device)
 * Enabling the removal of hard coded credentials from your applications and firmware and allowing you greater control of credentials through WoTT
 
# WoTT provided certificates

In order to facilitate encrypted communication between two peers, we need a cryptographic certificate. WoTT provides this through the agent [1]. This serves both as a means for enabling encrypted communication, as well as giving each unique device a recognisable identity. It is this identity and its associated certificate that we use to secure and verify inter-device connection.

With the WoTT Agent certificate installed on a device, we can then establish connections to other devices and services by using the certificate to cryptographically prove the identity of said device [2]. 
**Note**, this is *not* the same as how your browser works. In this scenario, the client (i.e. your browser) verifies that the remote server (e.g. https://www.google.com) is actually being served from Google’s server and not an impersonator. 
There is however no way for Google to cryptographically verify who you are- hence why you are required by Google to login with your details to access your email. 

WoTT's Agent allows you to bypass the need for username/passwords by providing a certificate unique to your device that can be used to verify your identity. It is through these certificates that WoTT secures your devices and allows them to communicate with each other.

* [1] We do this by issuing an x509 certificate from our own Certificate Authority (CA).
* [2] This is done using something called Mutual TLS, or mTLS for short.

# WoTT credentials

This isn't to say that WoTT does away with credentials completely- recall above that we want to grant you more freedom by removing the need for hard coded credentials. WoTT provides a service wherein you can add your own credentials such as API keys or usernames and passwords. This is provided through the [WoTT dash](https://dash.wott.io) which we strongly reccomend that you use and familiarise yourself with. 

## Installation

Supported hardware:

* Raspberry Pi

### Installing on Raspbian

Recommended installation steps:

```
$ curl -s https://packagecloud.io/install/repositories/wott/agent/script.deb.sh | sudo bash
$ sudo apt install wott-agent
```

#### Alternative runtime environments

 * [Python library](https://github.com/WoTTsecurity/agent/blob/master/docs/alternative_installation_methods.md#installation--python-runtime-advance://github.com/WoTTsecurity/agent/blob/master/docs/alternative_installation_methods.md#installation--python-runtime-advanced)


The certificates used for the WoTT Agent can be use for a number of use cases. Here are some ideas to help you get started:

## Use Cases

See below for examples of how to set up and use WoTT Agent enabled devices in the following scenarios

### [Google Core IoT](https://github.com/WoTTsecurity/agent/tree/master/docs/examples/google-core-iot)

Google Cloud Platform provides services that developers can use. Here we show you how to set up your WoTT Agent device and enroll it to your Google Cloud project to communicate with Google's services.


### [Simple WebApp](https://github.com/WoTTsecurity/agent/tree/master/docs/examples/simple-webapp)

A simple example use case of securing a Python 3 WebApp using two WoTT Agent devices acting as server and client. This guide includes an example WebApp, but the principle applies to any WebApp that you develop yourself- just ensure you do the correct setup.

### [Simple WebApp with Basic HTTP Auth access](https://github.com/WoTTsecurity/agent/tree/master/docs/examples/simple-webapp-auth)

Similar to the above use case, here we are setting up a Python 3 WebApp. A WoTT Agent device acts as a server and here we show you how to use WoTT's dashboard to add credentials. These credentials can then be used to set up basic username:password authorisation for access from any other device.

### Credential Management

 * To be written

### TLS/mTLS Access Control

* To be written

### Outdated

 
 * [Web of Things](https://github.com/WoTTsecurity/agent/tree/master/docs/examples/webofthings)
 * [Nginx (mTLS)](https://github.com/WoTTsecurity/agent/tree/master/docs/examples/nginx)
