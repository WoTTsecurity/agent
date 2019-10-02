[![CircleCI](https://circleci.com/gh/WoTTsecurity/agent.svg?style=svg)](https://circleci.com/gh/WoTTsecurity/agent) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/9e165c20e9b04d62a15d1ff7c4736878)](https://www.codacy.com/app/vpetersson/agent) [![wott-agent](https://snapcraft.io/wott-agent/badge.svg)](https://snapcraft.io/wott-agent)

# WoTT Agent

## What is this?

**TL;DR:** WoTT provides seamless security audit of linux nodes

Our goal is to improve the security posture of your servers and devices.

Here are some of the things that WoTT will check for:

 * Continuously analyzing your system for known vulnerabilities
   * I.e. a CVE scan of your installed system packages
 * Auditing your services to ensure they are configured securely
   * E.g. making sure your SSH daemon doesn't allow root logins
 * Making it easy to configure your firewall
 * Ensuring that you don't have any insecure services running
   * E.g. rsh and telnet

In addition to this, we also provide:

 * A cryptographic identity to each node, that can be used for access control using Mutual TLS (mTLS).
 * A simple credential management tool to help you remove hard coded credentials and API keys from your system

For more details and installation instructions, please see our [Getting Started Guide](https://wott.io/documentation/getting-started).

You can also browser our [Use cases](https://wott.io/documentation/use-cases) for more inspiration.

## Supported operating systems

| Linux Distribution  | Version | Comment |
| ------------- | ------------- | ---- |
| Ubuntu | 16.04, 18.04 |
| Ubuntu Core | 16, 18| Only works with Snap version |
| Debian/Raspbian | Jessie (8), Stretch (9), Buster (10) |


### Alternative runtime environments

* [Snap](https://github.com/WoTTsecurity/agent/tree/master/snap#ubuntu-snap-for-wott-agent)
* [Docker](https://github.com/WoTTsecurity/agent/blob/master/docs/alternative_installation_methods.md#installation-docker-runtime)
* [Python library](https://github.com/WoTTsecurity/agent/blob/master/docs/alternative_installation_methods.md#installation--python-runtime-advanced)

Due to technical limitations in both Docker and the Snap package, the WoTT agent is unable to perform a full security audit in these environments. For best result, use the Debian package.
