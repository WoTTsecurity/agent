# (Ubuntu) Snap for WoTT Agent

Packages the WoTT Agent into a Snap.


## Installing

On Ubuntu Core and other Ubuntu installations if `snapd` is logged in all following commands can be executed as user. Otherwise `sudo` is needed.

```
$ snap install wott-agent
```
The "unsafe" interfaces needed by this snap are not auto-connected (may change in the future). Manual connection is needed:
```
$ snap connect wott-agent:network-control :network-control
$ snap connect wott-agent:network-setup-control :network-setup-control
$ snap connect wott-agent:process-control :process-control
$ snap connect wott-agent:system-observe :system-observe
$ snap connect wott-agent:firewall-control :firewall-control
$ snap connect wott-agent:account-control :account-control
$ snap connect wott-agent:log-observe :log-observe
```

## Running

The wott-agent daemon runs automatically. In order to execute commands `sudo` is required:

```
$ sudo wott-agent whoami
```

## Building (locally)

```
$ sudo snap install snapcraft --classic
$ snapcraft
```

Detailed instructions can be found [here](https://forum.snapcraft.io/t/snapcraft-overview/8940).

## Release management

 * Push changes and bump up the version
 * Visit [this launchpad page](https://code.launchpad.net/~vpetersson/wott-agent/+git/wott-agent) and press "Import Now"
 * When the code base has successfully been refreshed above, visit [this page](https://launchpad.net/~wott/+snap/wott-agent) and select 'Request builds'
 * When the builds are done, they will automatically be published to the Candicate channel in the Snap store. You can then promote the Candidate release to Stable on [this page](https://snapcraft.io/wott-agent/releases)
