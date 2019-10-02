# (Ubuntu) Snap for WoTT Agent

Packages the WoTT Agent into a Snap.

[Installation inscructions](https://github.com/WoTTsecurity/agent/blob/master/docs/alternative_installation_methods.md#snap-runtime)

## Building (locally)

```
$ sudo snap install snapcraft --classic
$ snapcraft
```

Detailed instructions can be found [here](https://forum.snapcraft.io/t/snapcraft-overview/8940).

## Release management

 * Push changes and bump up the version
 * When the code base has successfully been refreshed above, visit [this page](https://launchpad.net/~wott/+snap/wott-agent) and select 'Request builds'
 * When the builds are done, they will automatically be published to the Candicate channel in the Snap store. You can then promote the Candidate release to Stable on [this page](https://snapcraft.io/wott-agent/releases)
