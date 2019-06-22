# Using WoTT to secure access to Screenly

## Introduction

Screenly is a service that provides digital signage and acts as an OS on the host device. Essentially it treats your host device as a streaming service that projects visual media (such as images and webpages) onto a monitor from multiple different sources. Think of it as a manager for your visual media- you send the content via a browser on the Screenly management page, and the host device projects that content onto a monitor.

Screenly by default allows anyone with the management page IP address to access it and send content. However, it does also provide HTTP authentication- and we can use WoTT's credentials to secure our Screenly device so that we can restrict and verify those who have access to it. 

Screenly offers a free OSE version that you can use. For this example you will need a Raspberry Pi, a monitor for Screenly to project onto; and at least one browser device. You will also need to have an account for the [WoTT Dashboard](https://dash.wott.io) in order to manage WoTT credentials.

## Installing WoTT agent on Screenly OSE

First you will need a Screenly device if you do not already.
Follow the instructions to install Screenly OSE (the free version) on your Raspberry Pi [here](https://www.screenly.io/ose/). We reccommend you follow the first option and use something like Etcher to flash the SD card with the Screenly boot. 
**Note** Screenly will overwrite your OS.

When the Raspberry Pi reboots, it will take you to the Screenly network configuration. You will need to access the SSID as you would a wifi network. This will grant you access to the Screenly management page. Now we need to secure access to your Screenly device. The first step towards this is installing the [WoTT Agent](https://github.com/WoTTsecurity/agent) which you should be familiar with.

To do this on the Screenly device, you need to access the terminal through `CTRL` + `ALT` + `F1`. To return back to the GUI, it is `CTRL` + `ALT` + `F2`. 
Once here, follow the WoTT agent installation as you would on any other device. 

**Optional:** If you want to avoid using the terminal directly on your Screenly device in the future, enable SSH through the `sudo raspi-config` command. It is also reccommended that you change your User and Password from the default `pi` and `raspberry` (this will also improve your WoTT security score!) if you are going to do this.

You will now need to register the pi on the WoTT dashboard. 


## Securing Screenly OSE with WoTT credentials 

Login to the WoTT Dash and navigate to 'Claim Device.' If you have installed the WoTT agent recently, the relevant information should be displayed on your terminal screen. If not, use the following commands:

``` 
$ sudo wott-agent whoami
$ sudo wott-aget claim-token
```

This will give you your Device ID and the token value to claim your device. 

Your raspberry pi should now be registered. Navigate to your Dashboard and select the Pi:

![pi](https://github.com/WoTTsecurity/agent/blob/master/docs/examples/screenly/rasbpi.png)

On the overview page, add a tag. This will be important for the credentials. This tag can be whatever you want, however we suggest something like `screenly-pi` or `pi` or a variant of that form:

![tag](https://github.com/WoTTsecurity/agent/blob/master/docs/examples/screenly/tag.png)

Now navigate to credentials and add a new credential with the following details:

```
Name = screenly
Key = login
Value = username:password
Owner = user
Tags = screenly-pi
```
Where the Owner is the name of the device running Screenly (so by default, `pi`). 
You can change the Name value of `screenly` if you wish, but note that this is how WoTT will call the credential information, so if you do change this name, be aware to use the correct credential name. Make sure as well that the Tags match whatever Tag you assigned the Pi earlier.

You now need to set up the screenly configuration file to call the WoTT credentials. This file is in a hidden folder, so to access it do the following:

```
$ vi ~/.screenly/screenly.conf
```

This will open the config file in Vi. Add the following lines to the config:

```
[auth_wott]
wott_secret_name = screenly
```

and `ESC` + `:wq` to save.

Your credentials are now all set up. To download them onto the device, restart WoTT on your Pi:

```
$ service wott-agent restart
```


