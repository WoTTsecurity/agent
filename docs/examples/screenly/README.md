# Using WoTT to secure access to Screenly

## Introduction

Screenly is a service that provides digital signage and acts as an OS on the host device. Essentially it treats your host device as a streaming service that projects visual media (such as images and webpages) onto a monitor from multiple different sources. Think of it as a manager for your visual media- you send the content via a browser on the Screenly management page, and the host device projects that content onto a monitor.

Screenly by default allows anyone with the management page IP address to access it and send content. However, it does also provide HTTP authentication- and we can use WoTT's credentials to secure our Screenly device so that we can restrict and verify those who have access to it.