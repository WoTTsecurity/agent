#!/bin/bash
systemctl stop wott-agent.service
systemctl disable wott-agent.service
systemctl stop wott-agent-self-update.timer
systemctl disable wott-agent-self-update.timer
rm /usr/lib/systemd/system/wott-agent-self-update.timer
systemctl daemon-reload
