systemctl enable wott-agent.service
systemctl start wott-agent.service
mv /usr/lib/systemd/system/wott-agent-self-update.timer.service /usr/lib/systemd/system/wott-agent-self-update.timer
systemctl enable wott-agent-self-update.timer
systemctl start wott-agent-self-update.timer
