# Example taken and adapted from https://adafruit-io-python-client.readthedocs.io/en/latest/feed-sharing.html#usage-example

# Import standard python modules.
import sys
import time
import random
import json

# Import Adafruit IO MQTT client.
from Adafruit_IO import MQTTClient

# Importing and splitting WoTT's credentials into username and key
with open('/opt/wott/credentials/adafruit/adafruit_aio.json', 'r') as creds:
    creds_info = json.load(creds)

creds_values = creds_info['credentials'].split(":")

# Taken from WoTT credentials
ADAFRUIT_IO_USERNAME = creds_values[0]

# Taken from WoTT credentials
ADAFRUIT_IO_KEY = creds_values[1]

# Shared IO Feed
# Make sure you have read AND write access to this feed to publish.
IO_FEED = 'data feed'

# IO Feed Owner's username
IO_FEED_USERNAME = creds_values[0]


# Define callback functions which will be called when certain events happen.
def connected(client):
    """Connected function will be called when the client connects.
    """
    client.subscribe(IO_FEED, IO_FEED_USERNAME)


def disconnected(client):
    """Disconnected function will be called when the client disconnects.
    """
    print('Disconnected from Adafruit IO!')
    sys.exit(1)


def message(client, feed_id, payload):
    """Message function will be called when a subscribed feed has a new value.
    The feed_id parameter identifies the feed, and the payload parameter has
    the new value.
    """
    print('Feed {0} received new value: {1}'.format(feed_id, payload))


# Create an MQTT client instance.
client = MQTTClient(ADAFRUIT_IO_USERNAME, ADAFRUIT_IO_KEY)

# Setup the callback functions defined above.
client.on_connect = connected
client.on_disconnect = disconnected
client.on_message = message

# Connect to the Adafruit IO server.
client.connect()

client.loop_background()
print('Publishing a new message every 10 seconds (press Ctrl-C to quit)...')

while True:
    value = random.randint(0, 100)
    print('Publishing {0} to {1}.'.format(value, IO_FEED))
    client.publish(IO_FEED, value, IO_FEED_USERNAME)
    time.sleep(10)
