# Fix import priority on systems with multiple python3 versions,
# e.g. on Jessie with python 3.4 and 3.5 installed.
# Puts python3 dist-packages at the end of the list, which
# effectively gives python3.5 dist-packages more priority.
import sys

print('CUSTOMIZING')
sys.path.remove('/usr/lib/python3/dist-packages')
sys.path.append('/usr/lib/python3/dist-packages')
