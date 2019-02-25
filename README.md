# Introduction

This is the source for PublicNTP's GlobalProbe NTP monitoring platform probe code.

# Prerequisites

## pip

    $ sudo apt-get -y install python3-pip

## psycopg2

    $ sudo pip3 install psycopg2-binary

## pause

    $ sudo pip3 install pause

## scapy

    $ sudo pip3 install scapy

# Run

```bash
$ GLOBALPROBE_SITE_ID="[site code]" \
GLOBALPROBE_DB_HOST="[pg host]" \
GLOBALPROBE_DB_PASSWORD="[pg user password]" \
GLOBALPROBE_DB_USER="[pg user]" \
GLOBALPROBE_DB_NAME="[pg db name]" \
nohup ./globalprobe-monitor.py
(ctrl-Z)
$ bg
$ disown %1
```

# Thanks

[David L. Mills](https://www.eecis.udel.edu/~mills/y2k.html) for table of conversion from NTP epoch to UNIX epoch.

[Scapy](https://scapy.net/) for being ridiculously powerful _and_ easy to use.

# Licensing

`globalprobe-monitor` is copyrighted by PublicNTP, Inc. and licensed under the
[MIT License](https://en.wikipedia.org/wiki/MIT_License). Refer to
[LICENSE](https://github.com/PublicNTP/globalprobe-monitor/blob/master/LICENSE)
for the full license text.

