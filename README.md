# aws-ebs-direct-demo

A quick demo that showcases using the AWS EBS Direct APIs to read a snapshot, parse its partitions to find a Linux filesystem, interpret it as ext4, and read files/directories.

This was a learning exercise so it doesn't use any parsing libraries, is poorly organised and probably isn't very portable.

Tested on a snapshot from a default Ubuntu 22.04 LTS image.

## Setup

```bash
pip3 install -t . requirements.txt
```

## Usage

```bash
python3 ebsd-interactive.py SNAPSHOT_ID
```

(This assumes you already have credentials and CLI/SDK profile/region already set up.)

Use `help` to list commands.
