# aws-ebs-direct-demo

A quick demo that showcases using the AWS EBS Direct APIs to read a snapshot, parse its partitions to find a Linux filesystem, interpret it as ext4, and read files/directories.

(This is going to be hard to read since it's just one giant .py file, about 800 lines at time of writing - I apologise for this but that's just how it grew over time. The main logical sections are split up with big block comments so you can mentally split them up.)

Does not use any ext4 parsing libraries, since I wanted an excuse to do some kernel deep-diving and learn how disks and filesystems work. It almost certainly has bugs and will be incompatible with many filesystems outside the testing profile.

Tested on Ubuntu 22.04 LTS, and may fail on other distros and other default filesystem settings. E.g. will definitely not work for Amazon Linux 2/2023 since it uses XFS filesystem by default rather than ext4.

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
