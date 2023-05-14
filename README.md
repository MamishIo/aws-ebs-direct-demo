# aws-ebs-direct-demo

A quick demo that showcases using the AWS EBS Direct APIs to read a snapshot, parse its partitions to find a Linux filesystem, interpret it as ext4, and read files/directories.

Does not use any ext4 parsing libraries, since I wanted an excuse to do some kernel deep-diving and learn how disks and filesystems work. It almost certainly has bugs and will be incompatible with many filesystems outside the testing profile.

Tested on Ubuntu 22.04 LTS, and may fail on other distros and other default filesystem settings. E.g. will definitely not work for Amazon Linux 2/2023 since it uses XFS filesystem by default rather than ext4.
