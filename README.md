# Parrot Sequoia access information
 Information on accessing the Parrot Sequoia. Use Linux to access most easily.

## Network map
The Parrot Sequoia is accessible through wifi on 192.168.47.1 and through USB on 10.1.1.2.

* Open ports on WIFI
  * 21 FTP (for data access)
  * 22 SSH (requires an unknown root password)
  * 80 HTTP interface (to control the camera)
  * 53 (unknown purpose)
  * 9050 ADB shell
* Open ports on USB
  * 21 FTP (for data access)
  * 22 SSH (requires an unknown root password)
  * 80 HTTP interface (to control the camera)
  * 9050 ADB shell

## Install ADB

On a Linux computer (ideally a Ubuntu or similar distribution):

```bash
sudo apt-get update
sudo apt-get install android-tools-adb
```

Then you can log conntect to the Sequoia and remount the root partition to write onto with
```bash
adb connect 10.1.1.2:9050
adb shell mount -o remount,rw /
adb shell
```

You are now root on the Sequoia with full write permissions.

## Firmware downgrade

Still needs to be figured out

## How to find the relevant information

### Scanning with NMap

To find the IP address, first see if the USB network device is connected. Alternatively, you can of course also do this through the WIFI interface. Then scan it.

```bash
ifconfig
nmap -sP 10.1.1.0/24
```

Assuming that NMap yielded 10.1.1.2 for the IP address, scan the device with
```bash
ifconfig
nmap -NP 10.1.1.2
```

