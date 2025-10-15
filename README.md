# boot-it

Boot-it is a simple integrated TFTP/BOOTP daemon for network booting development systems.

## Usage

Boot configurations are provided in .cfg files and are in an ini-like format. The main difference between the cfg file and ini being the comment character (#).

boot-it can be bound to a specific network interface using the `-i` option. For example, `-i eth0` will bind it to the eth0 interface.

### Example Configuration

dev-boot.cfg:
```
# Enable tftp daemon
tftpd = true

# Set the tftp daemon lookup dir. Multiple paths can be provided
path = .

# Configuration for a device with this MAC addr:
[00:06:3B:00:72:23]
file = build-cmake/build-rtems7-uC5282/rtems-init.boot
# Vendor string
vend = "BP_PARM=TEST"
ip = 10.0.0.55
```

Run with:
```
boot-it -c dev-boot.cfg -i eth0
```
