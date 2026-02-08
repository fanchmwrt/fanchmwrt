## About
FanchmWrt is an open-source home firewall system.  
This project is based on OpenWrt and incorporates some firewall features.    
Several popular device firmwares have been released and are available for download at [www.fanchmwrt.com](https://www.fanchmwrt.com).   
You can also compile firmwares for other models yourself.

## Development
You can compile the fanchmwrt firmware yourself, Ubuntu 22 is recommended.
Please include the repository address when re-releasing firmware.

### Requirements
You need the following tools to compile FanchmWrt the same as OpenWrt, the package names vary between
distributions. A complete list with distribution specific packages is found in
the [Build System Setup](https://openwrt.org/docs/guide-developer/build-system/install-buildsystem)
documentation.

```
binutils bzip2 diff find flex gawk gcc-6+ getopt grep install libc-dev libz-dev
make4.1+ perl python3.7+ rsync subversion unzip which
```

### Quickstart
Compiling FanchmWrt is the same as compiling OpenWrt; please refer to the OpenWrt compilation tutorial.

1. Run `./scripts/feeds update -a` to obtain all the latest package definitions
   defined in feeds.conf / feeds.conf.default

2. Run `./scripts/feeds install -a` to install symlinks for all obtained
   packages into package/feeds/

3. Run `make menuconfig` to select your preferred configuration for the
   toolchain, target system & firmware packages.

4. Run `make` to build your firmware. This will download all sources, build the
   cross-compile toolchain and then cross-compile the GNU/Linux kernel & all chosen
   applications for your target system.

## License

FanchmWrt is licensed under GPL-2.0

## Upstream Repository
https://github.com/openwrt/openwrt


