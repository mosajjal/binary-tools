
# Binary Toolbox

Various Useful tools as statically linked ELF binaries with no dependencies. Download, use, delete. 

All binaries have been stripped and packed with [upx](https://github.com/upx/upx) in order to have the smallest footprint.

# Filename map (x64)


.. csv-table:: Files
   :file: ./x64-index.csv
   :widths: 30, 70
   :header-rows: 1

# Filename map (ARM5)

|Software                                     |Version  |Filename   |SHA256                                                             |
|---------------------------------------------|---------|-----------|-------------------------------------------------------------------|
| [Brook](https://github.com/txthinking/brook)|20200701 |`brook`    |`268e1e0dfa9b129f83559f6959096fdfba5a6870c019c0666d90f3457cc9cb4f` |
| [Busybox](https://busybox.net)              |1.28.1   |`busybox`  |`ab9f082bf63528eebf1a102427283ad8a3bb243fb9b5f2187a6ed4d641e0175a` |
| [frp](https://github.com/fatedier/frp)      |0.33.0   |`frpc/frps`|`d2c90458d552cfa79b44885515a500c1920a8ae5928001af05c476580e57bd51` |
| [Gotop](https://github.com/cjbassi/gotop)   |3.0.0    |`gotop`    |`450565e4cd4b6d317d760f572c992ee2d01d2d65433fbcc7558a7515b75cc3f8` |
| [pv](https://linux.die.net/man/1/pv)        |1.6.0    |`pv`       |`f2d0b4fdba5929270832e4a6920aff1feb2ec6ae3a576fc2c9a45e7c1e72715b` |
| [Strace](https://github.com/strace/strace)  |4.10     |`strace`   |`9fc5d32b2681827b876b4466565b03ed002d90945253fb7c7745051a2870c79d` |
| [TCPDump](https://www.tcpdump.org/)         |4.7.4    |`tcpdump`  |`f813f9a5448d80a9bda334b94769fb551053d53a679d17f8b4fc58bdb7e5fc7b` |


# Shortened URL

to download these binaries, you can use the shortned URL format 

`wget n0p.me/bin/FILENAME`

# Custom Architectures

URL shortner for custom architectures have been disabled temporarily due to malicious use. It will be available again soon :)


# What is it for

* Testing the tools before searching for them in your package manager (yum, apt, pacman)
* Use in prod servers without having to run package manager
* Use inside Containers (we all know editing the file inside a container is a nightmare)
* Use inside servers with no internet connectivity (`scp`/`docker cp` and run)
* To build the leanest possible Containers out of statically linked binaries rather than a distro image


# A note on Pypack

`pypack` is a great tool to get the latest version of Python running on a Linux machine (CentOS/RHEL 5 or above, libc required). The archive containers a `venv`-like folder with a `python` binary suited to emulate a `virtualenv` but with a full Python, dependency libraries and headers included. The packed version also includes the latest version of pip `python -m pip` and the latest version of `requests` library. 

URL to download the latest `pypack`: [latest](https://n0p.me/pypack/latest) (Python 3.8.3 with the latest `pip` and `requests` as of 2020-06-08)

## Howto

* `cd` to your target parent directory (`~` for example)
* `wget n0p.me/pypack/latest -O latest.tar.gz`
* `tar xf latest.tar.gz`
* `cd py*-env`
* `./python -V`

you can rename and move the folder `py*-env` later on as well with no effect on your packes etc.

NOTE: `pypack` is in alpha and it's not tested on all major distros.
