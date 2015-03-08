cgminer-gc3355
==============

CGMiner 3.72 with GridSeed GC3355 support

./configure --enable-scrypt --enable-gridseed

How to compile on Raspberry PI

1. Update Repos
* `sudo apt-get update`
2. Get dependencies
* `sudo apt-get install build-essential autoconf automake libtool pkg-config libcurl4-gnutls-dev`
* `sudo apt-get install libjansson-dev uthash-dev libncurses5-dev libudev-dev libusb-1.0-0-dev libevent-dev`
3. Clone the Repo
* `git clone https://github.com/dtbartle/cgminer-gc3355.git`
4. Move into the directory, configure, and make the binary.
* `cd cgminer-gc3355`
* `./configure CFLAGS="-O3" --enable-scrypt --enable-gridseed`
* `make`
5. Make cgminer an executable
* `chmod +x cgminer`

GC3355-specific options can be specified via --gridseed-options or
"gridseed-options" in the configuration file as a comma-separated list of
sub-options:

* baud - miner baud rate (default 115200)
* freq - a choice of 250/400/450/500/550/600/650/700/750/800/850/900/950/1000
* pll_r, pll_f, pll_od - fine-grained frequency tuning; see below
* chips - number of chips per device (default 5)
* per_chip_stats - print per-chip nonce generations and hardware failures

If pll_r/pll_f/pll_od are specified, freq is ignored, and calculated as follows:
* Fin = 25
* Fref = int(Fin / (pll_r + 1))
* Fvco = int(Fref * (pll_f + 1))
* Fout = int(Fvco / (1 << pll_od))
* freq = Fout

This version of cgminer turns off all BTC cores so that power usage is low.
On a 5-chip USB miner, power usage is around 10 W. GPUs are also supported.
