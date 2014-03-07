cgminer-gc3355
==============

CGMiner 3.72 with GridSeed GC3355 support

./configure --enable-scrypt --enable-gridseed

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
