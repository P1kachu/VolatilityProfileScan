Volatility Profile Discovery
============================

First approach at determining any information about the OS lying into a memory
dump. Based on simple occurences counting, but quite accurate.

Useful for choosing a profile for analysis in Volatility after.

The same things can be done with grep, which may be way faster. But I wanted
something architecture independant and which fits into Volatility.

Works OK for windows, mac and linux (haven't tried for anything else yet, like
android and stuff).

## Demo on the batch of samples from AMF:

This is a small sample of what the plugin can do when asked to recover the dump's
OS with a minimum of 20 caracteristic executable. This means, an OS 'wins' only
when 90% minimum of the executables found are his (exe->windows, elf->linux...),
with at least 20 executables found.

linux-sample-1.bin
Volatility Foundation Volatility Framework 2.5
Found OS: Linux (100%)
real	0m34.876s
user	0m34.723s
sys	0m0.083s

/dumps/linux-sample-2.bin
Volatility Foundation Volatility Framework 2.5
Found OS: Linux (100%)
real	0m25.395s
user	0m25.297s
sys	0m0.077s

/dumps/linux-sample-3.bin
Volatility Foundation Volatility Framework 2.5
Found OS: Linux (100%)
real	0m18.173s
user	0m18.107s
sys	0m0.063s

/dumps/linux-sample-4.bin
Volatility Foundation Volatility Framework 2.5
Found OS: Linux (100%)
real	0m18.037s
user	0m17.937s
sys	0m0.063s

/dumps/linux-sample-5.bin
Volatility Foundation Volatility Framework 2.5
Found OS: Linux (100%)
real	0m18.300s
user	0m18.253s
sys	0m0.043s

/dumps/linux-sample-6.bin
Volatility Foundation Volatility Framework 2.5
Found OS: Linux (100%)
real	0m47.042s
user	0m46.973s
sys	0m0.060s

/dumps/mac-sample-1.bin
Volatility Foundation Volatility Framework 2.5
Found OS: OSX (100%)
real	0m16.900s
user	0m16.830s
sys	0m0.063s

/dumps/mac-sample-2.bin
Volatility Foundation Volatility Framework 2.5
Found OS: OSX (100%)
real	0m14.508s
user	0m14.457s
sys	0m0.047s

/dumps/mac-sample-3.bin
Volatility Foundation Volatility Framework 2.5
Found OS: OSX (100%)
real	0m32.668s
user	0m32.590s
sys	0m0.070s

/dumps/mac-sample-4.bin
Volatility Foundation Volatility Framework 2.5
Found OS: OSX (100%)
real	0m7.121s
user	0m7.060s
sys	0m0.060s

/dumps/sample001.bin
Volatility Foundation Volatility Framework 2.5
Found OS: Windows (100%)
real	0m33.015s
user	0m32.920s
sys	0m0.053s

/dumps/sample002.bin
Volatility Foundation Volatility Framework 2.5
Found OS: Windows (100%)
real	0m18.804s
user	0m18.737s
sys	0m0.063s

/dumps/sample003.bin
Volatility Foundation Volatility Framework 2.5
Found OS: Windows (100%)
real	0m21.384s
user	0m21.310s
sys	0m0.067s

/dumps/sample004.bin
Volatility Foundation Volatility Framework 2.5
Found OS: Windows (100%)
real	0m40.201s
user	0m40.110s
sys	0m0.083s

/dumps/sample005.bin
Volatility Foundation Volatility Framework 2.5
Found OS: Windows (100%)
real	0m29.602s
user	0m29.487s
sys	0m0.057s

/dumps/sample006.bin
Volatility Foundation Volatility Framework 2.5
Found OS: Windows (100%)
real	0m6.694s
user	0m6.640s
sys	0m0.050s

/dumps/sample007.bin
Volatility Foundation Volatility Framework 2.5
Found OS: Windows (100%)
real	0m28.082s
user	0m27.987s
sys	0m0.057s

/dumps/sample008.bin
Volatility Foundation Volatility Framework 2.5
Found OS: Windows (100%)
real	0m6.456s
user	0m6.403s
sys	0m0.050s

/dumps/sample009.bin
Volatility Foundation Volatility Framework 2.5
Found OS: Windows (100%)
real	0m27.764s
user	0m27.710s
sys	0m0.050s
