Volatility Profile Discovery
============================

First approach at determining any information about the OS laying into a memory
dump. Based on simple occurences counting, but quite accurate.

Useful for choosing a profile for analysis in Volatility after.

```sh
cd src/
./VolatilityProfileDiscovery DUMP
```

The same things can be done with grep, which may be way faster. But I wanted
something architecture independant.

Works OK for windows and linux.
Doesn't work for osx (yes, osx uses 'windows' object)
