# pyhashcat

Python bindings for hashcat
------

## NOTE: A recent hashcat commit changed the event type calls and the current pyhashcat source is not compatible with the bleeded edge hashcat source. A pyhashcat update is in the works, but it could take some time. 

pyhashcat has been completely rewritten as a Python C extension to interface directly with libhashcat. The pyhashcat module now acts as direct bindings to hashcat.This repository will be changing frequently in the coming weeks.

VERSION: 2.0b2 


Requirements: 
* libhashcat
* Python 2.7

### Install libhashcat and pyhashcat:

```
git clone https://github.com/Rich5/pyHashcat.git
cd pyhashcat/pyhashcat
git clone https://github.com/hashcat/hashcat.git
cd hashcat/
git submodule init
git submodule update
sudo make install_library
cd ..
python setup.py build_ext -R /usr/local/lib
sudo python setup.py install
```

### Simple Test:

```
user@host:~/pyHashcat/pyhashcat$ python test.py
-------------------------------
---- Simple pyhashcat Test ----
-------------------------------
[+] Running hashcat
STATUS:  Cracked
8743b52063cd84097a65d1633f5c74f5  -->  hashcat
```

### Help:

```
import pyhashcat
help(pyhashcat)
```
