#pyhashcat

Python bindings for hashcat
------

Requirements: 
* libhashcat
* Python 2.7

###Install libhashcat and pyhashcat:

```
git clone https://github.com/Rich5/pyHashcat.git
cd pyHashcat
git checkout -b bindings origin/bindings
cd pyhashcat
git clone https://github.com/hashcat/hashcat.git
cd hashcat/
git submodule init
git submodule update
sudo make install
cd ..
python setup.py build_ext -R /usr/local/lib
sudo python setup.py install
```

###Simple Test:

```
user@host:~/pyHashcat/pyhashcat$ python test.py
-------------------------------
---- Simple pyhashcat Test ----
-------------------------------
[+] Running hashcat
STATUS:  Cracked
8743b52063cd84097a65d1633f5c74f5  -->  hashcat
```
