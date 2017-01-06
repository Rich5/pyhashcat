
# Author: Rich Kelley
# License: MIT

# Build Extention: python setup.py build_ext -R /home/ubuntu/hashcat
# CFLAGS='-Wall -O0 -g' python setup.py build_ext -R /home/ubuntu/hashcat
from distutils.core import setup, Extension

pyhashcat_module = Extension('pyhashcat',
							include_dirs = ['hashcat/include', 'hashcat/deps/OpenCL-Headers', 'hashcat/OpenCL','hashcat'],
							library_dirs = ['/usr/local/lib'],
							libraries = ['hashcat'],
							sources = ['pyhashcat.c'],
							extra_compile_args=['-std=c99']
							)

setup (name ='pyhashcat',
	   version = '2.0',
	   description='Python bindings for hashcat',
	   author='Rich Kelley',
	   author_email='rk5devmail@gmail.com',
	   url='www.bytesdarkly.com',
       ext_modules = [pyhashcat_module])
