#############################################################################


				pyHashcat

	Author: Rich Kelley
	Email: RK5DEVMAIL[A T]gmail[D O T]com

	https://github.com/Rich5/pyHashcat.git


#############################################################################

Introduction:
-------------

pyHashcat is small Python module that acts as a simple wrapper to oclHashcat. At it's core pyHashcat is simply passing command arguments to oclHashcat, and providing process management functions. 

List of features:

- Interface with oclHashcat as a Python object
- Run oclHashcat as a background process
- Automatically builds command line arguments based on Python object variable assignment
- Support for stdout stream gobbling
- Support for stderr stream gobbling
- Parse output from oclHashcat files and return data as a Python dictionary data structure with user defined fields
- Parse restore files and return data as a Python dictionary data structure
- Wrapper class has context manager (i.e. with) that will automatically clean-up oclHashcat background process on object termination
- Lookup function for mapping hash types to oclHashcat type codes

After installing the module simply import pyHashcat to begin using the wrapper. Each oclHashcat command line variable is available to be set via the pyHashcat object.See examples below. 
Variables are named nearly the same as identified in oclHashcat help menu except for dashes have been converted to underscores. For example, the command line switch, --markov-threshold 32, would be assigned as, hashcat.markov_threshold = 32. Short-switch arguments will be used if available so in the above case, -t 32, would used as input to the oclHashcat binary. 

Context manager:

You may use the built attack mode functions or send command arguments to the start() function to start oclHashcat as a background process. 
pyHashcat supports context management using Python's "with" keyword to prevent runaway processes, but is not necessary. 

Test mode:

Setting TEST input variable to true will print the command to be sent to the oclHashcat binary without actually starting the process. This feature can be used to debug input. See test example below. 

Installation Instructions:
--------------------------

python setup.py install


Usage examples:
---------------

'''

	From: cudaExample0.cmd using Python context manager

'''


import pyHashcat

with pyHashcat.oclHashcatWrapper(path_to_exe, gcard_type='cuda', verbose=True) as hashcat:

	hashcat.hash_file = "example0.hash"
	hashcat.markov_threshold = 32
	hashcat.words_files.append("example.dict")
	hashcat.mask = "?a?a?a?a"
	hashcat.hybrid_mask_dict()

	while hashcat.is_running():
		print hashcat.stdout()	# Simple Stream gobbler


'''

	From: cudaExample0.cmd without context manager

'''

import pyHashcat

hashcat = pyHashcat.oclHashcatWrapper(path_to_exe, gcard_type='ocl', verbose=True)
hashcat.hash_file = "example0.hash"
hashcat.markov_threshold = 32
hashcat.words_files.append("example.dict")
hashcat.mask = "?a?a?a?a"
hashcat.hybrid_mask_dict()

while hashcat.is_running():
	print hashcat.stdout()

hashcat.stop()


'''

        From: Hybrid-Dictionary attack

'''


import pyHashcat

with pyHashcat.oclHashcatWrapper(path_to_exe, gcard_type='cuda', verbose=True) as hashcat:

        hashcat.hash_file = "example0.hash"
        hashcat.markov_threshold = 32
        hashcat.words_files.append("example.dict")
        hashcat.mask = "?a?a?a?a"
        hashcat.hybrid_dict_mask()

        while hashcat.is_running():
                print hashcat.stdout()  # Simple Stream gobbler





'''

	Example with rules

'''

import pyHashcat

with pyHashcat.oclHashcatWrapper(path_to_exe, gcard_type='cuda', verbose=True) as hashcat:

        hashcat.words_files.append("example.dict")
	hashcat.rules_files.append("best42.rule")
	hashcat.rules_files.append("custom.rule")
	hashcat.hash_type = "NTLM"
        hashcat.straight()
 
        while hashcat.is_running():
                print hashcat.stdout()  # Simple Stream gobbler




'''

	Test example

'''

import pyHashcat

with pyHashcat.oclHashcatWrapper(path_to_exe, gcard_type='cuda', verbose=True) as hashcat:

        hashcat.words_files.append("example.dict")
        hashcat.rules_files.append("best42.rule")
        hashcat.rules_files.append("custom.rule")
        hashcat.hash_type = "NTLM"
        hashcat.straight(TEST=True)	# Will print stdin arguments without starting process
        

'''

	Using the start function	
	NOTE: start function does not support the TEST option
'''

import pyHashcat

with pyHashcat.oclHashcatWrapper(path_to_exe, gcard_type='cuda', verbose=True) as hashcat:

        hashcat.start(argv=["-m", "1000", "-a", "0", "..\\hashes.hash", "dictionary.dict", "-r", "myrules.rule"])

	while hashcat.is_running():
		print hashcat.stdout()

'''

	Parse outfile example

'''


import pyHashcat

with pyHashcat.oclHashcatWrapper(path_to_exe, gcard_type='cuda', verbose=True) as hashcat:

        hashcat.words_files.append("example.dict")
        hashcat.rules_files.append("best42.rule")
        hashcat.rules_files.append("custom.rule")
        hashcat.hash_type = "NTLM"
	hashcat.outfile = "myoutput.txt"
        hashcat.straight()

        while hashcat.is_running():
		pass

	
	print hashcat.get_hashes(fields=('first', 'second', 'third'))





