#!/usr/bin/python
"""
	Wordpress Threat Remover
	Currently this version supports the removal of 
	"eval(gzinflate(base64_decode(" and
	"$GLOBALS["\x61\156\x75\156\x61"]"
	Author : alix@booj.com
	Version: .2
	
	There are two ways to write error-free programs;
	only the third one works.
		-- Alan J. Perlis
"""

import os
import sys
import datetime
import subprocess
import shutil
from argparse import ArgumentParser

the_date     = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
storage_dir  = './results/%s/' % ( the_date )
verbosity    = True
armed        = False

search_for = [ 
	"""eval(gzinflate(base64_decode(""",
	"""<?php if(!isset($GLOBALS["\x61\156\x75\156\x61"]))""",
	"""<?php $nxvqmn = '**#k#)tutjyf`x x22l:!}V;3q%}"""
	]

""" 
	Find the infected files within a single wordpress install

"""
def search( wordpress_path ):
	all_files = [os.path.join(dp, f) for dp, dn, filenames in os.walk( wordpress_path ) for f in filenames ]
	print 'Found %s files to inspect' % len( all_files )
	infected_files = []
	for fname in all_files:
		if fname[-4:] != '.php':
			continue
		with open( fname, 'r' ) as f:
			file_content = f.readlines()
			for line in file_content:
				for search in search_for:
					if search in line:
						if fname not in infected_files:
							infected_files.append( fname )
							break
			f.close()
	for f in infected_files:
		print f
	print 'Found %s infected files' % len(  infected_files )
	return infected_files

"""
	Finds the foriegn code, saves evaluation, backsup file, and removes the code.
	@desc  : 
	@params:
		wordpress_path : str() path to the WP install ex: /srv/wordpress/danberry
		phile_path     : str() infected file to back up, inflate, and clean. 
"""
def evaluate( wordpress_path, phile_path ):
	local_backup_path  = phile_path[ len( wordpress_path ) : phile_path.rfind('.') ] + '.backup' + phile_path[ phile_path.rfind('.') : ]
	local_exploit_path = phile_path[ len( wordpress_path ) : phile_path.rfind('.') ] + '.exploit' + phile_path[ phile_path.rfind('.') : ]
	print phile_path
	print local_backup_path
	print phile_path
	print local_exploit_path

	full_storage_dir = storage_dir + wordpress_path[ wordpress_path.rfind('/') : ]
	if not os.path.exists( full_storage_dir + local_exploit_path[ : local_exploit_path.rfind( '/' ) ] ):
		os.makedirs( full_storage_dir + local_exploit_path[ : local_exploit_path.rfind( '/' ) ] )
	print 'Backing Up:  %s > %s ' % ( phile_path, full_storage_dir + local_backup_path )
	shutil.copy( phile_path, storage_dir + local_backup_path )
	phile_orig    = open( phile_path, 'rb' )
	file_contents = phile_orig.readlines()
	phile_orig.close()
	
	print 'Unpacking Exploited File'
	unpacked   = """/*******   MALICIOUS CODE DO NOT EXECUTE   *******/\n"""
	unpacked  += __unpack_gzip_base64( file_contents[0], local_exploit_path )
	phile_exploit = open( storage_dir + local_exploit_path, 'w+' )
	phile_exploit.write( unpacked )
	phile_exploit.close()

	print 'Cleaning File'
	clean_file = open( phile_path, 'w')
	for line in file_contents[1:]:
		clean_file.write( line )
	clean_file.close()

"""
	Runs a php script which decodes the infected php for inspection later.
"""
def __unpack_gzip_base64( line, report_path ):
	bad_code = line[ line.find("base64_decode('") + 15 : -10 ]
	cmd      = [ 'php', './inflate_decode.php', bad_code ]
	process  = subprocess.Popen( cmd, stdout=subprocess.PIPE)
	out, err = process.communicate()
	malicious_code = out
	return malicious_code

"""
	Finds the malicious_code that we are concerned about 
	and adds the file to a list
"""
def __find_malicious_lines( script ):
    line_count = 1
    malicious_lines = []
    for line in script:
        if 'eval(gzinflate(base64_decode(' in line:
            malicious_lines.append( line_count )
        line_count = line_count + 1
    return malicious_lines

def launch( wordpress_path, args ):
	infected_files = search( wordpress_path )
	if args.clean:
		for phile in infected_files:
			evaluate( wordpress_path, phile )

def parse_args( args ):
  parser = ArgumentParser(description='')
  parser.add_argument('inspect_path', default=False, help='Downloads video urls from welcomemat')
  parser.add_argument('-c','--clean', action='store_true', default=False, help='level')
  args   = parser.parse_args()
  return args

if __name__ == "__main__":
	args = parse_args( sys.argv )
 	launch( args.inspect_path, args )

# End File: WordpressThreatRemover.py