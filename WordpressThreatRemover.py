#!/usr/bin/python
"""
	Wordpress Threat Remover
	Currently this version only supports the removal of "eval(gzinflate(base64_decode("
"""

import os
import sys
import subprocess
import shutil

storage_dir = './results/'
armed        = False

def search( wordpress_path ):
	all_files = [os.path.join(dp, f) for dp, dn, filenames in os.walk( wordpress_path ) for f in filenames ]
	print 'Found %s files to inspect' % len( all_files )
	infected_files = []
	for fname in all_files:
		with open( fname, 'r' ) as f:
			file_content = f.readlines()
			print fname
			print file_content
			if 'eval(gzinflate(base64_decode(' in file_content[0]:
				infected_files.append( fname )
			f.close()
	print 'Found %s infected files' % len(  infected_files )
	return infected_files

def destroy( wordpress_path, phile_path ):
	local_backup_path = phile_path[ len( wordpress_path ) : phile_path.rfind('.') ] + '.backup' + phile_path[ phile_path.rfind('.') : ]
	local_exploit_path = phile_path[ len( wordpress_path ) : phile_path.rfind('.') ] + '.exploit' + phile_path[ phile_path.rfind('.') : ]
	print local_backup_path
	print phile_path
	shutil.copy( phile_path, storage_dir + local_backup_path )
	phile         = open( phile_path, 'rb')
	file_contents = phile.readlines()
	phile.close()
	__unpack_gzip_base64( file_contents[0], local_exploit_path )
	clean_file = open( phile_path, 'w')
	print file_contents[1:]
	clean_file.write( file_contents[1:] )
	clean_file.close()
	sys.exit()

def __unpack_gzip_base64( line, report_path ):
	bad_code = line[ line.find("base64_decode('") + 15 : -10 ]
	cmd = [ 'php', './inflate_decode.php', bad_code ]
	process = subprocess.Popen( cmd, stdout=subprocess.PIPE)
	out, err = process.communicate()
	malicious_code = out
	print report_path
	f = open( storage_dir + report_path, 'w' )
	f.write( malicious_code )
	f.close()

def launch( wordpress_path ):
	infected_files = search( wordpress_path )
	if armed:
		for phile in infected_files:
			print phile
			destroy( wordpress_path, phile )
	else:
		print 'WordpressThreatRemover not armed'

if __name__ == "__main__":
	launch( sys.argv[1] )

# End File
