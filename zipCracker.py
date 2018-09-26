# coding=utf-8
#
# Usage:
#
# python zipCracker.py -f target.zip
#
# python zipCracker.py -f target.zip -s 1 -e 6
# 
# python zipCracker.py -f target.zip -d password.txt
#

import sys, time, os, io
from zipfile import ZipFile
from argparse import ArgumentParser
import itertools
import re
try:
    import zlib # We may need its compression method
    crc32 = zlib.crc32
except ImportError:
    zlib = None
    crc32 = binascii.crc32

class SharedFile:
    def __init__(self, file):
        self._file = file
        self._pos = 53 # 41 header + 12 CRC

    def init(self):
    	self._pos = 53

    def read(self, n=-1):
        self._file.seek(self._pos)
        data = self._file.read(n)
        self._pos += n
        return data

    def close(self):
    	pass
        #self._file = None

def _GenerateCRCTable():
    poly = 0xedb88320
    table = [0] * 256
    for i in range(256):
        crc = i
        for j in range(8):
            if crc & 1:
                crc = ((crc >> 1) & 0x7FFFFFFF) ^ poly
            else:
                crc = ((crc >> 1) & 0x7FFFFFFF)
        table[i] = crc
    return table

crcInitTable = _GenerateCRCTable() # only once

class ZipDecrypter:
    def _crc32(self, ch, crc):
        """Compute the CRC32 primitive on one byte."""
        global crcInitTable
        return ((crc >> 8) & 0xffffff) ^ crcInitTable[(crc ^ ord(ch)) & 0xff]

    def __init__(self):
    	pass

    def init(self, pwd):
    	self.key0 = 305419896
        self.key1 = 591751049
        self.key2 = 878082192
        for p in pwd:
            self._UpdateKeys(p)

    def _UpdateKeys(self, c):
        self.key0 = self._crc32(c, self.key0)
        self.key1 = (self.key1 + (self.key0 & 255)) & 4294967295
        self.key1 = (self.key1 * 134775813 + 1) & 4294967295
        self.key2 = self._crc32(chr((self.key1 >> 24) & 255), self.key2)

    def __call__(self, c):
        """Decrypt a single character."""
        c = ord(c)
        k = self.key2 | 2
        c = c ^ (((k * (k^1)) >> 8) & 255)
        c = chr(c)
        self._UpdateKeys(c)
        return c

class ZipExtFile(io.BufferedIOBase):
    """File-like object for reading an archive member.
       Is returned by ZipFile.open().
    """

    # Max size supported by decompressor.
    MAX_N = 1 << 31 - 1

    # Read from compressed files in 4k blocks.
    MIN_READ_SIZE = 4096

    # Search for universal newlines or line chunks.
    PATTERN = re.compile(r'^(?P<chunk>[^\r\n]+)|(?P<newline>\n|\r\n?)')

    def __init__(self, fileobj, mode, zipinfo, decrypter=None,
            close_fileobj=False):
        self._fileobj = fileobj
        self._decrypter = decrypter
        self._close_fileobj = close_fileobj

        self._compress_type = zipinfo.compress_type
        self._compress_size = zipinfo.compress_size
        self._compress_left = zipinfo.compress_size

        if self._compress_type == 8: #ZIP_DEFLATED
            self._decompressor = zlib.decompressobj(-15)
        elif self._compress_type != 0: #ZIP_STORED
            descr = compressor_names.get(self._compress_type)
            if descr:
                raise NotImplementedError("compression type %d (%s)" % (self._compress_type, descr))
            else:
                raise NotImplementedError("compression type %d" % (self._compress_type,))
        self._unconsumed = ''

        self._readbuffer = ''
        self._offset = 0

        self._universal = 'U' in mode
        self.newlines = None

        # Adjust read size for encrypted files since the first 12 bytes
        # are for the encryption/password information.
        if self._decrypter is not None:
            self._compress_left -= 12

        self.mode = mode
        self.name = zipinfo.filename

        if hasattr(zipinfo, 'CRC'):
            self._expected_crc = zipinfo.CRC
            self._running_crc = crc32(b'') & 0xffffffff
        else:
            self._expected_crc = None

    def _update_crc(self, newdata, eof):
        # Update the CRC using the given data.
        if self._expected_crc is None:
            # No need to compute the CRC if we don't have a reference value
            return
        self._running_crc = crc32(newdata, self._running_crc) & 0xffffffff
        # Check the CRC if we're at the end of the file
        if eof and self._running_crc != self._expected_crc:
            raise BadZipfile("Bad CRC-32 for file %r" % self.name)

    def read1(self, n):
        """Read up to n bytes with at most one read() system call."""

        # Simplify algorithm (branching) by transforming negative n to large n.
        if n < 0 or n is None:
            n = self.MAX_N

        # Bytes available in read buffer.
        len_readbuffer = len(self._readbuffer) - self._offset

        # Read from file.
        if self._compress_left > 0 and n > len_readbuffer + len(self._unconsumed):
            nbytes = n - len_readbuffer - len(self._unconsumed)
            nbytes = max(nbytes, self.MIN_READ_SIZE)
            nbytes = min(nbytes, self._compress_left)

            data = self._fileobj.read(nbytes)
            self._compress_left -= len(data)

            if data and self._decrypter is not None:
                data = ''.join(map(self._decrypter, data))

            if self._compress_type == 0: #ZIP_STORED
                self._update_crc(data, eof=(self._compress_left==0))
                self._readbuffer = self._readbuffer[self._offset:] + data
                self._offset = 0
            else:
                # Prepare deflated bytes for decompression.
                self._unconsumed += data

        # Handle unconsumed data.
        if (len(self._unconsumed) > 0 and n > len_readbuffer and
            self._compress_type == 8): #ZIP_DEFLATED
            data = self._decompressor.decompress(
                self._unconsumed,
                max(n - len_readbuffer, self.MIN_READ_SIZE)
            )

            self._unconsumed = self._decompressor.unconsumed_tail
            eof = len(self._unconsumed) == 0 and self._compress_left == 0
            if eof:
                data += self._decompressor.flush()

            self._update_crc(data, eof=eof)
            self._readbuffer = self._readbuffer[self._offset:] + data
            self._offset = 0

        # Read from buffer.
        data = self._readbuffer[self._offset: self._offset + n]
        self._offset += len(data)
        return data

    def close(self):
        try :
            if self._close_fileobj:
                self._fileobj.close()
        finally:
            super(ZipExtFile, self).close()

def _exit(string):
	global parser
	print ('\nExit : ' + string + '\n')
	parser.print_help()
	exit(0)

def _resultExit(count, passwd):
	print('Tried %d passwords and password is: %s' % (count, passwd))
	_timeEnd()
	exit(0)

def _zFile(zFile, fileName, password, info, checkByte, bytes, zefFile, zipDecrypter):
	zefFile.init()
	try:
		zipDecrypter.init(password)
		h = map(zipDecrypter, bytes[0:12])
		if ord(h[11]) != checkByte:
			# error password
			return False
		fileExt = ZipExtFile(zefFile, "r", info, zipDecrypter, True)
		fileExt.read1(1)
	except Exception as e:
		#print(e)
		return False
	return True

def _timeStart():
	global t1
	t1 = time.time()

def _timeEnd():
	global t1
	print('Used time is %d ms' % int((time.time() - t1) * 1000))

def main():
	global parser
	parser = ArgumentParser()
	parser.add_argument('-f', '--file', dest='zipFile', metavar='<filename>', required=True, type=str, help='path to zip file')
	parser.add_argument('-d', '--dictionary', dest='dictionary', metavar='<filename>', type=str, help='path to password dictionary file')
	parser.add_argument('-s', '--start-length', dest='minLength', metavar='N', default=1, type=int, help='minimum length for brute-force - defaults to 1 (only available in no dictionary file)')
	parser.add_argument('-e', '--end-length', dest='maxLength', metavar='N', default=6, type=int, help='maximum length for brute-force - defaults to 6 (only available in no dictionary file)')
	args = parser.parse_args()

	print('')

	_timeStart()

	zFile = ZipFile(args.zipFile)
	namelist = zFile.namelist()
	dictionary = args.dictionary
	minLength = args.minLength
	maxLength = args.maxLength

	zFileName = ''
	for name in namelist:
		if name[-1] != '/':
			zFileName = name
			break
	if zFileName == '':
		_exit('No valid file in zip ')
	info = zFile.getinfo(zFileName)
	if info.flag_bits & 0x8:
		checkByte = (info._raw_time >> 8) & 0xff
	else:
		checkByte = (info.CRC >> 24) & 0xff
	zFile.fp.seek(41)  # sizeFileHeader + fheader[_FH_FILENAME_LENGTH]  30 + 11
	bytesContent = zFile.fp.read(12)
	zef_file = SharedFile(zFile.fp)
	zipDecrypter = ZipDecrypter()
	
	count = 0
	if dictionary is not None:
		f = open(dictionary, 'r')
		content = f.readlines()
		f.close()
		print('%s passwords in dictionary file \n' % len(content))
		for passwd in content:
			count += 1
			if _zFile(zFile, zFileName, passwd.strip('\n\r'), info, checkByte, bytesContent, zef_file, zipDecrypter):
				_resultExit(count, passwd)
	else:
		#characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
		characters = "abcdefghijklmnopqrstuvwxyz"

		for length in range(minLength, maxLength + 1):
			print('Length of password : %s' % length)
			content = itertools.product(characters, repeat=length)
			for pw in content:
				passwd = ''.join(pw)
				count += 1
				if _zFile(zFile, zFileName, passwd, info, checkByte, bytesContent, zef_file, zipDecrypter):
					_resultExit(count, passwd)
	print('Tried %d passwords but no password found ...\n' % count)
	_timeEnd()

if __name__ == '__main__':
	main()