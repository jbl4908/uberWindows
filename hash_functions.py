# Author: John Lawrence
# Description: This file holds the hashing functions for uberWindows

import hashlib
import os
import binascii
try:
    import pefile
except:
    print("[WARNING] pefile Library missing, you will not be able to generate IMPHASH")

def get_md5(file_path):
    # We open the file in read byte formate
    file = open(file_path, "rb")
    data = file.read()
    # Create the md5 hash object
    m = hashlib.md5()
    # Add the data to the object
    m.update(data)
    # Get the digest
    hash = m.hexdigest()
    # Return the digest
    return hash

def get_sha256(file_path):
    # Open the file in read byte format
    file = open(file_path, "rb")
    data = file.read()
    # Create hash object
    m = hashlib.sha256()
    # Add data
    m.update(data)
    # Get the digest
    hash = m.hexdigest()
    return hash

def get_IMPHASH(file_path):
    p = pefile.PE(file_path)
    imphash = p.get_imphash()
    return imphash

def get_digsignature(file_path):
    # Get size of the file
    totsize = os.path.getsize(file_path)
    # Open the PE file with fast load
    file = pefile.PE(file_path, fast_load = True)
    # Parse the directories for IMAGE_DIRECTORY_ENtRY_SECURITY
    file.parse_data_directories(directories= [pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY'] ] )
    # Set offset and length of table
    sigoff = 0
    siglen = 0

    # Get the entry security directory
    for s in file.__structures__:
        if s.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
            sigoff = s.VirtualAddress
            siglen = s.Size

    # Now that we have our information we can close the file
    file.close()

    if sigoff < totsize:
        f = open(file_path, 'rb')
        #move to begininng of signature table
        f.seek(sigoff)
        # read signature table
        thesig = f.read(siglen)
        f.close()

        thesig = thesig[8:]
        return binascii.b2a_uu(thesig)
    else:
        return None

