# Author: John Lawrence
# Description: These are functions for creating the standardization files. The idea of standardization is gathering
# the current clean state of a box. This state is recorded in standardization text files for each forensic analysis
# function. Our prime example is the running process standardization where we record the current running processes
# (allow of which should be allowed) and then save it for future comparisons. If in the future we do a check and
# a process is not in this standardization file we will display it as PUP/PUA or malicious.

# 1st and 3rd party python libraries
import os
import winreg
import subprocess
from subprocess import PIPE,STDOUT
import base64
import datetime
from shutil import copyfile
import argparse

# Our own python functions
import hash_functions
import registry_functions
import browser_functions

def running_process_standardization():
    path = os.getcwd()

    process_standardization_file = open(path + "\\standards\\running_processes.txt","a+")
    # Get processes result
    # TODO add an option to filter out common processes like svchost and other common processes
    output = subprocess.check_output("wmic process get ParentProcessID, Name, ProcessID, CreationDate, ExecutablePath")
    output = output.decode()
    output = output.split("\r\n")
    # Print them according to the settings given
    for line in output:
        if(line is not '' and line is not (' ')):
            # Now let's add the MD5 Hashes to the output
            process_array = line.split("  ")
            process_array_clean = []
            for entry in process_array:
                if(entry != ''):
                    process_array_clean.append(entry)

            if(len(process_array_clean) == 6):
                process_standardization_file.write(process_array_clean[1] + "\n")
                process_standardization_file.write(process_array_clean[2] + "\n")
            elif(len(process_array_clean) == 5):
                process_standardization_file.write(process_array_clean[1] + "\n")

    process_standardization_file.close()

def running_process_standard(log_file):
    path = os.getcwd()
    process_standardization_file = open(path + "\\standards\\running_processes.txt", "r")
    actual_file = process_standardization_file.read()

    # Get processes result
    # TODO add an option to filter out common processes like svchost and other common processes
    output = subprocess.check_output("wmic process get ParentProcessID, Name, ProcessID, CreationDate, ExecutablePath")
    output = output.decode()
    output = output.split("\r\n")
    # Print them according to the settings given
    count = 0
    for line in output:
        if (count == 0):
            print(line)
            count += 1
        else:
            md5 = ''
            # Now let's add the MD5 Hashes to the output
            process_array = line.split("  ")
            try:
                if process_array[1] is not '':
                    md5 = hash_functions.get_md5(process_array[1])
            except:
                pass

            process_array = line.split("  ")
            process_array_clean = []
            for entry in process_array:
                if (entry != ''):
                    process_array_clean.append(entry)
            # Finally, print our result if its not in the standardization file
            #print(actual_file.split("\n"))
            try:
                # If length is six this means we have both the path and the executable name
                if(len(process_array_clean) == 6):
                    if((process_array_clean[1] in actual_file.split("\n")) and (process_array_clean[2] in actual_file.split("\n"))):
                        pass
                    else:
                        if(log_file is not 0):
                            log_file.write(str(line) + "\n" + "MD5: " + md5 + "\n\n")
                        print(str(line))
                        print("MD5: " + md5)
                        print('')
                # If length is five then we only have the executable name or path
                elif(len(process_array_clean) == 5):
                    if ((process_array_clean[1] in actual_file.split("\n"))):
                        pass
                    else:
                        if (log_file is not 0):
                            log_file.write(str(line) + "\n" + "MD5: " + md5 + "\n\n")
                        print(str(line))
                        print("MD5: " + md5)
                        print('')
            except:
                pass
            count += 1

#running_process_standardization()