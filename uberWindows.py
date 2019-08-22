# Author: John Lawrence
# Description: A python platform that consolidates retrieval of various windows artifacts for forensic analysis.
# Date: July 19th, 2019
# Version: 1.2
# TODO interface with the Virustotal API for anomalous findings, try adding it to the hash functions
# TODO check digital signatures of files/executables using powershell
# The current way I try to access Edge history doesn't work as I don't get permission even as admin!
# TODO perhaps an uberLinux someday????
# Work on downselects, use some opensource tools to infect and see if uberWindows can find it.
# TODO a good idea for a downselect would be cataloging a normal state computer and using that for comparison
# TODO add a means of checking for usb history with USBStor and such

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
import standardization_functions

# -------------------Argument Parser--------------------------
parser = argparse.ArgumentParser()
# Arguments
parser.add_argument("-l", '--logging', help='Enable logging at start', required=False, action='store_true')
# Parse
args = parser.parse_args()



# Main Menu +++++++++++++++++++++++++++++++++++++++
# This gets our path we are working in
path = os.getcwd()

def main():
    log_path = ""
    log_file = 0
    if (args.logging):
        # Open the log in the global log variables so other functions can write to it
        now = str(datetime.datetime.now())
        now = now.replace('.', '')
        now = now.replace(':', '')
        now = now.replace('-', '')
        log_path = ((path + "\output\OutputLog_" + str(now) + ".txt").replace(' ', ''))
        log_file = open(log_path, "a+")
        print("Now logging all actions to: " + log_path)

    try:
        os.mkdir(path + "\output")
    except:
        pass

    try:
        os.mkdir(path + "\\standards")
    except:
        pass


    # Opening ASCII art
    print(" __     __ ")
    print("|**|   |**|   __")
    print("|**|   |**|  |**|      _______     ___")
    print("|**|   |**|  |**|     |*******|   |***|____")
    print("|**|   |**|  |**|___  |**|  |*|   |********|")
    print("|**|   |**|  |******| |*******|   |***| |**|")
    print("|*********|  |*|  |*| |**|___     |***|")
    print("|*********|  |******| |******|    |***|")
    print("\n")

    while True:
        # Menu
        print("Current working directory is: " + path)
        print("To begin logging to a file, enter 'L'")
        print("For persistence artifact retrieval, enter 'P'")
        print("For master file path inspection, enter 'F'")
        print("For exectuion artifact retrieval, enter 'E'")
        print("For browser artifact retrieval, enter 'B'")
        print("For hash functions, enter 'H'")
        print("To exit, enter '0'")
        # Take in the navigation prompt and go to that sub menu or exit
        navigation = input("")
        if "P" in navigation:
            persistence(log_file)
        elif "F" in navigation:
            if (log_file is not 0):
                log_file.write("\n ----MasterFileTableInspection---- \n")
            master_file_table_inspection(log_file)
        elif "E" in navigation:
            execution(log_file)
        elif "B" in navigation:
            browsers(log_file)
        elif "H" in navigation:
            hashes(log_file)
        elif "L" in navigation:
            # Open the log in the global log variables so other functions can write to it
            now = str(datetime.datetime.now())
            now = now.replace('.', '')
            now = now.replace(':', '')
            now = now.replace('-', '')
            log_path = ((path + "\output\OutputLog_" + str(now) + ".txt").replace(' ',''))
            log_file = open(log_path,"a+")
            print("Now logging all actions to: " + log_path)
        elif "0" in navigation:
            try:
                # Ensure the file is closed gracefully.
                log_file.close()
            except:
                pass
            return 0

# Sub Menu's ++++++++++++++++++++++++++++++++++++++

def persistence(log_file):
    # Persistence menu
    while True:
        if (log_file is not 0):
            log_file.flush()

        print("Persistence")
        print("1. Find process dlls")
        print("2. Find running processes")
        print("3. Find scheduled tasks")
        print("4. Find all local users")
        print("5. Startup folders")
        print("6. Registry Check")
        print("7. Host File Check")

        print("E. Exit")



        navigation = input("")
        if "1" in navigation:
            if(log_file is not 0):
                log_file.write("\n ----ListDLLs---- \n")
            listdll(log_file)
        if "2" in navigation:
            if (log_file is not 0):
                log_file.write("\n ----RunningProcesses---- \n")
            standardization_input = input("Check processes against standard process? Y(recommended)/N")
            if("Y" in standardization_input or "y" in standardization_input):
                standardization_functions.running_process_standard(log_file)
            else:
                running_processes(log_file)
        if "3" in navigation:
            if (log_file is not 0):
                log_file.write("\n ----ScheduledTasks---- \n")
            scheduled_tasks(log_file)
        if "4" in navigation:
            if (log_file is not 0):
                log_file.write("\n ----LocalUsers---- \n")
            local_users(log_file)
        if "5" in navigation:
            if (log_file is not 0):
                log_file.write("\n ----StartupFolders---- \n")
            startup_folder(log_file)
        if "6" in navigation:
            registry_functions.full_service(log_file)
        if "7" in navigation:
            if (log_file is not 0):
                log_file.write("\n ----HostFile---- \n")
            host_check(log_file)
        if "E" in navigation:
            return 0

def hashes(log_file):
    while True:
        if (log_file is not 0):
            log_file.flush()

        print("Hash Functions")
        print("1. MD5")
        print("2. SHA256")
        print("3. IMPHASH")
        #print("4. Get Digital Signature of PE file")

        print("E. Exit")

        navigation = input("")
        if "1" in navigation:
            file_path = input("Provide the file path for the file: ")
            print("MD5 Hash: " + hash_functions.get_md5(file_path))
            if (log_file is not 0):
                log_file.write("\n" + str(file_path) + "\nIMPHASH:" + str(hash_functions.get_md5(file_path)))
        if "2" in navigation:
            file_path = input("Provide the file path for the file: ")
            print("SHA256 Hash: " + hash_functions.get_sha256(file_path))
            if (log_file is not 0):
                log_file.write("\n" + str(file_path) + "\nIMPHASH:" + str(hash_functions.get_md5(file_path)))
        if "3" in navigation:
            file_path = input("Provide the file path for PE file: ")
            try:
                print("IMPHASH: " + hash_functions.get_IMPHASH(file_path))
                if(log_file is not 0):
                    log_file.write("\n" + str(file_path) + "\nIMPHASH:" + str(hash_functions.get_md5(file_path)))
            except:
                print("[WARNING] the 'pefile' library is not installed. Cannot generate IMPHASH")
        # TODO Currently getting digital signatures is on hold
        #if "4" in navigation:
        #    file_path = input("Provide the file path for PE file: ")
        #    signature = hash_functions.get_digsignature(file_path)
        #    print("Signature Table: " + str(signature))
        #    print("[WARNING] the 'pefile' library is not installed. Cannot get digital signatures")
        if "E" in navigation:
            return 0



def execution(log_file):
    # Execution menu
    while True:
        if (log_file is not 0):
            log_file.flush()

        print("Execution")
        print("1. Check windows prefetch directory")
        print("2. Show logged on users")
        print("3. Windows Event Log")
        print("4. DNS Queries")
        print("5. Windows Error Reporting")
        print("6. All user accessed files")
        print("7. View attached USB devices")

        print("E. Exit")


        navigation = input("")
        if "1" in navigation:
            if (log_file is not 0):
                log_file.write("\n ----PrefetchFiles---- \n")
            prefetch(log_file)
        if "2" in navigation:
            if (log_file is not 0):
                log_file.write("\n ----LoggedOnUsers---- \n")
            logged_on(log_file)
        if "3" in navigation:
            if (log_file is not 0):
                log_file.write("\n ----WindowsEventLog---- \n")
            eventlog(log_file)
        if "4" in navigation:
            if (log_file is not 0):
                log_file.write("\n ----DNSQuery---- \n")
            dnsquery_check(log_file)
        if "5" in navigation:
            if (log_file is not 0):
                log_file.write("\n ----WindowsErrorReporting---- \n")
            error_reporting(log_file)
        if "6" in navigation:
            if (log_file is not 0):
                log_file.write("\n ----AllUserAccessedFiles/Folders---- \n")
            all_viewed_files(log_file)
            print("[NOTE}: Since this is based on powershell it is very experimental and tempermental")
        if "7" in navigation:
            if (log_file is not 0):
                log_file.write("\n ----ViewUSBDeviceHistory---- \n")
            registry_functions.usb_info_retrieval(log_file)
        if "E" in navigation:
            return 0

def browsers(log_file):
    while True:
        if(log_file is not 0):
            log_file.flush()

        print("Browsers")
        print("A. Get me everything from all browsers!!!")
        print("1. Check available browsers")
        print("2. Check Chrome extensions")
        print("3. Check Chrome History")
        print("4. Check Mozilla History")
        print("5. Check Mozilla Extensions")
        print("6. Check IE History")

        print("E. Exit")


        navigation = input("")
        if "A" in navigation or "a" in navigation:
            browser_functions.do_all_browser(log_file)
        if "1" in navigation:
            browser_functions.check_available_browsers(log_file)
        if "2" in navigation:
            browser_functions.chrome_extensions(log_file)
        if "3" in navigation:
            browser_functions.check_chrome_history_db(log_file)
        if "4" in navigation:
            browser_functions.check_mozilla_history_db(log_file)
        if "5" in navigation:
            browser_functions.mozilla_extensions(log_file)
        if "6" in navigation:
            browser_functions.check_IE_history_db(log_file)
        if "E" in navigation:
            return 0

# Query Functions +++++++++++++++++++++++++++++++++++++

# This function is focused on getting data from the event log
# TODO in further testing see if using the event cleaner is necessary for the other events
def eventlog(log_file):
    while True:
        print("\nWINLOGON COMMMAND CENTER")
        print("1. Get only important Event IDs")
        print("2. Get Successful Logon Events")
        print("3. Get Failed Login Events")
        print("4. Get Member added to security enabled group")
        print("5. Get Service Creation")
        print("9. Get all details on a specific event")
        print("0. Get event logs without parsing")
        print("E. Exit")
        parse = input("")
        # Exit EventLog
        if ("E" in parse):
            return 0
        security_logs = subprocess.check_output("powershell Get-Eventlog Security")
        security_logs = security_logs.decode()
        security_logs = security_logs.split("\r\n")
        # Count will ensure the first two lines are printed to organize the table
        count = 0
        if("9" not in parse):
            for event in security_logs:
                # Important Event ID
                if ("1" in parse) and count > 1:
                    if ("4624" in event) or ("4625" in event) or ("4776" in event) or ("4720" in event) or ("4732" in event) or (
                        "4728" in event) or ("7030" in event) or ("7040" in event) or ("7045" in event):
                        print(event)
                        if(log_file != 0):
                            log_file.write(event + "\n")



                # Succesful Logon Events
                elif ("2" in parse) and count > 1:
                    if ("4624" in event):
                        # Since the output is too big to handle in console, we will write it to a file
                        try:
                            if (log_file != 0):
                                log_file.write(event + "\n")
                            else:
                                print(event_cleaner(event))
                        except:
                            pass




                # Failed Logon Events
                elif ("3" in parse) and count > 1:
                    if ("4625" in event):
                        try:
                            if (log_file != 0):
                                log_file.write(event + "\n")
                            else:
                                print(event_cleaner(event))
                        except:
                            pass



                # Member added to Security Enabled Group Events
                elif ("4" in parse) and count > 1:
                    if ("4732" in event) or ("4728" in event):
                        print(event)
                        if (log_file != 0):
                            log_file.write(event + "\n")



                # Get Service Creation and Service Creation Failure Events
                elif ("5" in parse) and count > 1:
                    if ("7030" in event) or ("7045" in event):
                        print(event)
                        if (log_file != 0):
                            log_file.write(event + "\n")


                # Default print
                else:
                    print(event)
                    if (log_file != 0):
                        log_file.write(event + "\n")
                count += 1
        # Get more details on event
        elif ("9" in parse):
            event_index = input("Event Index:")
            event_details = subprocess.check_output("powershell (Get-Eventlog Security -Index " + str(event_index) + ") | Select-Object -Property *")
            event_details = event_details.decode()
            print(event_details)
            if (log_file != 0):
                log_file.write(event_details + "\n")

# Checks the host file
def host_check(log_file):
    file = open("C:\Windows\System32\drivers\etc\hosts", "r")
    hosts = file.read()
    print(hosts)
    if (log_file is not 0):
        log_file.write(hosts)
        log_file.flush()

# TODO for some god forsaken reason this is only giving me the header of the request
def dnsquery_check(log_file):
    print("If not working use 'ipconfig /displaydns'")
    output = subprocess.check_output("ipconfig /displaydns", shell=True)
    output = output.decode()
    output = output.split("\n")
    for line in output:
        print(line)
        if(log_file is not 0):
            log_file.write(line + "\n")

def listdll(log_file):
    # This will give us the dlls for a given running process, useful for finding dll injection
    # TODO try and get this to run using only powershell  'powershell (Get-Process | Where { $_.ProcessName -eq 'explorer' } | Select Modules).Modules'
    print("[NOTE] Powershell for this command '(Get-Process | Where { $_.ProcessName -eq 'process_name' } | Select Modules).Modules'")
    print("Replace process_name with the intended process name to check")
    process = input("Input process name or PID: ")
    # If anomalous is Y, we will not show common dlls from System32, as if they can overwrite system32 we have bigger problems
    anomalous = input("Do you want to only show non-system32 dlls? (Y/N)")
    # Get the listdlls result
    try:
        output = subprocess.check_output(path + "\listdlls " + process)
    except:
        print("Unable to execute listdlls")
    try:
        output = output.decode()
    except:
        print("Please perform first time setup of listdlls.exe, otherwise we cannot properly get dlls")
        return 1
    output = output.split("\r\n")
    # Print them according to the settings given
    for line in output:
        if "Y" in anomalous and ("C:\Windows\System32" not in line and "C:\Windows\SYSTEM32" not in line and "C:\Windows\system32" not in line and
                                 "C:\WINDOWS\System32" not in line and "C:\WINDOWS\SYSTEM32" not in line and "C:\WINDOwS\system32" not in line):
            print(line)
            if (log_file is not 0):
                log_file.write(line + "\n")
        elif "Y" not in anomalous:
            print(line)
            if (log_file is not 0):
                log_file.write(line + "\n")

def master_file_table_inspection(log_file):
    print("[NOTE] The executable for this is usable under the MIT License")
    # Get the file we want to do MFT inspection on
    file_path = input("Provide the full path to the file/directory you want to inspect the $MFT of: \n")
    # Attempt to get the output and decode it
    try:
        output = subprocess.check_output(path + "\MFTRCRD.exe " + file_path + " -d indxdump=off 1024 -s")
    except:
        print("Attempting to run MFTRCD.exe seems to not be running, is it there?")
    try:
        output = output.decode()
    except:
        return 1
    output = output.split("\r\n")
    # Print line by line
    for line in output:
        print(line)
        if(log_file is not 0):
            log_file.write(line + "\n")

def running_processes(log_file):
    # Get processes result
    # TODO add an option to filter out common processes like svchost and other common processes
    output = subprocess.check_output("wmic process get ParentProcessID, Name, ProcessID, CreationDate, ExecutablePath")
    output = output.decode()
    output = output.split("\r\n")
    # Print them according to the settings given
    for line in output:
        md5 = ''
        # Now let's add the MD5 Hashes to the output
        process_array = line.split("  ")
        try:
            if process_array[1] is not '':
                md5 = hash_functions.get_md5(process_array[1])
        except:
            pass
        # Finally, print or result
        print(str(line))
        if (log_file is not 0):
            log_file.write(line + "\n")
        print("MD5: " + md5)
        if (log_file is not 0):
            log_file.write("MD5: " + md5 + "\n")
        print('')

def scheduled_tasks(log_file):
    # if anomalous is Y, then we will only show tasks with a path not in Microsoft\Windows
    anomalous = input("Do you want to only show non Microsoft\Windows tasks? (Y/N)")
    # Tasks are located in C:\Windows\System32\Tasks\Microsoft\Windows usually
    # Get the scheduled tasks results
    try:
        output = subprocess.check_output("powershell Get-ScheduledTask")
        output = output.decode()
        output = output.split("\r\n")
    except:
        print("Unable to execute powershell script, how old is your powershell?")
        print("Attempting to open task scheduler")
        try:
            subprocess.run("C:\\Windows\\Systemm32\\taskchd")
        except:
            return 1
        return 1
    # Print them according to the settings given
    for line in output:
        if "Y" in anomalous and ("\Microsoft\Windows" not in line ):
            print(line)
            if (log_file is not 0):
                log_file.write(line + "\n")
        elif "Y" not in anomalous:
            print(line)
            if (log_file is not 0):
                log_file.write(line + "\n")

def prefetch(log_file):
    # Get prefetch directory result
    output = os.walk("C:\Windows\Prefetch")
    for dirname, dirnames, filenames in output:
        for i in filenames:
            print(i)
            if (log_file is not 0):
                log_file.write(i + "\n")
    # Print them according to the settings given
    for line in output:
        print(line)
        if (log_file is not 0):
            log_file.write(line + "\n")

def logged_on(log_file):
    #command = "cmd.exe /C query user"
    host = input("Input host to check users for. (127.0.0.1 for local machine): ")
    output = subprocess.check_output("wmic /NODE:" + host + " COMPUTERSYSTEM GET USERNAME")
    output = output.decode()
    output = output.split("\r\n")
    for line in output:
        print(line)
        if (log_file is not 0):
            log_file.write(line + "\n")

def local_users(log_file):
    # Get option for more information
    verbose = input("Do you want verbose output? (Y/N)")
    # Get the output of the useraccounts
    if "Y" in verbose:
        output = subprocess.check_output("wmic useraccount list full")
    else:
        output = subprocess.check_output("wmic useraccount get name, description, sid")
    # Print the output
    output = output.decode()
    output = output.split("\r\n")
    for line in output:
        print(line)
        if (log_file is not 0):
            log_file.write(line + "\n")

def startup_folder(log_file):
    users = subprocess.check_output("wmic useraccount get name")
    users = users.decode()
    users = users.split("\r\r")
    user_startup = []
    for line in users:
        line = line.strip("\n")
        line = line.strip("\t")
        line = line.strip(" ")
        if line != "":
            #print(line)
            user_startup.append(line)
    # Now to check the startup folder
    #print(user_startup)
    for user in user_startup:
        backslash = "\\"
        output = ""
        #print(backslash)
        #print('C:' + backslash + 'Users' + backslash + str(user) + backslash + 'AppData' + backslash + 'Roaming' + backslash + 'Microsoft' + backslash + 'Windows' + backslash + 'Start Menu' + backslash + 'Programs' + backslash + 'Startup')
        try:
            output = os.listdir('C:' + backslash + 'Users' + backslash + str(user) + backslash + 'AppData' + backslash + 'Roaming' + backslash + 'Microsoft' + backslash + 'Windows' + backslash+ 'Start Menu' + backslash + 'Programs' + backslash + 'Startup')
            print("Startup Folder for " + user + ":")
            print(output)
            if (log_file is not 0):
                log_file.write("Startup Folder for " + user + ": \n" + str(output))
        except:
            pass

# In our windows event section we use this function to return the important bits of each type of event
def event_cleaner(event):
    fields = []
    event = event.strip("\t")
    event = event.split(" ")
    for i in event:
        if i is not '':
            fields.append(i)
    # This handles succesful and failed login events
    if(fields[6] == "4624" or fields[6] == "4625"):
        event_details = subprocess.check_output("powershell (Get-Eventlog Security -Index " + str(fields[0]) + ") | Select-Object -Property *")
        event_details = event_details.decode()
        event_details = event_details.split("This")
        return event_details[0]

def error_reporting(log_file):
    # Get error reporting directory result
    critical_only = input("Do you want to see only critical error archives? (Y/N)")
    # Keep these for assigning a number to each error
    count = 0
    errors_displayed = []

    try:
        output = os.walk("C:\ProgramData\Microsoft\Windows\WER\ReportArchive")
        for dirname, dirnames, filenames in output:
            for i in dirnames:
                # Condition for if we only want critical
                if(("NonCritical" not in i) and ("Critical" in i) and ("Y" in critical_only)):
                    errors_displayed.append(i)
                    print("[" + str(count) + "] - " + i)
                    if (log_file is not 0):
                        log_file.write("[" + str(count) + "] - " + i + "\n")
                # Condition for if we want everything
                else:
                    errors_displayed.append(i)
                    print("[" + str(count) + "] - " + i)
                    if (log_file is not 0):
                        log_file.write("[" + str(count) + "] - " + i + "\n")
                count += 1
    except:
        print("The WER directory seems to be having some issues!")

    # Now let's ask if there is a specific WER report they want to see
    report_id = input("Provide the numerical ID for the report you want to see parsed (nothing for no report): ")
    if(report_id.isnumeric()):
        # Use the report id to point to the proper index in our errors_displayed list and print the contents of the report
        #try:
        print("[NOTE] Report located at C:\ProgramData\Microsoft\Windows\WER\ReportArchive\\" + str(errors_displayed[int(report_id)]) + "\\Report.wer")
        report = open("C:\ProgramData\Microsoft\Windows\WER\ReportArchive\\" + str(errors_displayed[int(report_id)]) + "\\Report.wer", "r")

        log_file.write("\nReport for ID: " + report_id + "\n")
        for line in report:
            # Only print lines that are of these categories
            print(line.replace("\n",""))
            if (log_file is not 0):
                # log_file.write("[NOTE] Report located at C:\ProgramData\Microsoft\Windows\WER\ReportArchive\\" + str(errors_displayed[int(report_id)]) + "\\Report.wer" + "\n")
                log_file.write(line.replace("\n","") + "\n")
        #except:
        print("Error encountered reading the report, do you have elevated priveleges?")
    return 0

def all_viewed_files(log_file):
    try:
        output = subprocess.check_output("powershell $Praise = Foreach($Item in ((New-Object -ComObject Shell.Application).NameSpace(34).Items())){If($Item.IsFolder){$Item.GetFolder.Items()}}; $Praise.GetFolder.Items().GetFolder()")
        output = output.decode()
        output = output.split("\r\n")
        for line in output:
            try:
                if ('Title' in line):
                    try:
                        print(line.split(":")[1])
                        if(log_file is not 0):
                            log_file.write("\n" + line.split(":")[1])
                    except:
                        print(line)
                        if(log_file is not 0):
                            log_file.write("\n" + line)
            except:
                print("Error parsing the output of all files command")
    except:
        print("Error accessing previously accessef filesl list. Possibly powershell")



main()