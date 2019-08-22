# Author: John Lawrence
# Description: Here we have our functions for analyzing browser activity
# TODO: History, extensions, cookies, downloads
# TODO: Start adding firefox support

import os
import socket
import ssl
import json
import sqlite3
import subprocess

# This will run all of our functions we are able to!
def do_all_browser(log_file):
    # Start by seeing what browsers are avaiable
    chrome, firefox, IE = check_available_browsers(log_file)
    print("!!!!!Executing all available browser artifact functions")
    if(log_file is not 0):
        log_file.write("\n!!!!!Executing all browser artifact functions")
    # If chrome is available get the extensions and history for chrome
    if(chrome):
        chrome_extensions(log_file)
        check_chrome_history_db(log_file)
    # If mozilla is available get the extensions and history for mozilla
    if(firefox):
        mozilla_extensions(log_file)
        check_mozilla_history_db(log_file)
    if(IE):
        check_IE_history_db(log_file)



# This function is necessary to get an extension name from its ID
def get_chrome_extension_name(id):
    # We can get the name of the extension by going to the _locales\en\messages.json file and finding the app name
    # NOTE: It seems like this JSON is not required to be normalized, so errors may occur due to various cases and spaces
    try:
        # Traverse the directory and go deeper
        extension_versions = os.listdir("C:\\Users\JohnB\AppData\Local\Google\Chrome\\User Data\Default\Extensions\\" + str(id))
        extension_locales = os.listdir("C:\\Users\JohnB\AppData\Local\Google\Chrome\\User Data\Default\Extensions\\" + str(id) + "\\" + str(extension_versions[0]) + "\\_locales\\")
        for locale in extension_locales:
            if("en" in locale):
                # We should be good with the first english locale we find.
                json_file = open("C:\\Users\JohnB\AppData\Local\Google\Chrome\\User Data\Default\Extensions\\" + str(id) + "\\" + str(extension_versions[0]) + "\\_locales\\" + locale + "\\messages.json")
                data = json.load(json_file)
                # Now that we have the data of this locale, we will iterate till we see one with 'name' or 'Name' in it
                for entry in data:
                    if(('name' in entry) or ('Name' in entry)):
                        # If we find a name entry, return its message value as that is most likely the name of ext
                        return(data[entry]['message'])
    except:
        print("Ran into an issue traversing the extension directories")
    # If we get here then no name was found :(
    return 0

# This function will both serve to inform the analyst, and return values telling other functions what
# browsers are available.
def check_available_browsers(log_file):
    chrome = False
    firefox = False
    IE = False

    if(log_file is not 0):
        log_file.write("\n ----CheckAvailableBrowsers---- \n")

    # Google Chrome Check
    try:
        output_Chrome = os.listdir("C:\\Program Files (x86)\Google")
        if("Chrome" in output_Chrome):
            chrome = True
            print("Google Chrome found")
            if(log_file is not 0):
                log_file.write("\nGoogle Chrome found")
    except:
        print("No Chrome found.")
        if(log_file is not 0):
            log_file.write("No Chrome found.")

    # Mozilla Firefox Check
    try:
        output_Mozilla = os.listdir("C:\\Program Files (x86)")
        if("Mozilla Firefox" in output_Mozilla):
            firefox = True
            print("Mozilla Firefox found")
            if (log_file is not 0):
                log_file.write("\nMozilla Firefox found")
    except:
        print("No Firefox found.")
        if (log_file is not 0):
            log_file.write("\nNo Firefox found")

    # Internet Explorer Check
    try:
        output_IE = os.listdir("C:\\Program Files (x86)")
        if("Internet Explorer" in output_IE):
            IE = True
            print("Internet Explorer found")
            if (log_file is not 0):
                log_file.write("\nInternet Explorer found")
                log_file.flush()
    except:
        print("No Internet Explorer found.")
        if (log_file is not 0):
            log_file.write("\nNo Internet Explorer found")

    return chrome, firefox, IE

def chrome_extensions(log_file):
    # First, use our available browsers functions to ensure Google Chrome is installed
    # Make sure to pass it 0 here, and in other functions so we don't write to our log.

    chrome, firefox, IE = check_available_browsers(0)
    if(chrome == False):
        print("Can't find Chrome, therefore can't check for chrome extensions!")
        if(log_file is not 0):
            log_file.write("Can't find Chrome, therefore can't check for chrome extensions!")
        return 1

    # If we have gotten this far then Chrome is on the box and we can check for it
    count = 0

    if (log_file is not 0):
        log_file.write("\n\n ----CheckChromeExtensions---- \n")
    try:
        # Get the list of extensions from the chrome extensions directory
        output_extensions = os.listdir("C:\\Users\JohnB\AppData\Local\Google\Chrome\\User Data\Default\Extensions")
        for extension_id in output_extensions:
            # Find what this extension GUID is in actual english
            name = get_chrome_extension_name(extension_id)
            if(name is not 0):
                print("[" + str(count) + "] " + extension_id + ": " + name)
                if(log_file is not 0):
                    log_file.write("\n" + "[" + str(count) + "] " + extension_id + ": " + name)
            else:
                print("[" + str(count) + "] " + extension_id + ": NO NAME FOUND IN LOCALES")
                if (log_file is not 0):
                    log_file.write("\n" + "[" + str(count) + "] " + extension_id + ": NO NAME FOUND IN LOCALES")
            count += 1
    except:
        print("Error gathering data on extensions")

# This accessses the chrome History DB on the local machine to check the history
def check_chrome_history_db(log_file):
    if (log_file is not 0):
        log_file.write("\n\n ----CheckChromeHistory---- \n")
    try:
        # The browser history should be in the History file in our Google Chrome default directory
        sqlite_file = "C:\\Users\\JohnB\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
        conn = sqlite3.connect(sqlite_file)
        c = conn.cursor()
        # Below is the original command for finding the top tables available
        # c.execute("SELECT name FROM sqlite_master WHERE type='table';")
        c.execute("SELECT url from urls;")
        url_list = c.fetchall()
        for url in url_list:
            print(url[0])
            if (log_file is not 0):
                log_file.write("\n" + str(url[0]))
    except:
        print("Encountered issues accessing the history sqlite3 database")
        if (log_file is not 0):
            log_file.write("\n Encountered issues accessing the history sqlite3 database")

# Checks the browsing history of every mozilla profile on the box
def check_mozilla_history_db(log_file):
    # On this machine, history is stored at C:\Users\JohnB\AppData\Roaming\Mozilla\Firefox\Profiles\3lgzo88n.default-release
    # in the places.sqlite file
    if (log_file is not 0):
        log_file.write("\n\n ----CheckMozillaHistory---- \n")

    try:
        # First we need to get the directory (it seems to be the .default-release unless they have a mozilla profile)
        mozilla_profiles = os.listdir("C:\\Users\\JohnB\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\")
        # Now open the 'places.sqlite' of the profiles we have found
        for profile in mozilla_profiles:
            try:
                sqlite_file = "C:\\Users\\JohnB\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" + str(profile) + "\\places.sqlite"
                conn = sqlite3.connect(sqlite_file)
                c = conn.cursor()
                # Below is the original command for finding the top tables available
                # c.execute("SELECT name FROM sqlite_master WHERE type='table';")

                # Now we get all visited urls
                c.execute("SELECT url from moz_places;")
                url_list = c.fetchall()
                for url in url_list:
                    print(url[0])
                    if (log_file is not 0):
                        log_file.write("\n" + url[0])
            except:
                print("Profile: " + profile + " unable to get history")
                if (log_file is not 0):
                    log_file.write("\nProfile: " + profile + " unable to get history\n")
    except:
        print("Encountered issue accessing mozilla history file")
        if (log_file is not 0):
            log_file.write("\nEncountered issue accessing mozilla history file")

def mozilla_extensions(log_file):
    if (log_file is not 0):
        log_file.write("\n\n ----CheckMozillaExtensions---- \n")

    try:
        # First we need to get the directory (it seems to be the .default-release unless they have a mozilla profile)
        mozilla_profiles = os.listdir("C:\\Users\\JohnB\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\")
        # Now open the 'extensions.json' of the profiles we have found
        # Use count to help index the extensions
        for profile in mozilla_profiles:
            try:
                json_file = "C:\\Users\\JohnB\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" + str(profile) + "\\extensions.json"
                json_file = open(json_file, "r", encoding="utf8")
                data = json.load(json_file)
                # Now that we have the data of this locale, we will iterate till we see one with 'name' or 'Name' in it
                count = 0
                print("Profile: " + str(profile))
                if (log_file is not 0):
                    log_file.write("\n\nProfile: " + str(profile))
                for entry in data['addons']:
                    print("[" + str(count) + "] " + str(entry['defaultLocale']['name']))
                    if (log_file is not 0):
                        log_file.write("\n[" + str(count) + "] " + str(entry['defaultLocale']['name']))
                    count += 1
            except:
                print("Unable to access extensions.json for profile: " + str(profile))
                if(log_file is not 0):
                    log_file.write("\nUnable to access extensions.json for profile: " + str(profile))
    except:
        print("Was unable to access the profile extensions")

def check_IE_history_db(log_file):
    if (log_file is not 0):
        log_file.write("\n\n ----CheckIEHistory---- \n")

    #try:
    # First we need to get the directory (it seems to be the .default-release unless they have a mozilla profile)
    #infile = os.listdir("C:\\Users\JohnB\AppData\Local\Microsoft\Windows\History\\History.IE5\\")
    #file = open("C:\\Users\JohnB\AppData\Local\Microsoft\Windows\History\\History.IE5\\container.dat")
    #print(infile)
    #print(file.read())

    # I use this unwieldy powershell command to get the history!
    try:
        output = subprocess.check_output("powershell Foreach($Item in ((New-Object -ComObject Shell.Application).NameSpace(34).Items())){If($Item.IsFolder){$Item.GetFolder.Items()}}")
        output = output.decode()
        output = output.split("\r\n")
        for i in output:
            # TODO we can actually see all of the files accessed by going into the 'This PC' folders. I should make use of that in the future
            if('Name' in i and 'This PC' not in i):
                i = i.split(":")
                try:
                    print(i[1])
                    if(log_file is not 0):
                        log_file.write("\n" + str(i[1]))
                except:
                    print(i[0])
                    if (log_file is not 0):
                        log_file.write("\n" + str(i[0]))
    except:
        print("Having an error grabbing IE history. Either the folders are off or the powershell isn't working")
        print("You can access: C:\\Users\JohnB\AppData\Local\Microsoft\Windows\History if this isn't working")
        if (log_file is not 0):
            log_file.write("\nHaving an error grabbing IE history. Either the folders are off or the powershell isn't working\nYou can access: C:\\Users\JohnB\AppData\Local\Microsoft\Windows\History if this isn't working")



# ------------------ Support Functions -------------------------
def https_google_connection():
    # First we use sockets to get information from the storefront using the ID
    target_host = "chrome.google.com"  # + str(extension)
    target_port = 443
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((target_host, target_port))
    client = ssl.wrap_socket(client, keyfile=None, certfile=None, server_side=False, cert_reqs=ssl.CERT_NONE,
                             ssl_version=ssl.PROTOCOL_SSLv23)
    # The headers for our HTTP request. I try to be as close to an actual request from a browser as possible.
    request = "GET /webstore/detail/" + str(extension) + "/ HTTP/1.1\r\nHost: chrome.google.com\r\n\r\n"
    client.send(request.encode())
    # After sending it receive our response
    # while True:
    response = client.recv(4096)
    if not response:
        client.close()
        # break
    print(response)

def backup():
    output = subprocess.check_output(
        "powershell $Praise = Foreach($Item in ((New-Object -ComObject Shell.Application).NameSpace(34).Items())){If($Item.IsFolder){$Item.GetFolder.Items()}}; $Praise.GetFolder.Items().GetFolder()")
    output = output.decode()
    output = output.split("\r\n")
    for line in output:
        if ('Title' in line):
            try:
                print(line.split(":")[1])
            except:
                print(line)



