# Author: John Lawrence
# Description: This holds the longer registry check parsing and gathering functions
# URL used for reference: https://www.forensicswiki.org/wiki/Windows_Registry#Persistence_keys

import winreg
import subprocess


# NOTE the additional "0, (winreg.KEY_WOW64_64KEY+ winreg.KEY_READ)" is needed for use on LOCAL MACHINE keys.
# This has to do in some way with 32 bit and 64 bit python checks. If you do not add it on then you will
# not get the keys

# This function is meant to controll calling all the other Registry Checks in order
def full_service(log_file):
    if(log_file is not 0):
        log_file.write("\n ----REGISTRY FULL SERVICE CHECK---- \n")

    print("\nCommand Processor Check:")
    if(log_file is not 0):
        log_file.write("\nCommand Processor Check:\n")
    # Getting an error right here on DeShawns machine where it can't find the file
    reg_command_processor(log_file)
    print("")

    print("\nDebugger Check:")
    if (log_file is not 0):
        log_file.write("\nDebugger Check:\n")
    reg_debugging(log_file)
    print("")

    print("\nExplorer Check:")
    if (log_file is not 0):
        log_file.write("\nExplorer Check:\n")
    reg_explorer(log_file)
    print("")

    print("\nLSA Check:")
    if (log_file is not 0):
        log_file.write("\nLSA Check:\n")
    reg_lsa(log_file)
    print("")

    print("\nRun Check:")
    if (log_file is not 0):
        log_file.write("\nRun Check:\n")
    reg_run(log_file)
    print("")

    print("\nRun Service Check:")
    if (log_file is not 0):
        log_file.write("\nRun Service Check:\n")
    reg_run_service(log_file)
    print("")

    print("\nSession Manager Check:")
    if (log_file is not 0):
        log_file.write("\nSession Manager Check:\n")
    reg_session_manager(log_file)
    print("")

    print("\nControl Check:")
    if (log_file is not 0):
        log_file.write("\nControl Check:\n")
    reg_control(log_file)
    print("")

    print("\nWindows Shell Check:")
    if (log_file is not 0):
        log_file.write("\nWindows Shell Check:\nThis will display some by default, as it is showing all non-microsoft extensions\n")
    print("This will display some by default, as it is showing all non-microsoft extensions")
    reg_shell(log_file)
    print("")

    print("\nWinlogon Check:")
    if (log_file is not 0):
        log_file.write("\nWinlogon Check:\n")
    reg_winlogon(log_file)
    print("")

    print("\nSystem Shell Policy Check:")
    if (log_file is not 0):
        log_file.write("\nSystem Shell Policy Check:\n")
    reg_policy(log_file)
    print("")

    print("\nMiscellanious Checks:")
    if (log_file is not 0):
        log_file.write("\nMiscellanious Checks:\n")
    reg_miscellanious(log_file)
    print("")

    if (log_file is not 0):
        log_file.flush()






# Registry Checks +++++++++++++++++++++++++++++++++++++++++++

# A function for showing the basics of what we do with winreg
def example_registry_check(log_file):
    # TODO setup the registry analysis section
    # _winreg.CreateKey(_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Command Processor")
    registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Command Processor",0, (winreg.KEY_WOW64_64KEY+ winreg.KEY_READ))
    result = reg_value_enum(registry_key)
    print("Values in Command Processor: " + str(result))
    if (log_file is not 0):
        log_file.write("Values in Command Processor: " + str(result) + "\n")
    registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft",0, (winreg.KEY_WOW64_64KEY+ winreg.KEY_READ))
    result = reg_key_enum(registry_key)
    print("Sub keys in Microsoft: " + str(result))
    if (log_file is not 0):
        log_file.write("Sub keys in Microsoft: " + str(result) + "\n")

# Checks cmd keys for any autorun or unwanted keys
def reg_command_processor(log_file):
    # Get all of the current User Keys
    user_keys = reg_key_enum(winreg.OpenKey(winreg.HKEY_USERS, ""))
    # Key Path 1
    try:
        path = r"Software\Microsoft\Command Processor"
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path,0, (winreg.KEY_WOW64_64KEY+ winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            if ("CompletionChar" not in entry) and ("DefaultColor" not in entry) and ("EnableExtensions" not in entry) and ("PathCompletionChar" not in entry):
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
    except:
        print("Software\Microsoft\Command Processor\ key not found in the registry. Moving on...")
    # Key Path 2
    try:
        path = r"Software\Wow6432Node\Microsoft\Command Processor"
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        result = reg_value_enum(registry_key)
        for entry in result:
            if ("CompletionChar" not in entry) and ("DefaultColor" not in entry) and ("EnableExtensions" not in entry) and ("PathCompletionChar" not in entry):
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
    except:
        print("Software\Wow6432Node\Microsoft\Command Processor not found in the registry. Moving on...")


    # Key Path 3 and 4 require us to use the SID user keys. So we will iterate through each user
    for sid in user_keys:
        # 3
        # Setup the path for this specific user
        path = str(sid) + r"\Software\Microsoft\Command Processor"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                if ("CompletionChar" not in entry) and ("DefaultColor" not in entry) and ("EnableExtensions" not in entry) and ("PathCompletionChar" not in entry):
                    print("Anomalous registry value detected at " + path + ": " + str(entry))
                    if (log_file is not 0):
                        log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass
        # 4
        path = str(sid) + r"\Software\Wow6432Node\Microsoft\Command Processor"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                if ("CompletionChar" not in entry) and ("DefaultColor" not in entry) and ("EnableExtensions" not in entry) and ("PathCompletionChar" not in entry):
                    print("Anomalous registry value detected at " + path + ": " + str(entry))
                    if (log_file is not 0):
                        log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled or Wow6432 is not complete
            pass

# Checks the automatic debugging registry keys for what debugger is chosen
def reg_debugging(log_file):
    # Key Path 1
    path = r"Software\Microsoft\Windows NT\CurrentVersion\AeDebug"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY+ winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            if ("UserDebuggerHotKey" not in entry):
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
    except:
        print("Software\Microsoft\Windows NT\CurrentVersion\AeDebug key not found. Moving on...")

# Checks Internet Explorer (or just Explorer) browser helper objects
def reg_explorer(log_file):
    # Key path 1, On windows 10 it doesn't seem to normally be there. So I will say all entries are anomalous
    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for entry in result:
            print("Anomalous registry key detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
    except:
        # It does not seem to normally exist on Windows 10, so it is quite often needed to be passed
        pass
    # Key path 2, On windows 10 it doesn't seem to normally be there. So I will say all entries are anomalous
    path = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for entry in result:
            print("Anomalous registry key detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
    except:
        pass

# Checks the Local Security Authority (LSA) values
def reg_lsa(log_file):
    # The authentication packages should be msv1_0
    # Key path 1
    path = r"System\CurrentControlSet\Control\Lsa"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            # First, check to see what values are present
            if ("auditbasedirectories" not in entry) and ("auditbaseobjects" not in entry) and ("Authentication Packages" not in entry) and (
                "Bounds" not in entry) and ("crashonauditfail" not in entry) and ("disabledomaincreds" not in entry) and ("everyoneincludesanonymous" not in entry) and (
                "forceguest" not in entry) and ("fullprivilegeauditing" not in entry) and ("LimitBlankPasswordUse" not in entry) and (
                "LsaPid" not in entry) and ("NoLmHash" not in entry) and ("Notification Packages" not in entry) and ("ProductType" not in entry) and (
                "restrictanonymous" not in entry) and ("restrictanonymoussam" not in entry) and ("SecureBoot" not in entry) and ("Security Packages" not in entry):
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            # Next, check to see that AuthenticationPackages is msv1_0 and Security Packages is ""
            if ("Authentication Packages" in entry) and ('msv1_0' not in entry[1]):
                print("Anomalous Control\Lsa\Authentication Packages value: " + str(entry[1]))
                if (log_file is not 0):
                    log_file.write("Anomalous Control\Lsa\Authentication Packages value: " + str(entry[1]) + "\n")
            if ("Security Packages" in entry) and ('""' not in entry[1]):
                print("Anomalous Control\Lsa\Security Packages value: " + str(entry[1]))
                if (log_file is not 0):
                    log_file.write("Anomalous Control\Lsa\Security Packages value: " + str(entry[1]) + "\n")
    except:
        pass

    # Key path 2
    # We will also check if security packages has the proper entry
    path = r"System\CurrentControlSet\Control\Lsa\OSConfig"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            if ("Security Packages" not in entry):
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            data = entry[1].split(" ")
            for value in data:
                if ("kerberos" is not value) and ("msv1_0" is not value) and ("tspkg" is not value) and ("pku2u" is not value) and ("wdigest" is not value) and ("cloudAP" is not value) and ("schannel" is not value):
                    print("Anomalous \Control\Lsa\OSConfig Security Package: " + str(value))
                    if (log_file is not 0):
                        log_file.write("Anomalous \Control\Lsa\OSConfig Security Package: " + str(value) + "\n")
    except:
        pass

# This is a big one, we will be checking all Run and RunOnce keys
def reg_run(log_file):
    # Key Path 1
    path = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")

    except:
        pass

    # Key Path 2
    path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 3
    path = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 4
    path = r"Software\Microsoft\Windows\CurrentVersion\RunOnce\Setup"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 5
    path = r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 6
    path = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 7
    path = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 8
    path = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce\Setup"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 9
    path = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 10
    path = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Time to check the users for any run keys
    user_keys = reg_key_enum(winreg.OpenKey(winreg.HKEY_USERS, ""))
    #Iterate through each user
    for sid in user_keys:
        # Key Path 11
        # Setup the path for this specific user
        path = str(sid) + r"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 12
        path = str(sid) + r"\Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 13
        path = str(sid) + r"\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 14
        path = str(sid) + r"\Software\Microsoft\Windows\CurrentVersion\RunOnce\Setup"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 15
        path = str(sid) + r"\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 16
        path = str(sid) + r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 17
        path = str(sid) + r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 18
        path = str(sid) + r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 19
        path = str(sid) + r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce\Setup"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 20
        path = str(sid) + r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

def reg_run_service(log_file):
    # Key Path 1
    path = r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 2
    path = r"Software\Microsoft\Windows\CurrentVersion\RunServices"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 3
    path = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 4
    path = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

def reg_session_manager(log_file):
    # Key Path 1
    path = r"System\CurrentControlSet\Control\Session Manager"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            if ("AutoChkTimeout" not in entry)  and ("BootExecute" not in entry) and ("BootShell" not in entry) and (
                "CriticalSectionTimeout" not in entry) and ("ExcludeFromKnownDlls" not in entry) and ("GlobalFlag"
                not in entry) and ("HeapDeCommitFreeBlockThreshold" not in entry) and ("HeapDeCommitTotalFreeThreshold"
                not in entry) and ("HeapSegmentCommit" not in entry) and ("HeapSegmentReserve" not in entry) and (
                "InitConsoleFlags" not in entry) and ("NumberOfInitialSessions" not in entry) and (
                "ObjectDirectories" not in entry) and ("ProcessorControl" not in entry) and ("ProtectionMode" not in entry) and (
                "ResourceTimeoutCount" not in entry) and ("RunLevelExecute" not in entry) and ("RunLevelValidate"
                not in entry) and ("SETUPEXECUTE" not in entry):
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            data = entry.split(" ")[1]
            if ("SetupExecute" in entry) and (data != ""):
                print("Anomalous value located in CurrentControlSet\Control\Session Manager\SetupExecute: " + entry)
                if (log_file is not 0):
                    log_file.write("Anomalous value located in CurrentControlSet\Control\Session Manager\SetupExecute: " + entry + "\n")
            if ("BootExecute" in entry):
                print("BootExecute values are: " + entry)
                if (log_file is not 0):
                    log_file.write("BootExecute values are: " + entry + "\n")
    except:
        pass

def reg_control(log_file):
    # Key Path 1
    path = r"System\CurrentControlSet\Control"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            if("BootDriverFlags" not in entry) and ("CurrentUser" not in entry) and ("EarlyStartServices" not in entry) and (
                "FirmwareBootDevice" not in entry) and ("LastBootShutdown" not in entry) and ("LastBootSucceeded" not in entry) and (
                "PreshutdownOrder" not in entry) and ("SystemBootDevice" not in entry) and ("SystemStartOptions" not in entry) and (
                "WaitToKillServiceTimeout" not in entry):
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        #for subkey in result:
        #    print("Anomalous subkey detected at " + path + ": " + str(subkey))
    except:
        pass

def reg_shell(log_file):
    # Key Path 1
    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            if("OneDrive" not in subkey) and ("Offline Files" not in subkey) and ("EnhancedStorageShell" not in subkey):
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 2
    path = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            if("OneDrive" not in subkey) and ("Offline Files" not in subkey) and ("EnhancedStorageShell" not in subkey):
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 3
    path = r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                    (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            if ("Windows" not in entry[1]) and ("Microsoft" not in entry[1]) and ("WebCheck" not in entry[1]):
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 4
    path = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                    (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            if ("Windows" not in entry[1]) and ("Microsoft" not in entry[1]) and ("WebCheck" not in entry[1]):
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 5
    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                    (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 6
    path = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 6.5
    path = r"Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 6.75
    path = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass


    # Time to check the users for any run keys
    user_keys = reg_key_enum(winreg.OpenKey(winreg.HKEY_USERS, ""))
    # Iterate through each user
    for sid in user_keys:
        # Key Path 7
        path = str(sid) + r"\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                if ("OneDrive" not in subkey) and ("Offline Files" not in subkey) and (
                        "EnhancedStorageShell" not in subkey):
                    print("Anomalous subkey detected at " + path + ": " + str(subkey))
                    if (log_file is not 0):
                        log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 8
        path = str(sid) + r"\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                if ("OneDrive" not in subkey) and ("Offline Files" not in subkey) and (
                        "EnhancedStorageShell" not in subkey):
                    print("Anomalous subkey detected at " + path + ": " + str(subkey))
                    if (log_file is not 0):
                        log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 9
        path = str(sid) + r"\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                if("Windows" not in entry):
                    print("Anomalous registry value detected at " + path + ": " + str(entry))
                    if (log_file is not 0):
                        log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 10
        path = str(sid) + r"\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                if("Windows" not in entry):
                    print("Anomalous registry value detected at " + path + ": " + str(entry))
                    if (log_file is not 0):
                        log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 11
        path = str(sid) + r"Software\Microsoft\Windows NT\CurrentVersion\Windows"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                if("Load" in entry) or ("Run" in entry):
                    print("Anomalous registry value detected at " + path + ": " + str(entry))
                    if (log_file is not 0):
                        log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                if("Load" in subkey) or ("Run" in subkey):
                    print("Anomalous subkey detected at " + path + ": " + str(subkey))
                    if (log_file is not 0):
                        log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 12
        path = str(sid) + r"Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                if("Load" in entry) or ("Run" in entry):
                    print("Anomalous registry value detected at " + path + ": " + str(entry))
                    if (log_file is not 0):
                        log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                if("Load" in subkey) or ("Run" in subkey):
                    print("Anomalous subkey detected at " + path + ": " + str(subkey))
                    if (log_file is not 0):
                        log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

# This is concerned with the credential auth and providers for winlogon
def reg_winlogon(log_file):
    # Key Path 1
    print("[NOTICE] It is always important to check the Software\Microsoft\Windows NT\CurrentVersion\Winlogon registry yourself!")
    print("Shell should be explorer.exe, Userinit should be \\system32\\userinit.exe")
    path = r"Software\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 2
    path = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 3
    path = r"Software\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        #for subkey in result:
        #    print("Anomalous subkey detected at " + path + ": " + str(subkey))
    except:
        pass

    # Key Path 4
    path = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        #for subkey in result:
        #    print("Anomalous subkey detected at " + path + ": " + str(subkey))
    except:
        pass

    # Key Path 5
    path = r"Software\Microsoft\Windows\CurrentVersion\Authentication\PLAP Providers"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 6
    path = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Authentication\PLAP Providers"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 7
    path = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            if("GinaDLL" in entry) or ("Shell" in entry) or ("System" in entry) or ("Taskman" in entry) or ("Userinit" in entry) or ("VMApplet" in entry):
                print("Important/Anomalaous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Important/Anomalaous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 8
    path = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Anomalous subkey detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass


    # Time to check the users for any run keys
    user_keys = reg_key_enum(winreg.OpenKey(winreg.HKEY_USERS, ""))
    # Iterate through each user
    for sid in user_keys:
        # Key Path 9
        path = str(sid) + r"\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                if("GinaDLL" in entry) or ("Shell" in entry) or ("System" in entry) or ("Taskman" in entry) or ("Userinit" in entry) or ("VMApplet" in entry):
                    print("Anomalous registry value detected at " + path + ": " + str(entry))
                    if (log_file is not 0):
                        log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 10
        path = str(sid) + r"\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

# This checks our system policy for a replacement shell
def reg_policy(log_file):
    # Key Path 1
    path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            if("Shell" in entry):
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        #for subkey in result:
        #    print("Anomalous subkey detected at " + path + ": " + str(subkey))
    except:
        pass

    # Key Path 2
    path = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            if("Shell" in entry):
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            print("Important/Anomalous subkeys detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("Important/Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

def reg_miscellanious(log_file):
    # Key Path 1
    path = r"Software\Microsoft\Active Setup\Installed Components"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            if("StubPath" in entry):
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            if("StubPath" in subkey):
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 2
    path = r"Software\Wow6432Node\Microsoft\Active Setup\Installed Components"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            if("StubPath" in entry):
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            if("StubPath" in subkey):
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 3
    path = r"Software\Microsoft\Windows NT\CurrentVersion\Windows"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            if("AppInit_DLLs" in entry):
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            if("AppInit_DLLs" in subkey):
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 4
    path = r"Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            if("AppInit_DLLs" in entry):
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            if("AppInit_DLLs" in subkey):
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 5 Security Providers
    path = r"System\CurrentControlSet\Control\SecurityProviders"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            print("Anomalous registry value detected at " + path + ": " + str(entry))
            if (log_file is not 0):
                log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        print("Security Providers:")
        for subkey in result:
            print("\tSecurity Provider detected at " + path + ": " + str(subkey))
            if (log_file is not 0):
                log_file.write("\tSecurity Provider detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 6
    path = r"System\CurrentControlSet\Control\SafeBoot"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            if("AlternateShell" in entry):
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            if("AlternateShell" in subkey):
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Key Path 7
    path = r"System\CurrentControlSet\Control\BootVerificationProgram"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_value_enum(registry_key)
        for entry in result:
            if("ImagePath" in entry):
                print("Anomalous registry value detected at " + path + ": " + str(entry))
                if (log_file is not 0):
                    log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
        result = reg_key_enum(registry_key)
        for subkey in result:
            if("ImagePath" in subkey):
                print("Anomalous subkey detected at " + path + ": " + str(subkey))
                if (log_file is not 0):
                    log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
    except:
        pass

    # Time to check the users for any run keys
    user_keys = reg_key_enum(winreg.OpenKey(winreg.HKEY_USERS, ""))
    # Iterate through each user
    for sid in user_keys:
        # Key Path 9
        path = str(sid) + r"\Software\Microsoft\Active Setup\Installed Components"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                if ("StubPath" in entry):
                    print("Anomalous registry value detected at " + path + ": " + str(entry))
                    if (log_file is not 0):
                        log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                if ("StubPath" in subkey):
                    print("Anomalous subkey detected at " + path + ": " + str(subkey))
                    if (log_file is not 0):
                        log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 10
        path = str(sid) + r"\Software\Wow6432Node\Microsoft\Active Setup\Installed Components"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                if ("StubPath" in entry):
                    print("Anomalous registry value detected at " + path + ": " + str(entry))
                    if (log_file is not 0):
                        log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                if ("StubPath" in subkey):
                    print("Anomalous subkey detected at " + path + ": " + str(subkey))
                    if (log_file is not 0):
                        log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 11
        path = str(sid) + r"\Software\Microsoft\Windows NT\CurrentVersion\Windows"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                if ("AppInit_DLLs" in entry):
                    print("Anomalous registry value detected at " + path + ": " + str(entry))
                    if (log_file is not 0):
                        log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                if ("AppInit_DLLs" in subkey):
                    print("Anomalous subkey detected at " + path + ": " + str(subkey))
                    if (log_file is not 0):
                        log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

        # Key Path 12
        path = str(sid) + r"\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_USERS, path)
            result = reg_value_enum(registry_key)
            for entry in result:
                if ("AppInit_DLLs" in entry):
                    print("Anomalous registry value detected at " + path + ": " + str(entry))
                    if (log_file is not 0):
                        log_file.write("Anomalous registry value detected at " + path + ": " + str(entry) + "\n")
            result = reg_key_enum(registry_key)
            for subkey in result:
                if ("AppInit_DLLs" in subkey):
                    print("Anomalous subkey detected at " + path + ": " + str(subkey))
                    if (log_file is not 0):
                        log_file.write("Anomalous subkey detected at " + path + ": " + str(subkey) + "\n")
        except:
            # An except occurs when the user doesn't have a registry, usually means user is disabled
            pass

# Support Functions +++++++++++++++++++++++++++++++++++++

# Use this to get all of the values in a key
def reg_value_enum(key):
    result = []
    index = 0
    while True:
        try:
            result.append(winreg.EnumValue(key, index))
            index += 1
        except OSError:
            break
    return result


# Use this to get all the sub-keys in a key
def reg_key_enum(key):
    result = []
    index = 0
    while True:
        try:
            result.append(winreg.EnumKey(key, index))
            index += 1
        except OSError:
            break
    return result

# Various keys require us to have a SID in the address, we will get that here
def sid_retrieval():
    # Use wmic to retrieve the users on the box
    users = subprocess.check_output("wmic useraccount get name, description, sid")
    users = users.decode()
    users = users.split("\r\r\n")
    # Begin gathering the SID
    sid = []
    for user in users:
        user = user.split("S-")
        try:
            sid.append(user[1].strip(" "))
        except:
            # Necessary as the first line does not have a user
            pass
    return sid

# USB Forensic Functions +++++++++++++++++++++
def usb_info_retrieval(log_file):
    # Here we will retrieve the setupapi log file and check if there are any USB information logs
    path = r"System\CurrentControlSet\Enum\USBSTOR"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                      (winreg.KEY_WOW64_64KEY + winreg.KEY_READ))
        result = reg_key_enum(registry_key)
        for key in result:
            print("USB Record found in registry: " + key)
            if (log_file is not 0):
                log_file.write("USB Record found in registry: " + key + "\n")
    except:
        print("Unable to access the USBSTOR registry location, this would indicate no USB has been used or USB use has been deactivated")
        if (log_file is not 0):
            log_file.write("Unable to access the USBSTOR registry location, this would indicate no USB has been used or USB use has been deactivated" + "\n")
