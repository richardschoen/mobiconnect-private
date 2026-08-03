
#!/QOpenSys/pkgs/bin/python3
#------------------------------------------------
# Script name: mbcsftpdownload.py
#
# Description:
# This script will download a specified file from a remote SFTP server.
# This version uses Paramiko instead of pysftp and supports user/password,
# private key file, or private key string authentication.
#
# Pip packages needed:
# pip3 install paramiko
#
# Parameters
# --sftphost/-host=SFTP Host
# --sftpport/-port=SFTP Port
# --sftpuser/-user=SFTP User (User name is always required)
# --sftppass/-pass=SFTP Pass (Password can be empty if using private key)
# --privatekeyfile/-privatekey=SFTP SSH private key file
# --privatekeystring/-privatekeystr=SFTP SSH private key as a string value
# --privatekeypass/-privatepass=SFTP SSH private key password if there is one
# --fromremotefile/-fromfile=Remote file to download
# --tolocalfile/-tofile=Local file to download to
# --replacefile/-replace=Replace local to file if it exists. True/False Default=False
#------------------------------------------------

#------------------------------------------------
# Imports
#------------------------------------------------
import sys
from sys import platform
import os
import time
import traceback
import argparse
import io
import stat
import paramiko

#------------------------------------------------
# Script initialization
#------------------------------------------------

appname = "Downloading File via SFTP"
exitcode = 0
exitmessage = ''
ssh = None
sftp = None

print("-------------------------------------------------------------------------------")
print(appname)
print("Start of Main Processing - " + time.strftime("%H:%M:%S"))
print("OS:" + platform)

#------------------------------------------------
# Define useful functions
#------------------------------------------------

def str2bool(strval):
    if strval is None:
        return False
    return strval.lower() in ("yes", "true", "t", "1")


def trim(strval):
    return strval.strip()


def rtrim(strval):
    return strval.rstrip()


def ltrim(strval):
    return strval.lstrip()


def none_if_empty(strval):
    if strval is None:
        return None
    value = strval.strip()
    return value if value != "" else None


def load_private_key_from_file(private_key_file, private_key_pass=None):
    """Load a private key file. Tries Ed25519 first, then common older key types."""
    key_classes = (
        paramiko.Ed25519Key,
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.DSSKey,
    )

    last_exception = None
    for key_class in key_classes:
        try:
            return key_class.from_private_key_file(private_key_file, password=private_key_pass)
        except Exception as ex:
            last_exception = ex

    raise Exception("Unable to load private key file " + private_key_file + ": " + str(last_exception))


def load_private_key_from_string(private_key_string, private_key_pass=None):
    """Load a private key from a string. Supports Ed25519, RSA, ECDSA, and DSS."""
    key_classes = (
        paramiko.Ed25519Key,
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.DSSKey,
    )

    # Helpful when the key is passed with escaped newlines from CL/automation tools.
    normalized_key = private_key_string.replace("\\n", "\n")

    last_exception = None
    for key_class in key_classes:
        try:
            return key_class.from_private_key(io.StringIO(normalized_key), password=private_key_pass)
        except Exception as ex:
            last_exception = ex

    raise Exception("Unable to load private key string: " + str(last_exception))


def sftp_path_is_file(sftp_client, remote_path):
    """Return True when remote_path exists and is a regular file."""
    try:
        remote_attrs = sftp_client.stat(remote_path)
        return stat.S_ISREG(remote_attrs.st_mode)
    except FileNotFoundError:
        return False
    except IOError:
        return False

#------------------------------------------------
# Main script logic
#------------------------------------------------
try:
    parmscriptname = sys.argv[0]

    parser = argparse.ArgumentParser()
    parser.add_argument('-host', '--sftphost', required=True, help="SFTP server host/ip")
    parser.add_argument('-port', '--sftpport', required=True, help="SFTP port")
    parser.add_argument('-user', '--sftpuser', required=True, help="SFTP user")
    parser.add_argument('-pass', '--sftppass', default="", required=False, help="SFTP password")
    parser.add_argument('-privatekey', '--privatekeyfile', default="", required=False, help="Private key file")
    parser.add_argument('-privatekeystr', '--privatekeystring', default="", required=False, help="Private key as a string value")
    parser.add_argument('-privatepass', '--privatekeypass', default="", required=False, help="Private key password")
    parser.add_argument('-fromfile', '--fromremotefile', required=True, help="Remote file to download")
    parser.add_argument('-tofile', '--tolocalfile', required=True, help="Local file to download to")
    parser.add_argument('-replace', '--replacefile', default="False", required=False, help="Replace output file. Default value=False")

    args = parser.parse_args()

    parmsftphost = args.sftphost.strip()
    parmsftpport = int(args.sftpport.strip())
    parmsftpuser = args.sftpuser.strip()
    parmsftppass = none_if_empty(args.sftppass)
    parmsprivatekeyfile = args.privatekeyfile.strip()
    parmsprivatekeystring = args.privatekeystring.strip()
    parmsprivatekeypass = none_if_empty(args.privatekeypass)
    parmsftpfromfile = args.fromremotefile.strip()
    parmtolocalfile = args.tolocalfile.strip()
    parmreplace = str2bool(args.replacefile)

    print("Parameters:")
    print("SFTP Host: " + parmsftphost)
    print("SFTP Port: " + str(parmsftpport))
    print("SFTP User: " + parmsftpuser)
    print("From Remote File: " + parmsftpfromfile)
    print("To Local File: " + parmtolocalfile)
    print("Replace file: " + str(parmreplace))

    pkey = None

    if parmsprivatekeystring != "":
        pkey = load_private_key_from_string(parmsprivatekeystring, parmsprivatekeypass)
    elif parmsprivatekeyfile != "":
        pkey = load_private_key_from_file(parmsprivatekeyfile, parmsprivatekeypass)

    ssh = paramiko.SSHClient()

    # Match original pysftp behavior where host key checking was disabled.
    # For stronger security, replace this with ssh.load_system_host_keys()
    # and remove AutoAddPolicy once known_hosts is maintained.
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = {
        'hostname': parmsftphost,
        'port': parmsftpport,
        'username': parmsftpuser,
        'timeout': 30,
        'banner_timeout': 30,
        'auth_timeout': 30,
    }

    if pkey is not None:
        connect_kwargs['pkey'] = pkey
        if parmsftppass is not None:
            connect_kwargs['password'] = parmsftppass
    else:
        connect_kwargs['password'] = parmsftppass

    ssh.connect(**connect_kwargs)
    sftp = ssh.open_sftp()

    if not sftp_path_is_file(sftp, parmsftpfromfile):
        raise Exception("Remote file " + parmsftpfromfile + " doesn't exist. Process cancelled.")

    if os.path.isfile(parmtolocalfile):
        if parmreplace:
            os.remove(parmtolocalfile)
        else:
            raise Exception('Local file ' + parmtolocalfile + ' exists and replace not selected. Process cancelled.')

    print("Downloading file " + parmsftpfromfile + " to " + parmtolocalfile)
    sftp.get(parmsftpfromfile, parmtolocalfile)

    exitcode = 0
    exitmessage = appname + " was successful."

#------------------------------------------------
# Handle Exceptions
#------------------------------------------------
except Exception as ex:
    exitcode = 99
    exitmessage = str(ex)
    print('Traceback Info')
    traceback.print_exc()

#------------------------------------------------
# Always perform final processing. Output exit message and exit code
#------------------------------------------------
finally:
    try:
        if sftp is not None:
            sftp.close()
    except Exception:
        pass

    try:
        if ssh is not None:
            ssh.close()
    except Exception:
        pass

    print('ExitCode:' + str(exitcode))
    print('ExitMessage:' + exitmessage)
    print("End of Main Processing - " + time.strftime("%H:%M:%S"))
    print("-------------------------------------------------------------------------------")

    sys.exit(exitcode)
