
#!/QOpenSys/pkgs/bin/python3
#------------------------------------------------
# Script name: mbcsshcmd.py
#
# Description:
# This script will run up to 5 individual remote QSH/PASE or other SSH commands
# over an SSH connection using Paramiko only. The commands are run separately.
#
# Supports authentication by:
#   - user ID and password
#   - user ID and private key file
#   - user ID and private key string
#
# Supports Ed25519, RSA, ECDSA, and DSS private keys.
#
# Pip packages needed:
#   pip3 install paramiko
#
# Parameters
# --sftphost/-host=SFTP/SSH Host
# --sftpport/-port=SFTP/SSH Port
# --sftpuser/-user=SFTP/SSH User
# --sftppass/-pass=SFTP/SSH Password. Optional if using private key.
# --privatekeyfile/-privatekey=SSH private key file. Optional.
# --privatekeystring/-privatekeystr=SSH private key as string. Optional.
# --privatekeypass/-privatepass=SSH private key password/passphrase. Optional.
# --command/-cmd=Remote command 1
# --command2/-cmd2=Remote command 2
# --command3/-cmd3=Remote command 3
# --command4/-cmd4=Remote command 4
# --command5/-cmd5=Remote command 5
#------------------------------------------------

import sys
from sys import platform
import os
import time
import traceback
import argparse
import io
import paramiko

#------------------------------------------------
# Helper functions
#------------------------------------------------

def _none_if_blank(value):
    """Return None for blank strings; otherwise return the stripped string."""
    if value is None:
        return None
    value = value.strip()
    return value if value != "" else None


def load_private_key_from_file(private_key_file, private_key_pass=None):
    """Load a private key file, trying common Paramiko key types including Ed25519."""
    key_classes = [
        paramiko.Ed25519Key,
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.DSSKey,
    ]

    last_error = None
    for key_class in key_classes:
        try:
            return key_class.from_private_key_file(private_key_file, password=private_key_pass)
        except Exception as ex:
            last_error = ex

    raise ValueError("Unable to load private key file as Ed25519, RSA, ECDSA, or DSS key") from last_error


def load_private_key_from_string(private_key_string, private_key_pass=None):
    """Load a private key from a string, trying common Paramiko key types including Ed25519."""
    key_classes = [
        paramiko.Ed25519Key,
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.DSSKey,
    ]

    last_error = None
    for key_class in key_classes:
        key_stream = io.StringIO(private_key_string)
        try:
            return key_class.from_private_key(key_stream, password=private_key_pass)
        except Exception as ex:
            last_error = ex

    raise ValueError("Unable to load private key string as Ed25519, RSA, ECDSA, or DSS key") from last_error


def run_remote_command(ssh_client, command, label):
    """Run one remote command and print stdout/stderr. Return its exit status."""
    print("-------------------------------------------------------------------------------")
    print(label + ": " + command)

    stdin, stdout, stderr = ssh_client.exec_command(command)

    # Print stdout as it is returned by the remote command.
    for line in stdout:
        print(line, end="")

    # Print stderr too, so remote command errors are visible in logs.
    for line in stderr:
        print(line, end="", file=sys.stderr)

    exit_status = stdout.channel.recv_exit_status()
    print(label + " ExitStatus: " + str(exit_status))
    return exit_status


#------------------------------------------------
# Script initialization
#------------------------------------------------
appname = "Run remote commands over SSH connection"
exitcode = 0
exitmessage = ""
ssh_client = None

print("-------------------------------------------------------------------------------")
print(appname)
print("Start of Main Processing - " + time.strftime("%H:%M:%S"))
print("OS:" + platform)

#------------------------------------------------
# Main script logic
#------------------------------------------------
try:
    parser = argparse.ArgumentParser()
    parser.add_argument('-host', '--sftphost', required=True, help="SFTP/SSH server host/ip")
    parser.add_argument('-port', '--sftpport', required=True, help="SFTP/SSH port")
    parser.add_argument('-user', '--sftpuser', required=True, help="SFTP/SSH user")
    parser.add_argument('-pass', '--sftppass', default="", required=False, help="SFTP/SSH password")
    parser.add_argument('-privatekey', '--privatekeyfile', default="", required=False, help="Private key file")
    parser.add_argument('-privatekeystr', '--privatekeystring', default="", required=False, help="Private key as string")
    parser.add_argument('-privatepass', '--privatekeypass', default="", required=False, help="Private key password/passphrase")
    parser.add_argument('-cmd', '--command', required=True, help="Command")
    parser.add_argument('-cmd2', '--command2', default="", required=False, help="Command 2")
    parser.add_argument('-cmd3', '--command3', default="", required=False, help="Command 3")
    parser.add_argument('-cmd4', '--command4', default="", required=False, help="Command 4")
    parser.add_argument('-cmd5', '--command5', default="", required=False, help="Command 5")

    args = parser.parse_args()

    parmsftphost = args.sftphost.strip()
    parmsftpport = int(args.sftpport.strip())
    parmsftpuser = args.sftpuser.strip()
    parmsftppass = _none_if_blank(args.sftppass)
    parmsprivatekeyfile = _none_if_blank(args.privatekeyfile)
    parmsprivatekeystring = _none_if_blank(args.privatekeystring)
    parmsprivatekeypass = _none_if_blank(args.privatekeypass)

    commands = [
        ("Command", args.command.strip()),
        ("Command2", args.command2.strip()),
        ("Command3", args.command3.strip()),
        ("Command4", args.command4.strip()),
        ("Command5", args.command5.strip()),
    ]

    print("Parameters:")
    print("SSH Host: " + parmsftphost)
    print("SSH Port: " + str(parmsftpport))
    print("SSH User: " + parmsftpuser)
    for label, command in commands:
        print(label + ": " + command)

    pkey = None
    if parmsprivatekeystring is not None:
        pkey = load_private_key_from_string(parmsprivatekeystring, parmsprivatekeypass)
    elif parmsprivatekeyfile is not None:
        pkey = load_private_key_from_file(parmsprivatekeyfile, parmsprivatekeypass)

    if pkey is None and parmsftppass is None:
        raise ValueError("Either --sftppass, --privatekeyfile, or --privatekeystring must be supplied")

    ssh_client = paramiko.SSHClient()

    # Matches the original script's permissive behavior where host key checking was disabled.
    # For production, replace AutoAddPolicy with RejectPolicy and load known_hosts.
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh_client.connect(
        hostname=parmsftphost,
        port=parmsftpport,
        username=parmsftpuser,
        password=parmsftppass if pkey is None else None,
        pkey=pkey,
        look_for_keys=False,
        allow_agent=False,
        timeout=30,
    )

    highest_command_exit_status = 0
    for label, command in commands:
        if command != "":
            command_exit_status = run_remote_command(ssh_client, command, label)
            if command_exit_status != 0 and highest_command_exit_status == 0:
                highest_command_exit_status = command_exit_status

    print("-------------------------------------------------------------------------------")

    if highest_command_exit_status == 0:
        exitcode = 0
        exitmessage = appname + " was successful."
    else:
        exitcode = highest_command_exit_status
        exitmessage = appname + " completed, but at least one remote command failed."

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
    if ssh_client is not None:
        try:
            ssh_client.close()
        except Exception:
            pass

    print('ExitCode:' + str(exitcode))
    print('ExitMessage:' + exitmessage)
    print("End of Main Processing - " + time.strftime("%H:%M:%S"))
    print("-------------------------------------------------------------------------------")

    sys.exit(exitcode)
