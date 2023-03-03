__author__ = "Tejaskumar Kasundra(tejaskumar.kasundra@gmail.com)"

#!/usr/bin/python

from numpy import not_equal
import objc
import ctypes.util
import os.path
import collections
from Foundation import NSOrderedSet
from Cocoa import NSData
import sys
import time
from threading import Thread


def load_objc_framework(framework_name):
    # Utility function that loads a Framework bundle and creates a namedtuple
    # where the attributes are the loaded classes from the Framework bundle

    loaded_classes = dict()
    framework_bundle = objc.loadBundle(framework_name, bundle_path=os.path.dirname(
        ctypes.util.find_library(framework_name)), module_globals=loaded_classes)
    return collections.namedtuple(
        'AttributedFramework',
        loaded_classes.keys())(
        **loaded_classes)


def get_interface_object(interface):
    # First check available WiFi Interfaces. If given
    # inteface is valid and present in list return
    # CoreWLAN interface object else return None.

    interfaces_list = CoreWLAN.CWWiFiClient.interfaceNames()
    if interface in interfaces_list:
        return CoreWLAN.CWWiFiClient.sharedWiFiClient().interfaceWithName_(interface)
    else:
        return None


def scan_ssid(cwinterface, ssid):
    # cwinterface - CoreWLAN CWWiFiClient Interface object
    # ssid - ssid name, security - PSK, 802.1x, OPEN
    # if ssid found with scan with exact security type
    # Return CWNetwork object or return None

    for _ in range(3):
        cwnetwork, error = cwinterface.scanForNetworksWithName_includeHidden_error_(
            ssid, True, None)
        if error is None:
            for ssid in cwnetwork:
                return ssid
        time.sleep(3)
    else:
        return None


def connect_psk_or_open_ssid(interface, ssid, security, psk, status):
    # interface - Interface name
    # ssid - ssid name to connect
    # security - OPEN or PSK
    # psk - Passphrase
    # Return status in string or any error in string

    cwinterface = get_interface_object(interface)
    if cwinterface is None:
        status[0] = "Interface not found on system."
        return
    cwnetwork = scan_ssid(cwinterface, ssid)
    if cwnetwork is None:
        status[0] = "SSID not found in scan. Try again."
        return
    if security == "PSK":
        _, error = cwinterface.associateToNetwork_password_forceBSSID_remember_possiblyHidden_error_(
            cwnetwork, psk, False, True, True, None)
    else:
        # For OPEN security SSID, pass PSK as None
        _, error = cwinterface.associateToNetwork_password_forceBSSID_remember_possiblyHidden_error_(
            cwnetwork, None, False, True, True, None)
    if error is not None:
        status[0] = "Error connecting to SSID."
        return
    status[0] = "Connected"
    return


def connect_8021x_ssid(interface, ssid, username, password, status):
    # interface - Interface name
    # ssid - ssid name to connect
    # username - 802.1X Username
    # password - 802.1X Password
    # Return status in string or any error in string

    cwinterface = get_interface_object(interface)
    if cwinterface is None:
        status[0] = "Interface not found on system."
        return
    cwnetwork = scan_ssid(cwinterface, ssid)
    if cwnetwork is None:
        status[0] = "SSID not found in scan. Try again."
        return
    _, error = cwinterface.associateToEnterpriseNetwork_identity_username_password_forceBSSID_remember_possiblyHidden_error_(
        cwnetwork, None, username, password, False, True, True, None)
    if error is not None:
        status[0] = "Error connecting to SSID."
        return
    status[0] = "Connected"
    return


if __name__ == "__main__":

    # Load the CoreWLAN.framework
    CoreWLAN = load_objc_framework('CoreWLAN')
    if len(sys.argv) < 4:
        print("Mandatory argument missing.\n"
              "Usage: For PSK SSID /usr/bin/python connect.py interface_name"
              " ssid PSK Passphrase\n"
              "For 8021X SSID /usr/bin/python connect.py interface_name"
              " ssid 802.1x 1x_username 1x_password\n"
              "For Open SSID /usr/bin/python connect.py interface_name"
              " ssid OPEN")
        sys.exit(1)
    interface = sys.argv[1]
    ssid = sys.argv[2]
    security = sys.argv[3]

    # To get return status from thread.
    status = [None]
    if security == "PSK" or security == "OPEN":
        # Associate is blocking function, so creating thread to timeout on
        # 10 Secs, if function does not return.
        if security == "PSK":
            psk = sys.argv[4]
            associate_thread = Thread(
                target=connect_psk_or_open_ssid, args=(
                    interface, ssid, security, psk, status, ))
        else:
            associate_thread = Thread(
                target=connect_psk_or_open_ssid, args=(
                    interface, ssid, security, None, status, ))
        associate_thread.daemon = True
        associate_thread.start()
        associate_thread.join(15)
        if associate_thread.is_alive():
            status[0] = "Not able to associate."
        print(status[0])
    elif security == "802.1x":
        username = sys.argv[4]
        password = sys.argv[5]
        associate_thread = Thread(
            target=connect_8021x_ssid, args=(
                interface, ssid, username, password, status, ))
        associate_thread.daemon = True
        associate_thread.start()
        associate_thread.join(15)
        if associate_thread.is_alive():
            status[0] = "Not able to associate."
        print(status[0])
    else:
        print("Unknown security type.")
