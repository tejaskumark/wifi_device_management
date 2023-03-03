__author__ = "Tejaskumar Kasundra(tejaskumar.kasundra@gmail.com)"

import os
import configparser
import uuid
from xml.etree.ElementTree import Element, SubElement, tostring
import re
import io
import socket
from scp import SCPClient
import paramiko
import time
from src.mlogger import logger


class SshExecution:
    """ This class will handle all SSH related things.
        This will be used across all different types of clients.
    """

    def __init__(self, client_dict):
        self.client_dict = client_dict

    def create_ssh_transport(self):
        for _ in range(1, 5):
            try:
                self.ssh = paramiko.SSHClient()
                self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.ssh.connect(
                    self.client_dict['device_lan_ip'],
                    username=self.client_dict['user'],
                    password=self.client_dict['device_ssh_pass'],
                    port=22,
                    timeout=20)
                logger.info(
                    "[ID:%s IP:%s]Client SSH is OK." %
                    (self.client_dict['device_lan_ip'],
                     self.client_dict['device_name']))
                return 1
            except paramiko.ssh_exception.AuthenticationException as e:
                self.client_dict['error'] = "User %s SSH authentication failed." % self.client_dict['user']
                return 0
            except paramiko.ssh_exception.NoValidConnectionsError as e:
                self.client_dict['error'] = "Host unreachable."
            except socket.timeout as e:
                logger.exception(
                    "[ID:%s IP:%s]Socket tiemout. Will retry after 10 Seconds." %
                    (self.client_dict['device_name'], self.client_dict['device_lan_ip']))
                self.client_dict['error'] = "SSH Failure."
            except Exception as e:
                logger.exception(
                    "[ID:%s IP:%s]Exception:%s. Will retry after 10 Seconds." %
                    (self.client_dict['device_name'], self.client_dict['device_lan_ip'], e))
                self.client_dict['error'] = "SSH Failure."
        else:
            logger.critical(
                "[ID:%s IP:%s]Unable to ssh, even after 4 attempts." %
                (self.client_dict['device_name'], self.client_dict['device_lan_ip']))
            return 0

    def execute_cmd(self, cmd):
        for attempt in range(1, 4):
            try:
                _, stdout, stderr = self.ssh.exec_command(cmd, timeout=30)
                error = str(stderr.read().rstrip(), 'utf-8')
                if error:
                    logger.info(
                        "[ID:%s IP:%s][CMD-%s]Error- %s" %
                        (self.client_dict['device_name'],
                         self.client_dict['device_lan_ip'],
                            cmd,
                            error))
                return str(stdout.read().rstrip(), 'utf-8'), 1
            except EOFError:
                logger.info(
                    "[ID:%s IP:%s][CMD-%s]Exception EOFError. Reconnect and try again.\
                     Attempt# %d" %
                    (self.client_dict['device_name'],
                     self.client_dict['device_lan_ip'],
                     cmd,
                     attempt))
                self.ssh.close()
                self.ssh.connect(
                    self.client_dict['device_lan_ip'],
                    username=self.client_dict['user'],
                    password=self.client_dict['device_ssh_pass'],
                    port=22,
                    timeout=30)
            except paramiko.SSHException as e:
                logger.exception(
                    "[ID:%s IP:%s] Exception:%s. Trying to reconnect." %
                    (self.client_dict['device_name'], self.client_dict['device_lan_ip'], e))
                self.ssh_close()
                self.ssh.connect(
                    self.client_dict['device_lan_ip'],
                    username=self.client_dict['user'],
                    password=self.client_dict['device_ssh_pass'],
                    port=22,
                    timeout=30)
            except Exception as e:
                logger.exception(
                    "[ID:%s IP:%s][CMD-%s]Exception:%s " %
                    (self.client_dict['device_name'], self.client_dict['device_lan_ip'], cmd, e))
        else:
            logger.critical("[ID:%s IP:%s]Unable to execute %s cmd\
                 even after 4 attempts." % (self.client_dict['device_name'], self.client_dict['device_lan_ip'], cmd))
            return "Error", 0

    def scp_put_file(self, file_object, remote_path_xml, file_type=1):
        try:
            scp = SCPClient(self.ssh.get_transport())
            if file_type:
                file_object.seek(0)
                scp.putfo(file_object, remote_path_xml)
            else:
                scp.put(file_object, remote_path_xml)
            scp.close()
            return 1
        except Exception as e:
            logger.exception(
                "Exception:%s during putting file to remote path" %
                e)
            return 0

    def ssh_close(self):
        self.ssh.close()


class Client:
    """ This class is common across different types of client.
        Main objective is to handle things common across all different types of client here.
    """

    def __init__(self, client_dict):
        self.client_dict = client_dict

    def client_initial_check(self):
        self.ssh_execution = SshExecution(self.client_dict)
        if not self.ssh_execution.create_ssh_transport():
            logger.critical(
                "[ID:%s IP:%s]SSH TO %s CLIENT NOT SUCCESSFUL."
                "ABORTING CLIENT CONNECTION." %
                (self.client_dict['device_os'],
                    self.client_dict['device_name'],
                    self.client_dict['device_lan_ip']))
            return 0
        return 1

    def client_final_check(self, misc_update=None):
        self.ssh_execution.ssh_close()
        return 1


class MacClient(Client):
    """ This class will handle all Macbook client connection process.
        Connect Client - Call client_connect_start
        Disconnect Client - Call client_disconnect_start
    """

    def __init__(self, client_dict):
        super().__init__(client_dict)
        self.remote_path_xml = "/tmp/wifi_automate.xml"
        self.mac_client_python = os.path.dirname(
            __file__) + "/misc/mac_connect.py"
        self.remote_path = "/tmp/mac_connect.py"

    def recursive_add_xml_element(self, obj_tmp, node):
        """ Recursively add element to Mac client XML profile.
        """
        for key in node:
            SubElement(obj_tmp, "key").text = key
            if "type" in node[key]:
                if "value" in node[key]:
                    SubElement(
                        obj_tmp, node[key]["type"]).text = node[key]["value"]
                else:
                    SubElement(obj_tmp, node[key]["type"])
            else:
                SubElement(obj_tmp, "string").text = node[key]["value"]

    def mac_client_sanitize(self):
        """ Remove existing profiles from client.
            Turn radio off and on.
        """
        try:
            logger.info(
                "[ID:%s IP:%s]Removing any existing wireless network profile." %
                (self.client_dict['device_name'], self.client_dict['device_lan_ip']))
            self.ssh_execution.execute_cmd("/usr/bin/profiles -D -U %s -f"
                                           % self.client_dict['login_user'])

            self.ssh_execution.execute_cmd("/usr/sbin/networksetup \
                -removeallpreferredwirelessnetworks %s" % self.client_dict['device_wifi_interface'])
            self.ssh_execution.execute_cmd("rm -rf %s" % self.remote_path_xml)

            logger.info(
                "[ID:%s IP:%s]Radio OFF." %
                (self.client_dict['device_name'],
                 self.client_dict['device_lan_ip']))
            _, _ = self.ssh_execution.execute_cmd("/usr/sbin/networksetup \
                -setnetworkserviceenabled Wi-Fi off")
            time.sleep(2)
            logger.info(
                "[ID:%s IP:%s]Radio ON." %
                (self.client_dict['device_name'],
                 self.client_dict['device_lan_ip']))
            _, _ = self.ssh_execution.execute_cmd("/usr/sbin/networksetup \
                -setnetworkserviceenabled Wi-Fi on")
            time.sleep(2)
            self.status["status_info"] = "Profile reset."
            self.status["status_code"] = 1
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            return 1
        except Exception as e:
            logger.info(
                "[ID:%s IP:%s]Exception:%s while sanitizing client." %
                (self.client_dict['device_name'], self.client_dict['device_lan_ip'], e))
            self.status["status_info"] = "Profile reset failed."
            self.status["status_code"] = 0
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            return 0

    def mac_client_xml_creation(self):
        """ Create XML profile for Mac client.
        """
        security_mapping = {"PSK": "WPA2", "802.1x": "WPA", "OPEN": "none"}
        plist = Element('plist')
        plist.set('version', '1.0')
        first_dict = SubElement(plist, "dict")
        common_elem_1 = {
            "PayloadDescription": {
                "value": "Automated WiFi Profile"},
            "PayloadDisplayName": {
                "value": "WiFi Profile"},
            "PayloadIdentifier": {
                "value": "Wi-Fi"},
            "PayloadType": {
                "value": "WiFi Profile"},
            "PayloadUUID": {
                "value": str(
                    uuid.uuid1())}}
        self.recursive_add_xml_element(first_dict, common_elem_1)
        SubElement(first_dict, "key").text = "PayloadContent"
        first_array = SubElement(first_dict, "array")
        second_dict = SubElement(first_array, "dict")
        common_elem_2 = {"AutoJoin": {"type": "true"},
                         "EncryptionType": {"value": security_mapping[self.client_dict["security"]]},
                         "PayloadType": {"value": "com.apple.wifi.managed"},
                         "PayloadUUID": {"value": str(uuid.uuid1())},
                         "SSID_STR": {"value": self.client_dict["device_ssid"]},
                         "HIDDEN_NETWORK": {"type": "true"}}
        self.recursive_add_xml_element(second_dict, common_elem_2)
        if self.client_dict["security"] == "PSK":
            SubElement(second_dict, "key").text = "Password"
            SubElement(second_dict, "string").text = self.client_dict['psk']
        if self.client_dict["security"] == "802.1x":
            SubElement(second_dict, "key").text = "EAPClientConfiguration"
            third_dict = SubElement(second_dict, "dict")
            eap_element = {
                "UserName": {
                    "value": self.client_dict['onex_username']}, "UserPassword": {
                    "value": self.client_dict['onex_password']}, "TTLSInnerAuthentication": {
                    "value": "MSCHAPv2"}, "TLSAllowTrustExceptions": {
                    "type": "true"}}
            self.recursive_add_xml_element(third_dict, eap_element)
            SubElement(third_dict, "key").text = "AcceptEAPTypes"
            second_array = SubElement(third_dict, "array")
            SubElement(second_array, "integer").text = "25"
        file_object = io.StringIO()
        file_object.write(tostring(plist).decode('utf-8'))
        return file_object

    def mac_client_connect(self):
        if not self.ssh_execution.scp_put_file(
                self.mac_client_python,
                self.remote_path, file_type=0):
            logger.critical(
                "[ID:%s IP:%s]Not able to scp wifi xml profile to remote client." %
                (self.client_dict['device_name'], self.client_dict['device_lan_ip']))
            self.status["status_info"] = "SCP Failed."
            self.status["status_code"] = 0
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            return 0
        if self.client_dict["security"] == "PSK":
            out, _ = self.ssh_execution.execute_cmd(
                "/usr/bin/python %s \"%s\" \"%s\" \"%s\" \"%s\"" %
                (self.remote_path, self.client_dict["device_wifi_interface"],
                 self.client_dict["device_ssid"], self.client_dict["security"], self.client_dict["psk"]))
            if out != "Connected":
                logger.critical(
                    "[ID:%s IP:%s]Error while connecting client. Error : %s" %
                    (self.client_dict['device_name'], self.client_dict['device_lan_ip'], out))
                self.status["status_info"] = out
                self.status["status_code"] = 0
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                return 0
            return 1
        elif self.client_dict["security"] == "OPEN":
            out, _ = self.ssh_execution.execute_cmd(
                "/usr/bin/python %s \"%s\" \"%s\" \"%s\"" %
                (self.remote_path, self.client_dict["device_wifi_interface"],
                 self.client_dict["device_ssid"], self.client_dict["security"]))
            if out != "Connected":
                logger.critical(
                    "[ID:%s IP:%s]Error while connecting client. Error : %s" %
                    (self.client_dict['device_name'], self.client_dict['device_lan_ip'], out))
                self.status["status_info"] = out
                self.status["status_code"] = 0
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                return 0
            return 1
        else:
            out, _ = self.ssh_execution.execute_cmd(
                "/usr/bin/python %s \"%s\" \"%s\" \"%s\" \"%s\" \"%s\"" %
                (self.remote_path, self.client_dict["device_wifi_interface"],
                 self.client_dict["device_ssid"], self.client_dict["security"],
                 self.client_dict["onex_username"], self.client_dict["onex_password"]))
            if out != "Connected":
                logger.critical(
                    "[ID:%s IP:%s]Error while connecting client. Error : %s" %
                    (self.client_dict['device_name'], self.client_dict['device_lan_ip'], out))
                self.status["status_info"] = out
                self.status["status_code"] = 0
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                return 0
            return 1

    # This XML profile import has been deprecated in recent Mac OS update.
    # So not using this function any more, and instead using pyobjc way
    # to interact with wifi interface on Mac OS.
    def mac_client_create_profile_connect(self):
        """ This function will create XML Profile.
            Push XML profile to client.
            On success return 1 else 0.
        """
        try:
            xml_object = self.mac_client_xml_creation()
            if not self.ssh_execution.scp_put_file(
                    xml_object, self.remote_path_xml):
                logger.critical(
                    "[ID:%s IP:%s]Not able to scp wifi xml profile to remote client." %
                    (self.client_dict['device_name'], self.client_dict['device_lan_ip']))
                self.status["status_info"] = "SCP Failed."
                self.status["status_code"] = 0
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                return 0
            out, _ = self.ssh_execution.execute_cmd(
                "/usr/bin/profiles -I -U %s -F %s" %
                (self.client_dict['login_user'], self.remote_path_xml))
            if out != "":
                logger.critical(
                    "[ID:%s IP:%s]Not able to import wifi \
                    xml profile to remote client. Error:%s" %
                    (self.client_dict['device_name'], self.client_dict['device_lan_ip'], out))
                self.status["status_info"] = "XML Import Failed."
                self.status["status_code"] = 0
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                return 0
            return 1
        except Exception as e:
            logger.critical(
                "[ID:%s IP:%s]Not able to configure client with SSID profile.\
                Exception:%s" %
                (self.client_dict['device_name'], self.client_dict['device_lan_ip'], e))
            self.status["status_info"] = "Profile Push Failed."
            self.status["status_code"] = 0
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            return 0

    def mac_client_is_associated(self, loop_count=6):
        """ This function will check whethere client getting associated or not.
            Based on client association status return 0 or 1.
        """
        for _ in range(1, loop_count):
            state, _ = self.ssh_execution.execute_cmd(
                "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I |\
                 grep -i state | awk -F \" \" '{print $2}' | xargs")
            bssid, _ = self.ssh_execution.execute_cmd(
                "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport\
                 -I | grep -w BSSID | awk -F \" \" '{print $2}' | xargs")
            bssid = bssid.rstrip().lstrip().upper()
            if state == "running" and bssid != "0:0:0:0:0:0":
                logger.info(
                    "[ID:%s IP:%s]Client got associated to SSID:%s" %
                    (self.client_dict['device_name'],
                     self.client_dict['device_lan_ip'],
                     self.client_dict["device_ssid"]))
                return 1
            else:
                logger.info(
                    "[ID:%s IP:%s]Client not yet associated to SSID:%s "
                    "will retry 5 times, before give it up." %
                    (self.client_dict['device_name'],
                     self.client_dict['device_lan_ip'],
                     self.client_dict['device_ssid']))
                time.sleep(10)
        else:
            logger.info(
                "[ID:%s IP:%s]Client did not associate to SSID:%s after max attempts." %
                (self.client_dict["device_name"],
                 self.client_dict["device_lan_ip"],
                 self.client_dict["device_ssid"]))
            return 0

    def mac_client_os_check(self):
        """ This function will verify client OS.
            Based on verificatio return status 0 or 1.
        """
        out, _ = self.ssh_execution.execute_cmd("sw_vers | echo $?")
        if out != "0":
            logger.info(
                "[ID:%s IP:%s]Client operation system "
                "does not seem to be Mac OS. Please check once. Error Code:%s" %
                (self.client_dict['device_name'], self.client_dict['device_lan_ip'], out))
            return 0
        logger.info(
            "[ID:%s IP:%s]Client operating system check passed. Error Code:%s" %
            (self.client_dict['device_name'], self.client_dict['device_lan_ip'], out))
        return 1

    def client_connect_start(self):
        """ This function will start client connection process.
        """
        self.status = {}
        try:
            self.client_dict["login_user"] = self.client_dict["device_ssh_user"]
            self.client_dict["user"] = self.client_dict["device_ssh_user"]
            if not self.client_initial_check():
                self.status["status_info"] = self.client_dict["error"]
                self.status["status_code"] = 0
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                return self.status
            if not self.mac_client_os_check():
                self.status["status_info"] = "OS check failure."
                self.status["status_code"] = 0
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                return self.status
            self.mac_client_sanitize()
            if self.mac_client_connect():
                if self.mac_client_is_associated():
                    self.mac_client_status_update()
                    self.client_final_check()
                    return self.status
                else:
                    self.client_final_check()
                    self.status["status_info"] = "Profile pushed."
                    self.status["status_code"] = 1
                    self.status["bssid"] = "--"
                    self.status["wifiip"] = "--"
                    return self.status
            else:
                self.client_final_check()
                return self.status
        except Exception as e:
            logger.exception(
                "[ID:%s IP:%s]Exception while client connect %s." %
                (self.client_dict['device_name'], self.client_dict['device_lan_ip'], e))
            self.status["status_info"] = "Try again. Issue persist contact @tejaskumar.kasundra"
            self.status["status_code"] = 0
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            self.client_final_check()
            return self.status

    def mac_client_status_update(self):
        """ This function will fetch client wifi details.
            BSSID, WiFiIP, WiFiMac will be fetched from clients.
        """
        try:
            for _ in range(5):
                state, _ = self.ssh_execution.execute_cmd(
                    "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I | grep -i state | awk -F \" \" '{print $2}' | xargs")
                if state == "running":
                    break
                else:
                    time.sleep(5)
            self.status["wifimac"], _ = self.ssh_execution.execute_cmd(
                "ifconfig %s \
                | grep -i ether | awk -F \" \" '{print $2}' | \
                    xargs" %
                self.client_dict['device_wifi_interface'])
            self.status["wifimac"] = self.status["wifimac"].rstrip(
            ).lstrip().upper()
            if state == "init":
                self.status["status_info"] = "Profile pushed."
                self.status["status_code"] = 1
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                logger.info(
                    "[ID:%s IP:%s]Client BSSID:%s WiFi IP:%s" %
                    (self.client_dict['device_name'],
                     self.client_dict['device_lan_ip'],
                     self.status["bssid"],
                     self.status["wifip"]))
                return 1
            elif state == "running":
                self.status["bssid"], _ = self.ssh_execution.execute_cmd(
                    "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport\
                    -I | grep -w BSSID | awk -F \" \" '{print $2}' | xargs")
                self.status["bssid"] = self.status["bssid"].rstrip(
                ).lstrip().upper()
                time.sleep(5)
                self.status["wifiip"], _ = self.ssh_execution.execute_cmd(
                    "ifconfig %s |\
                    grep -w inet | awk -F \" \" '{print $2}' | xargs" %
                    self.client_dict['device_wifi_interface'])
                if len(self.status["wifiip"].split(".")) != 4:
                    self.status["wifiip"] = "--"
                self.status["status_info"] = "Connected"
                self.status["status_code"] = 1
                logger.info(
                    "[ID:%s IP:%s]Client BSSID:%s WiFi IP:%s" %
                    (self.client_dict['device_name'],
                     self.client_dict['device_lan_ip'],
                     self.status["bssid"],
                     self.status["wifiip"]))
                return 1
            else:
                self.status["status_info"] = "Profile pushed."
                self.status["status_code"] = 1
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                logger.info(
                    "[ID:%s IP:%s]Client Status update is skipped as state is undetermined.")
                return 0
        except Exception as e:
            self.status["status_info"] = "Profile pushed."
            self.status["status_code"] = 1
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            logger.exception(e)
            return 0

    def client_disconnect_start(self):
        """ This function will start client disconnection process.
        """
        self.status = {}
        self.client_dict['login_user'] = self.client_dict['device_ssh_user']
        self.client_dict['user'] = self.client_dict['device_ssh_user']
        if not self.client_initial_check():
            self.status["status_info"] = self.client_dict["error"]
            self.status["status_code"] = 1
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            return self.status
        if not self.mac_client_os_check():
            self.status["status_info"] = "OS check failure."
            self.status["status_code"] = 1
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            return self.status
        self.mac_client_sanitize()
        return self.status


class WindowsClient(Client):
    """ This class will handle all Windows client connection process.
        Connect Client - Call client_connect_start
        Disconnect Client - Call client_disconnect_start
    """

    def __init__(self, client_dict):
        super().__init__(client_dict)
        self.remote_path = "C:/"
        self.remote_path_xml = "C:/wifi_automate.xml"
        self.peap_exe_local = os.path.dirname(__file__) + "/misc/wlan_peap.exe"
        self.peap_exe_remote = "C:/wlan_peap.exe"

    def windows_client_os_check(self):
        """ This function will verify client OS.
            Based on verificatio return status 0 or 1.
        """
        out, _ = self.ssh_execution.execute_cmd("ver | echo %errorlevel%")
        if out != "0":
            logger.info(
                "[ID:%s IP:%s]Client operation system does not "
                "seem to be Windows. Please check once. Error Code:%s" %
                (self.client_dict["device_name"], self.client_dict["device_lan_ip"], out))
            return 0
        logger.info(
            "[ID:%s IP:%s]Client operating system check passed. Error Code:%s" %
            (self.client_dict["device_name"], self.client_dict["device_lan_ip"], out))
        return 1

    def windows_client_parse_netsh(self, element_name, netsh_output):
        """
        This function parse output of netsh wlan show interafces command.
        element_name: This argument is element to serach and return corresponding value.
        netsh_output: This argument accepts output of cli "netsh wlan show interfaces" in string.
        This function will return corresponding vlaues in string.
        """
        pattern = '%s.*:(.*).' % element_name
        found_element = re.search(pattern, netsh_output)
        if found_element:
            if element_name == "BSSID" or element_name == "Physical address":
                bssid = found_element.group().split(":")[1::]
                temp = ":"
                return temp.join(bssid)
            elif element_name == "SSID" or element_name == "State":
                output = found_element.group()
                return output.split(":")[1].lstrip().rstrip()
            else:
                return None

    def windows_client_sanitize(self):
        """ Remove existing profiles from client.
            Turn radio off and on.
        """
        try:
            _, _ = self.ssh_execution.execute_cmd(
                "netsh wlan delete profile name=*")
            out, _ = self.ssh_execution.execute_cmd("echo %errorlevel%")
            logger.info(
                "[ID:%s IP:%s]Removing any existing wireless network profile. Error Code:%s" %
                (self.client_dict["device_name"], self.client_dict["device_lan_ip"], out))
            _, _ = self.ssh_execution.execute_cmd(
                "netsh interface set interface \"%s\" disable" %
                self.client_dict["device_wifi_interface"])
            out, _ = self.ssh_execution.execute_cmd("echo %errorlevel%")
            logger.info(
                "[ID:%s IP:%s]Radio Interface:%s OFF. Error Code:%s" %
                (self.client_dict["device_name"],
                 self.client_dict["device_lan_ip"],
                 self.client_dict["device_wifi_interface"],
                 out))
            time.sleep(2)
            _, _ = self.ssh_execution.execute_cmd(
                "netsh interface set interface \"%s\" enable" %
                self.client_dict["device_wifi_interface"])
            out, _ = self.ssh_execution.execute_cmd("echo %errorlevel%")
            logger.info(
                "[ID:%s IP:%s]Radio Interface:%s ON. Error Code:%s" %
                (self.client_dict["device_name"],
                 self.client_dict["device_lan_ip"],
                 self.client_dict["device_wifi_interface"],
                 out))
            self.status["status_info"] = "Profile reset."
            self.status["status_code"] = 1
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            time.sleep(2)
            return 1
        except Exception as e:
            self.status["status_info"] = "Profile reset failed."
            self.status["status_code"] = 0
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            logger.exception(
                "[ID:%s IP:%s]Exception:%s while sanitizing client." %
                (self.client_dict["device_name"], self.client_dict["device_lan_ip"], e))
            return 0

    def windows_client_xml_create(self):
        """ XML Profile will be created.
            Return: File like object of XML profile
        """
        WLANProfile = (Element("WLANProfile",
                               xmlns="http://www.microsoft.com"
                               "/networking/WLAN/profile/v1"))
        SubElement(WLANProfile, "name").text = self.client_dict["device_ssid"]
        SSIDConfig = SubElement(WLANProfile, "SSIDConfig")
        SSID = SubElement(SSIDConfig, "SSID")
        SubElement(SSID, "name").text = self.client_dict["device_ssid"]
        SubElement(SSIDConfig, "nonBroadcast").text = "true"
        SubElement(WLANProfile, 'connectionType').text = "ESS"
        if self.client_dict["security"] == "802.1x":
            SubElement(WLANProfile, 'connectionMode').text = "manual"
        else:
            SubElement(WLANProfile, 'connectionMode').text = "auto"
        MSM = SubElement(WLANProfile, 'MSM')
        Security = SubElement(MSM, 'security')
        if self.client_dict["security"] == "OPEN":
            authencryption = SubElement(Security, "authEncryption")
            SubElement(authencryption, "authentication").text = "open"
            SubElement(authencryption, "encryption").text = "none"
            SubElement(authencryption, "useOneX").text = "false"
            file_object = io.StringIO()
            file_object.write(tostring(WLANProfile).decode('utf-8'))
            return file_object
        if self.client_dict["security"] == "PSK":
            authencryption = SubElement(Security, "authEncryption")
            SubElement(authencryption, "authentication").text = "WPA2PSK"
            SubElement(authencryption, "encryption").text = "AES"
            SubElement(authencryption, "useOneX").text = "false"
            sharedkey = SubElement(Security, "sharedKey")
            SubElement(sharedkey, "keyType").text = "passPhrase"
            SubElement(sharedkey, "protected").text = "false"
            SubElement(sharedkey, "keyMaterial").text = self.client_dict['psk']
            file_object = io.StringIO()
            file_object.write(tostring(WLANProfile).decode('utf-8'))
            return file_object
        if self.client_dict["security"] == "802.1x":
            authencryption = SubElement(Security, "authEncryption")
            SubElement(authencryption, "authentication").text = "WPA2"
            SubElement(authencryption, "encryption").text = "AES"
            SubElement(authencryption, "useOneX").text = "true"
            SubElement(Security, "PMKCacheMode").text = "enabled"
            SubElement(Security, "PMKCacheTTL").text = "720"
            SubElement(Security, "PMKCacheSize").text = "128"
            SubElement(Security, "preAuthMode").text = "disabled"
            onex = SubElement(
                Security,
                "OneX",
                xmlns="http://www.microsoft.com/networking/OneX/v1")
            SubElement(onex, "authMode").text = "user"
            eapconfig = SubElement(onex, "EAPConfig")
            eaphostconfig = SubElement(
                eapconfig,
                "EapHostConfig",
                xmlns="http://www.microsoft.com/provisioning/EapHostConfig")
            eapmethod = SubElement(eaphostconfig, "EapMethod")
            SubElement(
                eapmethod,
                "Type",
                xmlns="http://www.microsoft.com/provisioning/EapCommon").text = "25"
            SubElement(
                eapmethod,
                "VendorId",
                xmlns="http://www.microsoft.com/provisioning/EapCommon").text = "0"
            SubElement(
                eapmethod,
                "VendorType",
                xmlns="http://www.microsoft.com/provisioning/EapCommon").text = "0"
            SubElement(
                eapmethod,
                "AuthorId",
                xmlns="http://www.microsoft.com/provisioning/EapCommon").text = "0"
            config = SubElement(
                eaphostconfig,
                "Config",
                xmlns="http://www.microsoft.com/provisioning/EapHostConfig")
            eap = SubElement(
                config,
                "Eap",
                xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1")
            SubElement(eap, "Type").text = "25"
            eaptype = SubElement(
                eap,
                "EapType",
                xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1")
            servervalidation = SubElement(eaptype, "ServerValidation")
            SubElement(
                servervalidation,
                "DisableUserPromptForServerValidation").text = "false"
            SubElement(servervalidation, "ServerNames")
            SubElement(servervalidation, "TrustedRootCA")
            SubElement(eaptype, "FastReconnect").text = "true"
            SubElement(eaptype, "InnerEapOptional").text = "false"
            eap_inner = SubElement(
                eaptype,
                "Eap",
                xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1")
            SubElement(eap_inner, "Type").text = "26"
            eaptype_inner = SubElement(
                eap_inner,
                "EapType",
                xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1")
            SubElement(eaptype_inner, "UseWinLogonCredentials").text = "false"
            SubElement(eaptype, "EnableQuarantineChecks").text = "false"
            SubElement(eaptype, "RequireCryptoBinding").text = "false"
            peapextensions = SubElement(eaptype, "PeapExtensions")
            SubElement(
                peapextensions,
                "PerformServerValidation",
                xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2").text = "false"
            SubElement(
                peapextensions,
                "AcceptServerName",
                xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2").text = "true"
            peapextensionsv2 = SubElement(
                peapextensions,
                "PeapExtensionsV2",
                xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2")
            SubElement(
                peapextensionsv2,
                "AllowPromptingWhenServerCANotFound",
                xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV3").text = "true"
            file_object = io.StringIO()
            file_object.write(tostring(WLANProfile).decode('utf-8'))
            return file_object

    def windows_client_create_profile_connect(self):
        """ This function will create XML Profile.
            Push XML profile to client.
            On success return 1 else 0.
        """
        xml_profile = self.windows_client_xml_create()
        if self.ssh_execution.scp_put_file(xml_profile, self.remote_path_xml):
            if self.client_dict["security"] == "802.1x":
                logger.info(self.client_dict)
                out, _ = self.ssh_execution.execute_cmd(
                    "if exist %s echo 1" %
                    (self.peap_exe_remote))
                if out == "1":
                    logger.info(
                        "[ID:%s IP:%s]PEAP Binary already present. Status:%s" %
                        (self.client_dict["device_name"], self.client_dict["device_lan_ip"], out))
                else:
                    if not self.ssh_execution.scp_put_file(
                            self.peap_exe_local, self.remote_path, file_type=0):
                        self.status["status_info"] = "SCP Failed."
                        self.status["status_code"] = 0
                        self.status["bssid"] = "--"
                        self.status["wifiip"] = "--"
                        return 0
            out, _ = self.ssh_execution.execute_cmd(
                "netsh wlan add profile filename=%s" %
                self.remote_path_xml)
            if "added" not in out.split(" "):
                logger.info(
                    "[ID:%s IP:%s]Some error during import profile %s." %
                    (self.client_dict["device_name"], self.client_dict["device_lan_ip"], out))
                self.status["status_info"] = "XML Import Failed."
                self.status["status_code"] = 0
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                return 0

            if self.client_dict["security"] == "802.1x":
                out, _ = self.ssh_execution.execute_cmd(
                    "C:\\wlan_peap.exe -ssidname \"%s\"\
                    -username \"%s\" -password \"%s\"" %
                    (self.client_dict["device_ssid"],
                        self.client_dict['onex_username'],
                        self.client_dict['onex_password']))
                if out == "1":
                    self.status["status_info"] = "802.1X Settings Failed."
                    self.status["status_code"] = 0
                    self.status["bssid"] = "--"
                    self.status["wifiip"] = "--"
                    return 0
                _, _ = self.ssh_execution.execute_cmd(
                    "netsh wlan set profileparameter\
                    name=\"%s\" connectionmode=auto" %
                    self.client_dict["device_ssid"])
            status, _ = self.ssh_execution.execute_cmd("echo %errorlevel%")
            logger.info("[ID:%s IP:%s]Client connection started. Error Code:%s" % (
                self.client_dict["device_name"], self.client_dict["device_lan_ip"], status))
            return 1
        else:
            self.status["status_info"] = "Profile Push Failed."
            self.status["status_code"] = 0
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            logger.critical(
                "[ID:%s IP:%s]Not able to configure client "
                "with SSID profile." %
                (self.client_dict["device_name"],
                 self.client_dict["device_lan_ip"]))
            return 0

    def windows_client_is_associated(self, loop_count=6):
        """ This function will check client association.
            On successful association 1 will be returned and 0 on failure.
        """
        for _ in range(1, loop_count):
            out, _ = self.ssh_execution.execute_cmd(
                "netsh wlan show interface name='%s" %
                self.client_dict["device_wifi_interface"])
            state_out = self.windows_client_parse_netsh("State", out)
            bssid = self.windows_client_parse_netsh("BSSID", out)
            if state_out == "connected" and bssid != "":
                logger.info(
                    "[ID:%s IP:%s]Client got associated to SSID:%s" %
                    (self.client_dict["device_name"],
                     self.client_dict["device_lan_ip"],
                     self.client_dict["device_ssid"]))
                return 1
            else:
                logger.info(
                    "[ID:%s IP:%s]Client not yet associated to SSID:%s will retry "
                    "5 times, before give it up." %
                    (self.client_dict["device_name"],
                     self.client_dict["device_lan_ip"],
                     self.client_dict["device_ssid"]))
                time.sleep(10)
        else:
            logger.info(
                "[ID:%s IP:%s]Client did not associate to SSID:%s after max attempts." %
                (self.client_dict["device_name"], self.client_dict["device_lan_ip"], self.client_dict["device_ssid"]))
            return 0

    def client_connect_start(self):
        """ This function will start client connection process.
        """
        self.status = {}
        self.client_dict["user"] = self.client_dict["device_ssh_user"]
        try:
            if not self.client_initial_check():
                self.status["status_info"] = self.client_dict["error"]
                self.status["status_code"] = 0
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                return self.status
            if not self.windows_client_os_check():
                self.status["status_info"] = "OS Check Failure."
                self.status["status_code"] = 0
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                return self.status
            self.windows_client_sanitize()
            if self.windows_client_create_profile_connect():
                if self.windows_client_is_associated():
                    self.windows_client_status_update()
                    self.client_final_check()
                    return self.status
                else:
                    self.client_final_check()
                    self.status["status_info"] = "Profile pushed."
                    self.status["status_code"] = 1
                    self.status["bssid"] = "--"
                    self.status["wifiip"] = "--"
                    return self.status
            else:
                self.client_final_check()
                return self.status
        except Exception as e:
            logger.exception(
                "[ID:%s IP:%s]Exception while client connect %s." %
                (self.client_dict["device_name"], self.client_dict["device_lan_ip"], e))
            self.status["status_info"] = "Try again. Issue persist contact @tejaskumar.kasundra"
            self.status["status_code"] = 1
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            self.client_final_check()
            return self.status

    def windows_client_parse_ipconfig(self, element, subelement, ipconfig):
        """ This function will parse ipconfig and return value based
            on element and subelement given.
        """
        RE_ELEM_COMPONENT = re.compile(r"{}.*".format(element))
        RE_SUBELEM_COMPONENT = re.compile(r"{}.*".format(subelement))
        y = 1
        for line in ipconfig.split("\n"):
            if RE_ELEM_COMPONENT.search(line):
                y = 0
            if RE_SUBELEM_COMPONENT.search(line) and y == 0:
                return line.split(":")[1].rstrip()
        return None

    def windows_client_status_update(self):
        """ This function will fetch client wifi details.
            BSSID, WiFiIP, WiFiMac will be fetched from clients.
        """
        for _ in range(5):
            netsh, _ = self.ssh_execution.execute_cmd(
                "netsh wlan show interfaces")
            state = self.windows_client_parse_netsh("State", netsh)
            if state == "connected":
                break
            else:
                time.sleep(5)
        self.status["wifimac"] = self.windows_client_parse_netsh(
            "Physical address", netsh)
        self.status["wifimac"] = self.status["wifimac"].rstrip(
        ).lstrip().upper()
        if state == "disconnected":
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            self.status["status_info"] = "Profile pushed."
            self.status["status_code"] = 1
            logger.info(
                "[ID:%s IP:%s]Client BSSID:%s WiFi IP:%s" %
                (self.client_dict["device_name"],
                 self.client_dict["device_lan_ip"],
                 self.status["bssid"],
                 self.status["wifiip"]))
            return 1
        elif state == "connected":
            self.status["bssid"] = self.windows_client_parse_netsh(
                "BSSID", netsh)
            self.status["bssid"] = self.status["bssid"].rstrip(
            ).lstrip().upper()
            ipconfig, _ = self.ssh_execution.execute_cmd("ipconfig")
            self.status["wifiip"] = self.windows_client_parse_ipconfig(
                "Wireless", "IPv4 Address", ipconfig)
            if len(self.status["wifiip"].split(".")) != 4:
                self.status["wifiip"] = "--"
            logger.info(
                "[ID:%s IP:%s]Client BSSID:%s WiFi IP:%s" %
                (self.client_dict["device_name"],
                 self.client_dict["device_lan_ip"],
                 self.status["bssid"],
                 self.status["wifiip"]))
            self.status["status_info"] = "Connected"
            self.status["status_code"] = 1
            return 1
        else:
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            self.status["status_info"] = "Profile Pushed."
            self.status["status_code"] = 1
            logger.info(
                "[ID:%s IP:%s]Client Status update is skipped as WiFi is off." %
                (self.client_dict["device_name"], self.client_dict["device_lan_ip"]))
            return 0

    def client_disconnect_start(self):
        """ This function will start client disconnection process.
        """
        self.status = {}
        self.client_dict["user"] = self.client_dict["device_ssh_user"]
        if not self.client_initial_check():
            self.status["status_info"] = self.client_dict["error"]
            self.status["status_code"] = 1
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            return self.status
        if not self.windows_client_os_check():
            self.status["status_info"] = "OS check failure."
            self.status["status_code"] = 1
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            return self.status
        self.windows_client_sanitize()
        self.client_final_check()
        return self.status


class RasPiClient(Client):
    """ This class will handle all RasPi client connection process.
        Connect Client - Call client_connect_start
        Disconnect Client - Call client_disconnect_start
    """

    def __init__(self, client_dict):
        super().__init__(client_dict)
        self.raspi_client_conf_path = "/etc/wpa_supplicant/%s"\
            % self.client_dict["device_wifi_interface"]

    def raspi_client_sanitize(self):
        """ Remove existing profiles from client.
            Push default profile to client.
            Turn radio off and on.
        """
        try:
            _, _ = self.ssh_execution.execute_cmd(
                "ip addr flush %s" %
                self.client_dict["device_wifi_interface"])
            logger.info(
                "[ID:%s IP:%s]IP Addr flused from interface." %
                (self.client_dict["device_name"],
                 self.client_dict["device_lan_ip"]))
            logger.info("[ID:%s IP:%s]Killing any existing running wpa_supplicant." % (
                self.client_dict["device_name"], self.client_dict["device_lan_ip"]))
            pid, _ = self.ssh_execution.execute_cmd(
                "ps -ef | grep -i wpa_supplicant\
                | grep -i %s | grep -v grep | awk -F \" \" '{print $2}' | xargs" %
                self.client_dict["device_wifi_interface"])
            if pid == "" or pid is not None:
                _, _ = self.ssh_execution.execute_cmd("/bin/kill -9 %s" % pid)
            _, _ = self.ssh_execution.execute_cmd(
                "/bin/rm -rf %s" %
                self.raspi_client_conf_path)
            conf = io.StringIO()
            conf.write(
                "ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev")
            conf.write("\nupdate_config=1\ncountry=IN\n")
            if not self.ssh_execution.scp_put_file(
                    conf, self.raspi_client_conf_path):
                logger.info(
                    "[ID:%s IP:%s]Not able to push default supplicant conf. Aborting." %
                    (self.client_dict["device_name"], self.client_dict["device_lan_ip"]))
                self.status["status_info"] = "Profile reset failed."
                self.status["status_code"] = 0
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                return 0
            cli = "/sbin/wpa_supplicant -s -B -P /run/wpa_supplicant.%s.pid -i %s\
                     -D nl80211,wext -c %s" % (self.client_dict["device_wifi_interface"],
                                               self.client_dict["device_wifi_interface"], self.raspi_client_conf_path)
            _, _ = self.ssh_execution.execute_cmd(cli)
            self.status["status_info"] = "Profile reset."
            self.status["status_code"] = 1
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            return 1
        except Exception as e:
            self.status["status_info"] = "Profile reset failed."
            self.status["status_code"] = 0
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            logger.exception(
                "[ID:%s IP:%s]Exception:%s while sanitizing client." %
                (self.client_dict["device_name"], self.client_dict["device_lan_ip"], e))
            return 0

    def raspi_client_create_profile_connect(self):
        """ This function will create Profile.
            Push profile to client.
            On success return 1 else 0.
        """
        try:
            conf = io.StringIO()
            conf.write(
                "ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\n")
            conf.write("update_config=1\ncountry=IN\n")
            if self.client_dict['security'] == "PSK":
                conf.write(
                    "network={\nssid=\"%s\"\nscan_ssid=1\npsk=\"%s\"\nkey_mgmt=WPA-PSK\n}" %
                    (self.client_dict["device_ssid"], self.client_dict['psk']))
            if self.client_dict['security'] == "OPEN":
                conf.write(
                    "network={\nssid=\"%s\"\nscan_ssid=1\nkey_mgmt=NONE\n}" %
                    self.client_dict["device_ssid"])
            if self.client_dict['security'] == "802.1x":
                conf.write(
                    "network={\nssid=\"%s\"\nscan_ssid=1\nkey_mgmt=WPA-EAP\neap=PEAP\n"
                    "identity=\"%s\"\npassword=\"%s\"\nphase2=\"auth=MSCHAPV2\"\n}" %
                    (self.client_dict["device_ssid"],
                     self.client_dict['onex_username'],
                     self.client_dict['onex_password']))
            if not self.ssh_execution.scp_put_file(
                    conf, self.raspi_client_conf_path):
                logger.info(
                    "[ID:%s IP:%s]Not able to push supplicant conf. Aborting." %
                    (self.client_dict["device_name"], self.client_dict["device_lan_ip"]))
                self.status["status_info"] = "SCP Failed."
                self.status["status_code"] = 0
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                return 0
            logger.info(
                "[ID:%s IP:%s]Client profile pushed successful." %
                (self.client_dict["device_name"], self.client_dict["device_lan_ip"]))
            _, _ = self.ssh_execution.execute_cmd(
                "chmod 600 %s" %
                (self.raspi_client_conf_path))
            _, _ = self.ssh_execution.execute_cmd(
                "ifconfig %s down" %
                (self.client_dict["device_wifi_interface"]))
            time.sleep(3)
            _, _ = self.ssh_execution.execute_cmd(
                "/bin/kill -15 `ps -ef | grep -i wpa_supplicant|\
                    grep -i %s | awk -F \" \" '{print $2}' | xargs`" %
                self.client_dict["device_wifi_interface"])
            _, _ = self.ssh_execution.execute_cmd(
                "ifconfig %s up" %
                self.client_dict["device_wifi_interface"])
            time.sleep(3)
            cli = "/sbin/wpa_supplicant -s -B -P /run/wpa_supplicant.%s.pid -i %s\
                    -D nl80211,wext -c %s" % (self.client_dict["device_wifi_interface"],
                                              self.client_dict["device_wifi_interface"], self.raspi_client_conf_path)
            _, _ = self.ssh_execution.execute_cmd(cli)
            logger.info("[ID:%s IP:%s]Killing any existing running dhclient." % (
                self.client_dict["device_name"], self.client_dict["device_lan_ip"]))
            pid, _ = self.ssh_execution.execute_cmd(
                "ps -ef | grep -i dhclient\
                | grep -i %s | grep -v grep | awk -F \" \" '{print $2}' | xargs" %
                self.client_dict["device_wifi_interface"])
            if pid == "" or pid is not None:
                _, _ = self.ssh_execution.execute_cmd("/bin/kill -9 %s" % pid)
            return 1
        except Exception as e:
            logger.critical(
                "[ID:%s IP:%s]Not able to configure client with SSID profile.\
                 Exception:%s" %
                (self.client_dict["device_name"], self.client_dict["device_lan_ip"], e))
            self.status["status_info"] = "Profile Push Failed."
            self.status["status_code"] = 0
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            return 0

    def raspi_client_is_associated(self, loop_count=6):
        """ This function will check client association.
            On successful association start dhclient.
            Success 1 will be returned and 0 on failure.
        """
        for _ in range(1, loop_count):
            out, _ = self.ssh_execution.execute_cmd(
                "/sbin/wpa_cli -i % s status | grep -w wpa_state | awk -F '=' '{print $2}'" %
                self.client_dict["device_wifi_interface"])
            bssid, _ = self.ssh_execution.execute_cmd(
                "/sbin/wpa_cli -i %s status | grep -w bssid | awk -F '=' '{print $2}'" %
                self.client_dict["device_wifi_interface"])
            bssid = bssid.rstrip().lstrip().upper()
            if out == "COMPLETED" and bssid != "":
                logger.info(
                    "[ID:%s IP:%s]Client got associated to SSID:%s" %
                    (self.client_dict["device_name"],
                     self.client_dict["device_lan_ip"],
                     self.client_dict["device_ssid"]))
                _, _ = self.ssh_execution.execute_cmd(
                    "dhclient %s &" %
                    self.client_dict["device_wifi_interface"])
                logger.info(
                    "[ID:%s IP:%s]Starting dhclient." %
                    (self.client_dict["device_name"],
                     self.client_dict["device_lan_ip"]))
                return 1
            else:
                logger.info(
                    "[ID:%s IP:%s]Client not yet associated to SSID:%s will retry 5 times,"
                    "before give it up." %
                    (self.client_dict["device_name"],
                     self.client_dict["device_lan_ip"],
                     self.client_dict["device_ssid"]))
                time.sleep(10)
        else:
            logger.info(
                "[ID:%s IP:%s]Client did not associate to SSID:%s after max attempts." %
                (self.client_dict["device_name"],
                 self.client_dict["device_lan_ip"],
                 self.client_dict["device_ssid"]))
            return 0

    def raspi_client_os_check(self):
        """ Verify client OS with Raspberry.
            On success return 1 and on failure return 0.
        """
        out, _ = self.ssh_execution.execute_cmd("lsb_release -i |\
            awk -F \" \" \'{print $3}\' | xargs")
        if out != "Raspbian":
            logger.info(
                "[ID:%s IP:%s]Client operation system does not seem to be Raspbian OS."
                "Please check once. OS:%s" %
                (self.client_dict["device_name"], self.client_dict["device_lan_ip"], out))
            return 0
        logger.info("[ID:%s IP:%s]Client operating system check passed. OS:%s" % (
            self.client_dict["device_name"], self.client_dict["device_lan_ip"], out))
        return 1

    def client_connect_start(self):
        """ This function will start client connection process.
        """
        self.status = {}
        self.client_dict["user"] = self.client_dict["device_ssh_user"]
        try:
            if not self.client_initial_check():
                self.status["status_info"] = self.client_dict["error"]
                self.status["status_code"] = 0
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                return self.status
            if not self.raspi_client_os_check():
                self.status["status_info"] = "OS Check Failure."
                self.status["status_code"] = 0
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                return self.status
            self.raspi_client_sanitize()
            if self.raspi_client_create_profile_connect():
                if self.raspi_client_is_associated():
                    self.raspi_client_status_update()
                    self.client_final_check()
                    return self.status
                else:
                    self.client_final_check()
                    self.status["status_info"] = "Profile pushed."
                    self.status["status_code"] = 1
                    self.status["bssid"] = "--"
                    self.status["wifiip"] = "--"
                    return self.status
            else:
                self.client_final_check()
                return self.status
        except Exception as e:
            logger.exception(
                "[ID:%s IP:%s]Exception while client connect %s." %
                (self.client_dict["device_name"], self.client_dict["device_lan_ip"], e))
            self.status["status_info"] = "Try again. Issue persist contact @tejaskumar.kasundra"
            self.status["status_code"] = 1
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            self.client_final_check()
            return self.status

    def client_disconnect_start(self):
        """ This function will start client disconnection process.
        """
        self.status = {}
        self.client_dict["user"] = self.client_dict["device_ssh_user"]
        if not self.client_initial_check():
            self.status["status_info"] = self.client_dict["error"]
            self.status["status_code"] = 1
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            return self.status
        if not self.raspi_client_os_check():
            self.status["status_info"] = "OS check failure."
            self.status["status_code"] = 1
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            return self.status
        self.raspi_client_sanitize()
        self.client_final_check()
        return self.status

    def raspi_client_status_update(self):
        """ This function will fetch client wifi details.
            BSSID, WiFiIP, WiFiMac will be fetched from clients.
        """
        for _ in range(5):
            state, _ = self.ssh_execution.execute_cmd(
                "/sbin/wpa_cli -i %s status | grep -w wpa_state\
                | awk -F '=' '{print $2}'" %
                self.client_dict["device_wifi_interface"])
            if state == "COMPLETED":
                break
            else:
                time.sleep(5)
        self.status["wifimac"], _ = self.ssh_execution.execute_cmd(
            "ifconfig %s |\
            grep -i hwaddr | awk -F \" \" '{print $5}' | xargs" %
            self.client_dict["device_wifi_interface"])
        if self.status["wifimac"] == "":
            self.status["wifimac"], _ = self.ssh_execution.execute_cmd(
                "ifconfig %s |\
                grep -i ether | awk -F \" \" '{print $2}' | xargs" %
                self.client_dict["device_wifi_interface"])
        self.status["wifimac"] = self.status["wifimac"].rstrip().lstrip().upper()
        if state == "COMPLETED":
            self.status["bssid"], _ = self.ssh_execution.execute_cmd(
                "/sbin/wpa_cli\
                -i %s status | grep -w bssid | awk -F '=' '{print $2}'" %
                self.client_dict["device_wifi_interface"])
            self.status["bssid"] = self.status["bssid"].rstrip(
            ).lstrip().upper()
            if len(self.status["bssid"].split(":")) != 6:
                self.status["bssid"] == "--"
            time.sleep(5)
            self.status["wifiip"], _ = self.ssh_execution.execute_cmd(
                "ifconfig %s \
                | grep -w inet |awk -F \" \" '{print $2}' | xargs" %
                self.client_dict["device_wifi_interface"])
            if re.search(r'addr:.*', self.status["wifiip"]):
                self.status["wifiip"] = self.status["wifiip"].split(":")[
                    1]
            if len(self.status["wifiip"].split(".")
                   ) != 4 or self.status["wifiip"] is None:
                self.status["wifiip"] = "--"
            logger.info(
                "[ID:%s IP:%s]Client BSSID:%s WiFi IP:%s WiFi_Mac:%s" %
                (self.client_dict["device_name"],
                    self.client_dict["device_lan_ip"],
                    self.status["bssid"],
                    self.status["wifiip"],
                    self.status["wifimac"]))
            self.status["status_info"] = "Connected"
            self.status["status_code"] = 1
            return 1
        else:
            self.status["status_info"] = "Profile pushed."
            self.status["status_code"] = 1
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            logger.info(
                "[ID:%s IP:%s]Client BSSID:%s WiFi IP:%s" %
                (self.client_dict["device_name"],
                    self.client_dict["device_lan_ip"],
                    self.status["bssid"],
                    self.status["wifiip"]))
            return 1


class UbuntuClient(Client):
    """ This class will handle all Ubuntu client connection process.
        Connect Client - Call client_connect_start
        Disconnect Client - Call client_disconnect_start
    """

    def __init__(self, client_dict):
        super().__init__(client_dict)
        self.ubuntu_client_conf_path = "/etc/NetworkManager/system-connections/"

    def ubuntu_client_sanitize(self):
        """ Remove all existing profiles from client.
            Push default profile to client.
            Turn radio off and on.
        """
        try:
            profiles, _ = self.ssh_execution.execute_cmd(
                "/usr/bin/nmcli connection show | grep \"wi-fi\\|wireless\\|wifi\" \
                | awk -F \" \" \'{print \"%s\"$1\"*\"}\' | xargs" %
                self.ubuntu_client_conf_path)
            _, _ = self.ssh_execution.execute_cmd(
                "cd %s; rm -rf %s" %
                (self.ubuntu_client_conf_path, profiles))
            logger.info("[ID:%s IP:%s]NMCLI Removed wireless network profile(s):. %s" % (
                self.client_dict["device_name"], self.client_dict["device_lan_ip"], profiles))
            profiles, _ = self.ssh_execution.execute_cmd(
                "grep -in \"ssid\" /etc/NetworkManager/system-connections/* \
                | awk -F \":\" \'{print $1}\' | xargs")
            if profiles != "":
                _, _ = self.ssh_execution.execute_cmd("rm -rf %s" % profiles)
                logger.info("[ID:%s IP:%s]Dir Removed wireless network profile(s):. %s" % (
                    self.client_dict["device_name"], self.client_dict["device_lan_ip"], profiles))
            logger.info(
                "[ID:%s IP:%s]Restarting network-manager service." %
                (self.client_dict["device_name"], self.client_dict["device_lan_ip"]))
            _, _ = self.ssh_execution.execute_cmd(
                "service network-manager restart")
            logger.info(
                "[ID:%s IP:%s]Radio OFF." %
                (self.client_dict["device_name"],
                 self.client_dict["device_lan_ip"]))
            _, _ = self.ssh_execution.execute_cmd(
                "/usr/bin/nmcli radio wifi off")
            time.sleep(5)
            logger.info(
                "[ID:%s IP:%s]Radio ON." %
                (self.client_dict["device_name"],
                 self.client_dict["device_lan_ip"]))
            _, _ = self.ssh_execution.execute_cmd(
                "/usr/bin/nmcli radio wifi on")
            self.status["status_info"] = "Profile reset."
            self.status["status_code"] = 1
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            time.sleep(5)
            return 1
        except Exception as e:
            self.status["status_info"] = "Profile reset failed."
            self.status["status_code"] = 0
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            logger.exception(
                "[ID:%s IP:%s]Exception:%s while sanitizing client." %
                (self.client_dict["device_name"], self.client_dict["device_lan_ip"], e))
            return 0

    def ubuntu_client_create_profile_connect(self):
        """ This function will create Profile.
            Push profile to client.
            On success return 1 else 0.
        """
        try:
            self.ubuntu_client_property()
            config = configparser.ConfigParser()
            # Adding connection section
            config.add_section("connection")
            config.set(
                "connection", "id", "%s" %
                self.client_dict["device_ssid"])
            config.set("connection", "uuid", "%s" % str(uuid.uuid1()))
            config.set("connection", "type", "wifi")
            config.set("connection", "permission", "")
            config.set("connection", "autoconnect-priority", "99")
            # Adding wifi section
            config.add_section("wifi")
            config.set("wifi", "hidden", "true")
            config.set("wifi", "mac-address-blacklist", "")
            config.set("wifi", "mode", "infrastructure")
            config.set("wifi", "ssid", "%s" % self.client_dict["device_ssid"])
            # Adding wifi-security section for PSK or 802.1x
            if self.client_dict['security'] != "OPEN":
                config.add_section("wifi-security")
                if self.client_dict['security'] == "PSK":
                    config.set("wifi-security", "key-mgmt", "wpa-psk")
                    config.set(
                        "wifi-security", "psk", "%s" %
                        self.client_dict['psk'])
                if self.client_dict['security'] == "802.1x":
                    config.set("wifi-security", "key-mgmt", "wpa-eap")
                    # Adding 802-1x section for 802.1x
                    config.add_section("802-1x")
                    config.set("802-1x", "eap", "peap")
                    config.set(
                        "802-1x", "identity", "%s" %
                        self.client_dict['onex_username'])
                    config.set(
                        "802-1x", "password", "%s" %
                        self.client_dict['onex_password'])
                    config.set("802-1x", "phase2-auth", "mschapv2")
            config.add_section("ipv4")
            config.set("ipv4", "dns-search", "")
            config.set("ipv4", "method", "auto")
            config.set("ipv4", "route-metric", "99")
            config.add_section("ipv6")
            config.set("ipv6", "addr-gen-mode", "stable-privacy")
            config.set("ipv6", "dns-search", "")
            config.set("ipv6", "method", "auto")
            fp = io.StringIO()
            config.write(fp, space_around_delimiters=False)
            if self.ssh_execution.scp_put_file(
                fp,
                "%s/%s" %
                (self.ubuntu_client_conf_path,
                 self.client_dict["device_ssid"])):
                logger.info(
                    "[ID:%s IP:%s]Client SSID profile pushed successfully." %
                    (self.client_dict["device_name"], self.client_dict["device_lan_ip"]))
                _, _ = self.ssh_execution.execute_cmd(
                    "chmod 600 %s/*" %
                    (self.ubuntu_client_conf_path))
                _, _ = self.ssh_execution.execute_cmd(
                    "service network-manager restart")
                time.sleep(15)
                return 1
            else:
                self.status["status_info"] = "SCP Failed."
                self.status["status_code"] = 0
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                logger.info(
                    "[ID:%s IP:%s]Client SSID profile not able to transfer." %
                    (self.client_dict["device_name"], self.client_dict["device_lan_ip"]))
                return 0
        except Exception as e:
            logger.critical(
                "[ID:%s IP:%s]Not able to configure client with SSID profile."
                "Exception:%s" %
                (self.client_dict["device_name"], self.client_dict["device_lan_ip"], e))
            self.status["status_info"] = "Profile Push Failed."
            self.status["status_code"] = 0
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            return 0

    def ubuntu_client_is_associated(self, loop_count=6):
        """ This function will check client association.
            On successful association 1 will be returned and 0 on failure.
        """
        for loop in range(1, loop_count):
            out, _ = self.ssh_execution.execute_cmd(
                "/sbin/wpa_cli -i %s status | grep -w wpa_state\
                    | awk -F '=' '{print $2}'" %
                self.client_dict["device_wifi_interface"])
            bssid, _ = self.ssh_execution.execute_cmd(
                "/sbin/wpa_cli\
                    -i %s status | grep -w bssid | awk -F '=' '{print $2}'" %
                self.client_dict["device_wifi_interface"])
            bssid = bssid.rstrip().lstrip().upper()
            if out == "COMPLETED" and bssid != "":
                logger.info(
                    "[ID:%s IP:%s]Client got associated to SSID:%s" %
                    (self.client_dict["device_name"],
                     self.client_dict["device_lan_ip"],
                     self.client_dict["device_ssid"]))
                return 1
            else:
                logger.info(
                    "[ID:%s IP:%s]Client not yet associated to SSID:%s "
                    "will retry 5 times, before give it up." %
                    (self.client_dict["device_name"],
                     self.client_dict["device_lan_ip"],
                     self.client_dict["device_ssid"]))
                time.sleep(10)
                if loop == 3:
                    _, _ = self.ssh_execution.execute_cmd(
                        "nmcli connection up %s &" %
                        self.client_dict["device_ssid"])
                    logger.info(
                        "[ID:%s IP:%s]nmcli connection executed." %
                        (self.client_dict["device_name"],
                         self.client_dict["device_lan_ip"]))
        else:
            logger.info(
                "[ID:%s IP:%s]Client did not associate to SSID:%s after max attempts." %
                (self.client_dict["device_name"],
                 self.client_dict["device_lan_ip"],
                 self.client_dict["device_ssid"]))
            return 0

    def ubuntu_client_os_check(self):
        """ Verify client OS with Ubuntu and verify lsb is 16.04 or later.
            On success return 1 and on failure return 0.
        """
        out, _ = self.ssh_execution.execute_cmd(
            "lsb_release -d | awk -F \" \" \'{print $2}\'")
        if out != "Ubuntu":
            logger.info(
                "[ID:%s IP:%s]Client operation system does "
                "not seem to be Linux OS. Please check once. Error Code:%s" %
                (self.client_dict["device_name"], self.client_dict["device_lan_ip"], out))
            return 0
        cmd = "lsb_release -r | awk -F \" \" \'{print $2}\' | awk -F \".\" \'{print $1}\' | xargs"
        self.ubuntu_release, _ = self.ssh_execution.execute_cmd(cmd)
        if int(self.ubuntu_release) < 16:
            return 0
        logger.info(
            "[ID:%s IP:%s]Client operating system check passed.Distributor ID:%s"
            " Codename:%s" %
            (self.client_dict["device_name"],
             self.client_dict["device_lan_ip"],
             out,
             self.ubuntu_release))
        return 1

    def client_connect_start(self):
        """ This function will start client connection process.
        """
        self.status = {}
        self.client_dict["user"] = self.client_dict["device_ssh_user"]
        try:
            if not self.client_initial_check():
                self.status["status_info"] = self.client_dict["error"]
                self.status["status_code"] = 0
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                return self.status
            if not self.ubuntu_client_os_check():
                self.status["status_info"] = "OS Check Failure."
                self.status["status_code"] = 0
                self.status["bssid"] = "--"
                self.status["wifiip"] = "--"
                return self.status
            self.ubuntu_client_sanitize()
            if self.ubuntu_client_create_profile_connect():
                if self.ubuntu_client_is_associated():
                    self.ubuntu_client_status_update()
                    self.client_final_check()
                    return self.status
                else:
                    self.client_final_check()
                    self.status["status_info"] = "Profile pushed."
                    self.status["status_code"] = 1
                    self.status["bssid"] = "--"
                    self.status["wifiip"] = "--"
                    return self.status
            else:
                self.client_final_check()
                return self.status
        except Exception as e:
            logger.exception(
                "[ID:%s IP:%s]Exception while client connect %s." %
                (self.client_dict["device_name"], self.client_dict["device_lan_ip"], e))
            self.status["status_info"] = "Try again. Issue persist contact @tejaskumar.kasundra"
            self.status["status_code"] = 1
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            self.client_final_check()
            return self.status

    def client_disconnect_start(self):
        """ This function will start client disconnection process.
        """
        self.status = {}
        self.client_dict["user"] = self.client_dict["device_ssh_user"]
        if not self.client_initial_check():
            self.status["status_info"] = self.client_dict["error"]
            self.status["status_code"] = 1
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            return self.status
        if not self.ubuntu_client_os_check():
            self.status["status_info"] = "OS check failure."
            self.status["status_code"] = 1
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            return self.status
        self.ubuntu_client_sanitize()
        self.client_final_check()
        return self.status

    def ubuntu_client_property(self):
        """ Get MAC address of interface based on
            grep of hwaddr or ether.
        """
        self.mac, _ = self.ssh_execution.execute_cmd(
            "ifconfig %s | grep -i hwaddr |\
                    awk -F \" \" \'{print $5}\' | xargs" %
            self.client_dict["device_wifi_interface"])
        if self.mac == "":
            self.mac, _ = self.ssh_execution.execute_cmd(
                "ifconfig %s | grep -i ether |\
                awk -F \" \" \'{print $2}\' | xargs" %
                self.client_dict["device_wifi_interface"])
        return 1

    def ubuntu_client_status_update(self):
        """ This function will fetch client wifi details.
            BSSID, WiFiIP, WiFiMac will be fetched from clients.
        """
        for _ in range(5):
            state, _ = self.ssh_execution.execute_cmd(
                "/sbin/wpa_cli -i %s status | grep -w wpa_state\
                | awk -F '=' '{print $2}'" %
                self.client_dict["device_wifi_interface"])
            if state == "COMPLETED":
                break
            else:
                time.sleep(5)
        self.ubuntu_client_property()
        self.status["wifimac"] = self.mac
        self.status["wifimac"] = self.status["wifimac"].rstrip(
        ).lstrip().upper()
        if state == "COMPLETED":
            self.status["bssid"], _ = self.ssh_execution.execute_cmd(
                "/sbin/wpa_cli\
                -i %s status | grep -w bssid | awk -F '=' '{print $2}'" %
                self.client_dict["device_wifi_interface"])
            self.status["bssid"] = self.status["bssid"].rstrip(
            ).lstrip().upper()
            time.sleep(5)
            self.status["wifiip"], _ = self.ssh_execution.execute_cmd(
                "ifconfig %s \
                | grep -w inet |awk -F \" \" '{print $2}' | xargs" %
                self.client_dict["device_wifi_interface"])
            if re.search(r'addr:.*', self.status["wifiip"]):
                self.status["wifiip"] = self.status["wifiip"].split(":")[
                    1]
            if len(self.status["wifiip"].split(".")) != 4:
                self.status["wifiip"] = "--"
            logger.info(
                "[ID:%s IP:%s]Client BSSID:%s WiFi IP:%s WiFi_Mac:%s" %
                (self.client_dict["device_name"],
                    self.client_dict["device_lan_ip"],
                    self.status["bssid"],
                    self.status["wifiip"],
                    self.status["wifimac"]))
            self.status["status_info"] = "Connected"
            self.status["status_code"] = 1
            return 1
        else:
            self.status["bssid"] = "--"
            self.status["wifiip"] = "--"
            logger.info(
                "[ID:%s IP:%s]Client BSSID:%s WiFi IP:%s" %
                (self.client_dict["device_name"],
                    self.client_dict["device_lan_ip"],
                    self.status["bssid"],
                    self.status["wifiip"]))
            self.status["status_info"] = "Profile Pushed."
            self.status["status_code"] = 1
            return 1
