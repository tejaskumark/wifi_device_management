__author__ = "Tejaskumar Kasundra(tejaskumar.kasundra@gmail.com)"

import time
import json
import sqlite3
from pathlib import Path
from . import app
from flask import jsonify, render_template
from flask import request  # import main Flask class and request object
from src.client import MacClient, WindowsClient, RasPiClient, UbuntuClient
from src.mlogger import logger


dbFile = "/app/client.db"


@app.route("/about")
def about():
    time.sleep(20)
    return "WiFi Device Management Interface."


@app.route("/", methods=["GET"])
def index():
    try:
        return render_template("index.html")
    except Exception as e:
        logger.exception(e)


@app.route("/get/ssids", methods=["GET"])
def getssids():
    try:
        conn = sqlite3.connect(dbFile)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT rowid, * FROM ssids;")
        data = cur.fetchall()
    except Exception as e:
        logger.exception(e)
        return {'error': e}, 500
    r = [dict(row) for row in data]
    cur.close()
    return json.dumps(r)


@app.route("/add/ssid", methods=["POST"])
def addssid():
    content = request.json
    try:
        name = content["ssidname"]
        security = content["security"]
        password = content["passwordkey"]
        onexuser = content["onexuser"]
        onexpass = content["onexpass"]
    except KeyError as e:
        logger.exception(e)
        return {'error': 'Expected key value data not present.'}, 400
    try:
        conn = sqlite3.connect(dbFile)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""insert into ssids values (?, ?, ?, ?, ?)""",
                    (name, security, onexuser, onexpass, password))
        conn.commit()
        cur.close()
    except sqlite3.IntegrityError as e:
        logger.exception(e)
        return "SSID name already exist. Please enter unique name.", 500
    except Exception as e:
        return {'error': str(e)}, 500
    return "Success"


@app.route("/delete/ssid", methods=["DELETE"])
def deletessid():
    content = request.json
    try:
        rowid = content["id"]
        ssid_name = content["ssid_name"]
    except KeyError as e:
        logger.exception(e)
        return {'error': 'Expected key value data not present.'}, 400
    try:
        conn = sqlite3.connect(dbFile)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""delete from ssids where rowid=?""", (rowid,))
        cur.execute(
            """update clients set device_ssid=null, device_status=1 where device_ssid=?""",
            (ssid_name,
             ))
        conn.commit()
        cur.close()
    except Exception as e:
        logger.exception(e)
        return {"error": "Error during deleting values from db."}, 500
    return "Success"


@app.route("/edit/ssid", methods=["POST"])
def editssid():
    content = request.json
    try:
        rowid = content["id"]
        name = content["ssidname"]
        security = content["security"]
        password = content["passwordkey"]
        onexuser = content["onexuser"]
        onexpass = content["onexpass"]
    except KeyError as e:
        logger.exception(e)
        return {'error': 'Expected key value data not present.'}, 400
    try:
        conn = sqlite3.connect(dbFile)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """SELECT ssid_name FROM ssids where rowid=(?)""", (rowid,))
        data = cur.fetchone()
        old_ssid = data["ssid_name"]
        cur.execute(
            """update ssids set ssid_name=(?), security=(?), onex_user=(?), onex_pass=(?),
        passwordkey=(?) where rowid=(?)""",
            (name,
             security,
             onexuser,
             onexpass,
             password,
             rowid))
        cur.execute(
            """update clients set device_ssid=(?), device_status=1, device_info="--",
            device_wifi_ip="--", device_wifi_bssid="--" where device_ssid=(?)""",
            (name,
             old_ssid))
        conn.commit()
        cur.close()
    except sqlite3.IntegrityError as e:
        logger.exception(e)
        return "SSID name already exist. Please enter unique name.", 500
    except Exception as e:
        logger.exception(e)
        return {'error': 'Error during inserting values into DB.'}, 500
    return "Success"


@app.route("/add/client", methods=["POST"])
def addclient():
    content = request.json
    try:
        name = content["clientname"]
        clientos = content["clientos"]
        lanip = content["lanip"]
        sshuser = content["sshusername"]
        sshpass = content["sshpassword"]
        wifiint = content["wifiinterface"]
        clientssid = content["ssidname"]
        devicestatus = "1"
    except KeyError as e:
        logger.exception(e)
        return {'error': 'Expected key value data not present.'}, 400
    try:
        conn = sqlite3.connect(dbFile)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """insert into clients (device_name, device_lan_ip, device_ssid,
        device_wifi_interface, device_ssh_user, device_ssh_pass, device_os, device_status)
        values (?, ?, ?, ?, ?, ?, ?, ?)""",
            (name,
             lanip,
             clientssid,
             wifiint,
             sshuser,
             sshpass,
             clientos,
             devicestatus))
        conn.commit()
        cur.close()
    except sqlite3.IntegrityError as e:
        logger.exception(e)
        return "Client name already exist. Please enter unique name.", 400
    except Exception as e:
        logger.exception(e)
        return {'error': 'Error during inserting values into DB.'}, 500
    return "Success"


@app.route("/get/clients", methods=["GET"])
def getclients():
    try:
        conn = sqlite3.connect(dbFile)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT rowid, * FROM clients;")
        data = cur.fetchall()
    except Exception as e:
        logger.exception(e)
        return {'error': e}, 500
    r = [dict(row) for row in data]
    cur.close()
    return json.dumps(r)


@app.route("/delete/client", methods=["DELETE"])
def deleteclient():
    content = request.json
    try:
        rowid = content["id"]
    except KeyError as e:
        logger.exception(e)
        return {'error': 'Expected key value data not present.'}, 400
    try:
        conn = sqlite3.connect(dbFile)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""delete from clients where rowid=?""", (rowid,))
        conn.commit()
        cur.close()
    except Exception as e:
        logger.exception(e)
        return {"error": "Error during deleting values from db."}, 500
    return "Success"


@app.route("/get/client", methods=["GET"])
def getclient():
    try:
        rowid = request.args["id"].split("-")[1]
    except Exception as e:
        logger.exception(e)
        return {"error": "expected key \"id\" is missing from request url."}, 400
    try:
        conn = sqlite3.connect(dbFile)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""SELECT * FROM clients where rowid=?""", (rowid,))
        data = cur.fetchall()
    except Exception as e:
        logger.exception(e)
        return {"error": "internal server error."}, 500
    r = [dict(row) for row in data]
    cur.close()
    return json.dumps(r), 200, {
        "Content-Type": "application/json; charset=utf-8"}


@app.route("/edit/client", methods=["POST"])
def editclient():
    content = request.json
    try:
        rowid = content["id"].split("-")[1]
        device_name = content["device_name"]
        device_lan_ip = content["device_lan_ip"]
        device_ssid = content["device_ssid"]
        device_wifi_interface = content["device_wifi_interface"]
        device_ssh_user = content["device_ssh_user"]
        device_ssh_pass = content["device_ssh_pass"]
        device_os = content["device_os"]
    except KeyError as e:
        logger.exception(e)
        return {"error": "Expected key value data not present."}, 400
    except Exception as e:
        logger.exception(e)
        return {"error": "Something not working."}, 400
    try:
        conn = sqlite3.connect(dbFile)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """update clients set device_name=(?), device_lan_ip=(?), device_ssid=(?), device_os=(?),
        device_ssh_user=(?), device_ssh_pass=(?), device_wifi_interface=(?) where rowid=(?)""",
            (device_name,
             device_lan_ip,
             device_ssid,
             device_os,
             device_ssh_user,
             device_ssh_pass,
             device_wifi_interface,
             rowid))
        conn.commit()
        cur.close()
    except sqlite3.IntegrityError as e:
        logger.exception(e)
        return "Client name already exist. Please enter unique name.", 500
    except Exception as e:
        logger.exception(e)
        return {'error': 'Error during inserting values into DB.'}, 500
    return "Success"


@app.route("/connect/client", methods=["POST"])
def connectclient():
    content = request.json
    try:
        rowid = content["id"]
        device_ssid = content["ssid"]
    except KeyError as e:
        logger.exception(e)
        return {"error": "Expected key value data not present."}, 400
    try:
        conn = sqlite3.connect(dbFile)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""SELECT * FROM clients where rowid=?""", (rowid,))
        device_data = dict(cur.fetchone())
        if not device_data:
            return "Device missing. Try again.", 404
        if device_data["device_status"] in [2, 4]:
            status = {
                'status_info': 'Device is busy. Please try after sometime.',
                'status_code': 0,
                'bssid': "--",
                "wifiip": "--"}
            return json.dumps(status), 200, {
                "Content-Type": "application/json; charset=utf-8"}
        cur.execute(
            """SELECT * FROM ssids where ssid_name=?""", (device_ssid,))
        ssid_data = dict(cur.fetchone())
        if not ssid_data:
            return "SSID missing. Try again.", 404
        cur.execute(
            """update clients set device_status=(?), device_ssid=(?) where rowid=(?)""",
            ("2",
             device_ssid,
             rowid,
             ))
        conn.commit()
        device_data["device_status"] = 2
        device_data["security"] = ssid_data["security"]
        device_data["device_ssid"] = ssid_data["ssid_name"]
        device_data["psk"] = ssid_data["passwordkey"]
        device_data["onex_username"] = ssid_data["onex_user"]
        device_data["onex_password"] = ssid_data["onex_pass"]
        if device_data["device_os"] == "Mac":
            client = MacClient(device_data)
            res = client.client_connect_start()
        elif device_data["device_os"] == "Windows":
            client = WindowsClient(device_data)
            res = client.client_connect_start()
        elif device_data["device_os"] == "RasPi":
            client = RasPiClient(device_data)
            res = client.client_connect_start()
        elif device_data["device_os"] == "Ubuntu":
            client = UbuntuClient(device_data)
            res = client.client_connect_start()
        else:
            return "Client OS Not Supported.", 404
        if res["status_code"] == 1:
            cur.execute(
                """update clients set device_status=(?),
                device_info=(?), device_wifi_bssid=(?), device_wifi_ip=(?) where rowid=(?)""",
                ("3",
                 res["status_info"],
                 res["bssid"],
                 res["wifiip"],
                 rowid,
                 ))
            conn.commit()
        else:
            cur.execute(
                """update clients set device_status=(?), device_info=(?),
                device_wifi_bssid=(?), device_wifi_ip=(?) where rowid=(?)""",
                ("1",
                 res["status_info"],
                 res["bssid"],
                 res["wifiip"],
                 rowid,
                 ))
            conn.commit()
        if "wifimac" in res.keys():
            if device_data["device_wifi_mac"] is None or device_data["device_wifi_mac"] != res["wifimac"]:
                cur.execute(
                    """update clients set device_wifi_mac=(?) where rowid=(?)""",
                    (res["wifimac"],
                        rowid,
                     ))
                conn.commit()
        return json.dumps(res), 200, {
            "Content-Type": "application/json; charset=utf-8"}
    except Exception as e:
        logger.exception(e)
        return {"error": "internal server error."}, 500


@app.route("/disconnect/client", methods=["POST"])
def disconnectclient():
    content = request.json
    try:
        rowid = content["id"]
    except KeyError as e:
        logger.exception(e)
        return {"error": "Expected key value data not present."}, 400
    try:
        conn = sqlite3.connect(dbFile)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""SELECT * FROM clients where rowid=?""", (rowid,))
        device_data = dict(cur.fetchone())
        if not device_data:
            return "Client data missing.", 404
        if device_data["device_status"] in [2, 4]:
            status = {
                'status_info': 'Device is busy. Please try after sometime.',
                'status_code': 0,
                'bssid': "--",
                "wifiip": "--"}
            return json.dumps(status), 200, {
                "Content-Type": "application/json; charset=utf-8"}
        cur.execute(
            """update clients set device_status=(?) where rowid=(?)""",
            ("4",
             rowid,
             ))
        conn.commit()
        device_data["device_status"] = 4
        if device_data["device_os"] == "Mac":
            client = MacClient(device_data)
            res = client.client_disconnect_start()
        elif device_data["device_os"] == "Windows":
            client = WindowsClient(device_data)
            res = client.client_disconnect_start()
        elif device_data["device_os"] == "RasPi":
            client = RasPiClient(device_data)
            res = client.client_disconnect_start()
        elif device_data["device_os"] == "Ubuntu":
            client = UbuntuClient(device_data)
            res = client.client_disconnect_start()
        else:
            return "Client OS Not Supported.", 404
        cur.execute(
            """update clients set device_status=(?),
            device_info=(?), device_wifi_bssid=(?), device_wifi_ip=(?) where rowid=(?)""",
            ("1",
                res["status_info"],
                res["bssid"],
                res["wifiip"],
                rowid,
             ))
        conn.commit()
        return json.dumps(res), 200, {
            "Content-Type": "application/json; charset=utf-8"}
    except Exception as e:
        logger.exception(e)
        return {"error": "internal server error."}, 500
