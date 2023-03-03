# WiFi Clients Management Remotely
Connect Different OS Clients Windows, Mac, Ubuntu, Raspberry Pi to WiFi Remotely

- It is a docker/container based, so to run this on any machine user can follow below simple steps.

Things to Rememeber - 
- Localhost port 8080 will be used for web server, if this port is already used by other things, we can change same into `docker-compose.yml` as per user need.

**Steps**
- Run CLI `docker-compose -f docker-compose.yml up -d --build`
- This will create two containers, namely
  1. nginx:latest
  2. wifi_device_management
- If both of above containers are running, then we should be able to access UI as below from our browser http://localhost:8080
- Once UI is opening user can move to FAQ section and understand prerequisite to work with different OS clients.
- Usage flow for Tools is as below,
  1. First Create SSID from `SSIDs` tab
  2. Add Client Details into `Devices` tab
  3. Once Client entry added from `Devices` tab, user can perform Connect/Disconnect to Client from UI itself.
 
 
![image](https://user-images.githubusercontent.com/45988670/222689393-9caf741b-a937-4fb4-99e5-929edeab8cc2.png)
