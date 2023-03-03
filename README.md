# wifi_device_management
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

