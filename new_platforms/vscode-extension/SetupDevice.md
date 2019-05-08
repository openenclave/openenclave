# Configure Azure IoT Edge Device

## Azure

### Required Azure Resources

Ensure that you have an instance of [Azure IoT Hub](https://ms.portal.azure.com/#create/hub) that you are able to manage devices for.

### Create Azure IoT Hub Edge device

1. Navigate to your Azure IoT Hub in the [Azure Portal](https://ms.portal.azure.com).
1. Click on `Automatic Device Management > IoT Edge`
1. Click on `Add an IoT Edge device`
1. Enter a unique Device ID and click `Save`
1. Click on the new device in the list of `IoT Edge devices`
1. Make note of the `Connection string` for use when you connect your actual device.

## Device

Once you have created an Azure IoT Hub Edge device, the next step is connecting that to a real device.  In broad strokes, this amounts to
putting the Azure IoT Edge runtime and agent on a device and connecting it to the Azure IoT Hub Edge device you creaed above.  Below are the 
steps for setting that up on an AArch64 or ARM32v7 device.

### AArch64

    Note: these instructions enable the ARM32v7 edge runtime on AArch64, so be sure to deploy ARM32v7 containers

Instructions can be found [here](https://devblogs.microsoft.com/iotdev/a-workaround-to-run-azure-iot-edge-on-arm64-devices/).

First, you'll need to download and install the Azure IoT Edge runtime and agent:

```bash
sudo apt-get update 
sudo apt-get install curl
sudo dpkg --add-architecture armhf
sudo apt-get update
sudo apt-get install libc-bin libc-bin libc-dev-bin libc6 libc6:armhf libc6-dev libgcc1 libgcc1:armhf locales
wget http://ports.ubuntu.com/ubuntu-ports/pool/main/h/hostname/hostname_3.16ubuntu2_armhf.deb
sudo dpkg -I ./hostname_3.16ubuntu2_armhf.deb

wget http://ftp.us.debian.org/debian/pool/main/o/openssl1.0/libssl1.0.2_1.0.2r-1~deb9u1_armhf.deb
sudo dpkg -i libssl1.0.2_1.0.2r-1~deb9u1_armhf.deb

sudo apt-get install -f

curl -L https://aka.ms/moby-engine-armhf-latest -o moby_engine.deb && sudo dpkg -i ./moby_engine.deb
curl -L https://aka.ms/moby-cli-armhf-latest -o moby_cli.deb && sudo dpkg -i ./moby_cli.deb
sudo apt-get install -f
curl -L https://aka.ms/libiothsm-std-linux-armhf-latest -o libiothsm-std.deb && sudo dpkg -i ./libiothsm-std.deb
curl -L https://aka.ms/iotedged-linux-armhf-latest -o iotedge.deb && sudo dpkg -i ./iotedge.deb
sudo apt-get install -f
curl -L https://aka.ms/libiothsm-std-linux-armhf-latest -o libiothsm-std.deb && sudo dpkg -i ./libiothsm-std.deb
curl -L https://aka.ms/iotedged-linux-armhf-latest -o iotedge.deb && sudo dpkg -i ./iotedge.deb
sudo apt-get install -f
```

After that, you need to add your `Connection string` to the Azure IoT Edge config file (look for **device_connection_string**):

```bash
sudo vi /etc/iotedge/config.yaml
```

Once this is done, you need to restart the Azure IoT Edge runtime:

```bash
sudo systemctl daemon-reload
sudo systemctl restart iotedge
```

### ARM32v7

Instructions can be found [here](https://docs.microsoft.com/en-us/azure/iot-edge/how-to-install-iot-edge-linux-arm):

First, you'll need to download and install the Azure IoT Edge runtime and agent:

```bash
curl -L https://aka.ms/moby-engine-armhf-latest -o moby_engine.deb && sudo dpkg -i ./moby_engine.deb
curl -L https://aka.ms/moby-cli-armhf-latest -o moby_cli.deb && sudo dpkg -i ./moby_cli.deb
sudo apt-get install -f

curl -L https://aka.ms/libiothsm-std-linux-armhf-latest -o libiothsm-std.deb && sudo dpkg -i ./libiothsm-std.deb
curl -L https://aka.ms/iotedged-linux-armhf-latest -o iotedge.deb && sudo dpkg -i ./iotedge.deb
sudo apt-get install -f
```

After that, you need to add your `Connection string` to the Azure IoT Edge config file (look for **device_connection_string**):

```bash
sudo vi /etc/iotedge/config.yaml
```

Once this is done, you need to restart the Azure IoT Edge runtime:

```bash
sudo systemctl daemon-reload
sudo systemctl restart iotedge
```
