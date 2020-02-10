# Configure Azure IoT Edge Device

## Azure

### Required Azure Resources

Ensure that you have an instance of [Azure IoT
Hub](https://ms.portal.azure.com/#create/hub) that you are able to manage
devices for.

### Create Azure IoT Hub Edge device

1. Navigate to your Azure IoT Hub in the [Azure
   Portal](https://ms.portal.azure.com).
1. Click on `Automatic Device Management > IoT Edge`
1. Click on `Add an IoT Edge device`
1. Enter a unique Device ID and click `Save`
1. Click on the new device in the list of `IoT Edge devices`
1. Make note of the `Connection string` for use when you connect your actual
   device.

## Device

Once you have created an Azure IoT Hub Edge device, the next step is connecting
that to a real device.  In broad strokes, this amounts to putting the Azure IoT
Edge runtime and agent on a device and connecting it to the Azure IoT Hub Edge
device you created above. To do so, refer to how to
[Install the Azure IoT Edge runtime on Debian-based Linux systems](https://docs.microsoft.com/en-us/azure/iot-edge/how-to-install-iot-edge-linux).
Follow the instructions marked for Ubuntu 18.04 Server.
