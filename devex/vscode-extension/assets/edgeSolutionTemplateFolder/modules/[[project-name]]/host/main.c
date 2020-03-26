// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <openenclave/host.h>

#include <azure_c_shared_utility/crt_abstractions.h>
#include <azure_c_shared_utility/platform.h>
#include <azure_c_shared_utility/shared_util_options.h>
#include <azure_c_shared_utility/threadapi.h>
#include <iothub.h>
#include <iothub_client_options.h>
#include <iothub_message.h>
#include <iothub_module_client_ll.h>
#include <iothubtransportmqtt.h>

#include "host.h"

// Set to true to enable tracing.
bool g_traceOn = false;

// Message counter.
size_t g_messagesReceivedByInput1Queue = 0;

typedef struct MESSAGE_INSTANCE_TAG
{
    IOTHUB_MESSAGE_HANDLE messageHandle;

    // For tracking the messages within the user callback.
    size_t messageTrackingId;
} MESSAGE_INSTANCE;

// SendConfirmationCallback is invoked when the message that was forwarded on
// from 'InputQueue1Callback' pipeline function is confirmed.
static void SendConfirmationCallback(
    IOTHUB_CLIENT_CONFIRMATION_RESULT result,
    void* userContextCallback)
{
    // The context corresponds to which message# we were at when we sent.
    MESSAGE_INSTANCE* messageInstance = (MESSAGE_INSTANCE*)userContextCallback;

    printf(
        "Confirmation[%zu] received for message with result = %d.\n",
        messageInstance->messageTrackingId,
        result);

    IoTHubMessage_Destroy(messageInstance->messageHandle);
    free(messageInstance);
}

// Allocates a context for callback and clones the message.
//
// NOTE: The message MUST be cloned at this stage. InputQueue1Callback's caller
// always frees the message so we need to pass down a new copy.
static MESSAGE_INSTANCE* CreateMessageInstance(char* messageBody)
{
    MESSAGE_INSTANCE* messageInstance =
        (MESSAGE_INSTANCE*)malloc(sizeof(MESSAGE_INSTANCE));
    if (NULL == messageInstance)
    {
        fprintf(
            stderr,
            "Failed to allocate 'MESSAGE_INSTANCE' for pipelined message.\n");
    }
    else
    {
        memset(messageInstance, 0, sizeof(*messageInstance));

        if ((messageInstance->messageHandle =
                 IoTHubMessage_CreateFromString(messageBody)) == NULL)
        {
            free(messageInstance);
            messageInstance = NULL;
        }
        else
        {
            IoTHubMessage_SetContentTypeSystemProperty(
                messageInstance->messageHandle, "application%2fjson");
            IoTHubMessage_SetContentEncodingSystemProperty(
                messageInstance->messageHandle, "utf-8");

            messageInstance->messageTrackingId =
                g_messagesReceivedByInput1Queue;
        }
    }

    return messageInstance;
}

static IOTHUBMESSAGE_DISPOSITION_RESULT SendEnclaveResponse(
    IOTHUB_MODULE_CLIENT_LL_HANDLE iotHubModuleClientHandle,
    char* messageBodyStr)
{
    IOTHUBMESSAGE_DISPOSITION_RESULT result;
    IOTHUB_CLIENT_RESULT clientResult;

    char* enclaveMessage = (char*)malloc(ENCLAVE_MESSAGE_SIZE * sizeof(char));
    if (NULL == enclaveMessage)
    {
        fprintf(stderr, "Failed to allocate enclave message.\n");
        result = IOTHUBMESSAGE_ABANDONED;
    }
    else
    {
        int enclaveResult =
            call_enclave(messageBodyStr, enclaveMessage, ENCLAVE_MESSAGE_SIZE);
        if (enclaveResult != 0)
        {
            result = IOTHUBMESSAGE_ABANDONED;
        }
        else
        {
            // This message should be sent to next stop in the pipeline, namely
            // "output1".  What happens at "outpu1" is determined by the
            // configuration of the Edge routing table setup.
            MESSAGE_INSTANCE* messageInstance =
                CreateMessageInstance(enclaveMessage);
            if (NULL == messageInstance)
            {
                result = IOTHUBMESSAGE_ABANDONED;
            }
            else
            {
                printf(
                    "Sending message (%zu) to the next stage in pipeline.\n",
                    g_messagesReceivedByInput1Queue);

                clientResult = IoTHubModuleClient_LL_SendEventToOutputAsync(
                    iotHubModuleClientHandle,
                    messageInstance->messageHandle,
                    "output1",
                    SendConfirmationCallback,
                    (void*)messageInstance);
                if (clientResult != IOTHUB_CLIENT_OK)
                {
                    IoTHubMessage_Destroy(messageInstance->messageHandle);
                    free(messageInstance);

                    fprintf(
                        stderr,
                        "IoTHubModuleClient_LL_SendEventToOutputAsync failed "
                        "on sending msg#=%zu, err=%d.\n",
                        g_messagesReceivedByInput1Queue,
                        clientResult);

                    result = IOTHUBMESSAGE_ABANDONED;
                }
                else
                {
                    // The message instance's message handle and messageInstance
                    // itself are destroyed and freed, respectively, in
                    // SendConfirmationCallback once the message is sent, or if
                    // it fails to send.
                    result = IOTHUBMESSAGE_ACCEPTED;
                }
            }
        }

        free(enclaveMessage);
    }

    return result;
}

static IOTHUBMESSAGE_DISPOSITION_RESULT InputQueue1Callback(
    IOTHUB_MESSAGE_HANDLE message,
    void* userContextCallback)
{
    IOTHUBMESSAGE_DISPOSITION_RESULT result;
    IOTHUB_MODULE_CLIENT_LL_HANDLE iotHubModuleClientHandle =
        (IOTHUB_MODULE_CLIENT_LL_HANDLE)userContextCallback;

    const unsigned char* messageBody;
    size_t contentSize;

    if (IoTHubMessage_GetByteArray(message, &messageBody, &contentSize) !=
        IOTHUB_MESSAGE_OK)
    {
        messageBody = "<null>";
    }

    char* messageBodyStr = (char*)malloc(contentSize + 1);
    if (NULL == messageBodyStr)
    {
        fprintf(stderr, "Failed to allocate message body string.\n");
        result = IOTHUBMESSAGE_ABANDONED;
    }
    else
    {
        memcpy(messageBodyStr, messageBody, contentSize);
        messageBodyStr[contentSize] = '\0';

        printf(
            "Received Message [%zu]\n Data: [%s].\n",
            g_messagesReceivedByInput1Queue,
            messageBodyStr);

        result = SendEnclaveResponse(iotHubModuleClientHandle, messageBodyStr);

        free(messageBodyStr);
        g_messagesReceivedByInput1Queue++;
    }

    return result;
}

static IOTHUB_MODULE_CLIENT_LL_HANDLE InitializeConnection()
{
    IOTHUB_MODULE_CLIENT_LL_HANDLE iotHubModuleClientHandle;

    if (IoTHub_Init() != 0)
    {
        fprintf(stderr, "Failed to initialize the platform.\n");
        iotHubModuleClientHandle = NULL;
    }
    else if (
        (iotHubModuleClientHandle = IoTHubModuleClient_LL_CreateFromEnvironment(
             MQTT_Protocol)) == NULL)
    {
        fprintf(
            stderr,
            "Failed to create IoT Hub module client from environment.\n");
    }
    else
    {
        IoTHubModuleClient_LL_SetOption(
            iotHubModuleClientHandle, OPTION_LOG_TRACE, &g_traceOn);
    }

    return iotHubModuleClientHandle;
}

static void DeInitializeConnection(
    IOTHUB_MODULE_CLIENT_LL_HANDLE iotHubModuleClientHandle)
{
    if (iotHubModuleClientHandle != NULL)
    {
        IoTHubModuleClient_LL_Destroy(iotHubModuleClientHandle);
    }
    IoTHub_Deinit();
}

static int SetupCallbacksForModule(
    IOTHUB_MODULE_CLIENT_LL_HANDLE iotHubModuleClientHandle)
{
    int ret;

    if (IoTHubModuleClient_LL_SetInputMessageCallback(
            iotHubModuleClientHandle,
            "input1",
            InputQueue1Callback,
            (void*)iotHubModuleClientHandle) != IOTHUB_CLIENT_OK)
    {
        fprintf(stderr, "Failed to set input message callback.\n");
        ret = -1;
    }
    else
    {
        ret = 0;
    }

    return ret;
}

static void SendEnclaveMessage(
    IOTHUB_MODULE_CLIENT_LL_HANDLE iotHubModuleClientHandle)
{
    static int iterationCount = 0;

    if (iterationCount++ == 50)
    {
        SendEnclaveResponse(iotHubModuleClientHandle, "\"I'm still here...\"");
        iterationCount = 0;
    }
}

void iothub_module()
{
    IOTHUB_MODULE_CLIENT_LL_HANDLE iotHubModuleClientHandle;

    srand((unsigned int)time(NULL));

    if ((iotHubModuleClientHandle = InitializeConnection()) != NULL &&
        SetupCallbacksForModule(iotHubModuleClientHandle) == 0)
    {
        // The receiver just loops constantly waiting for messages.
        printf("Waiting for incoming messages.\n");
        while (true)
        {
            IoTHubModuleClient_LL_DoWork(iotHubModuleClientHandle);

            SendEnclaveMessage(iotHubModuleClientHandle);
            ThreadAPI_Sleep(100);
        }
    }

    DeInitializeConnection(iotHubModuleClientHandle);
}

int main(int argc, const char* argv[])
{
    oe_result_t result = OE_OK;

    result = create_enclave(argc, argv);
    if (result != OE_OK)
    {
        return result;
    }

    iothub_module();

    result = terminate_enclave();

    return result;
}
