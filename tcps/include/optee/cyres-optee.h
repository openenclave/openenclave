/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef _OE_ENCLAVE_H
# include <openenclave/enclave.h>
#endif
#ifndef USE_OPTEE
# error cyres-optee.h should only be included with USE_OPTEE
#endif

Tcps_StatusCode 
ExportCyrepCertChain(
    Tcps_ConstStringA exportFilePath);

Tcps_StatusCode 
GetCyrepKey(
    char **keyPEM);

Tcps_Void
FreeCyrepKey(
    char *keyPEM);
