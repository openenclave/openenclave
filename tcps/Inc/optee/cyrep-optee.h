/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef TRUSTED_CODE
# error cyrep-optee.h should only be included with TRUSTED_CODE
#endif
#ifndef USE_OPTEE
# error cyrep-optee.h should only be included with USE_OPTEE
#endif

#include <tcps.h>

Tcps_StatusCode 
ExportCyrepCertChain(
    Tcps_ConstStringA exportFilePath);

Tcps_StatusCode 
GetCyrepKey(
    char **keyPEM);

Tcps_Void
FreeCyrepKey(
    char *keyPEM);
