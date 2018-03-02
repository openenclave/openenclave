#include "strings.h"

Pair strings[] = {
    {0, "AEP"},
    {0, "BuildEnclave"},
    {0, "CalculateSegmentsSize"},
    {0, "CallEnclave"},
    {0, "CheckPostConstraints"},
    {0, "CheckPreConstraints"},
    {0, "CheckStruct"},
    {0, "ClearArg"},
    {0, "ClearArgByName"},
    {0, "CloneStruct"},
    {0, "CombineSegments"},
    {0, "CondBroadcast"},
    {0, "CondDestroy"},
    {0, "CondInit"},
    {0, "CondSignal"},
    {0, "CondWait"},
    {0, "CopyStruct"},
    {0, "CreateEnclave"},
    {0, "DestroyStruct"},
    {0, "DispatchOCall"},
    {0, "ECall"},
    {0, "Enter"},
    {0, "EnterSim"},
    {0, "FileExists"},
    {0, "FreeStruct"},
    {0, "GetCreateFlags"},
    {0, "GetGSRegisterBase"},
    {0, "GetQuote"},
    {0, "HexDump"},
    {0, "InitArg"},
    {0, "LoadFile"},
    {0, "LoadPages"},
    {0, "LoadSegments"},
    {0, "MutexDestroy"},
    {0, "MutexInit"},
    {0, "MutexLock"},
    {0, "MutexTryLock"},
    {0, "MutexUnlock"},
    {0, "Once"},
    {0, "OpenSGXDriver"},
    {0, "OpenSGXMeasurer"},
    {0, "PadStruct"},
    {0, "PrintStruct"},
    {0, "PutErr"},
    {0, "RegisterOCall"},
    {0, "ResultStr"},
    {0, "SetArg"},
    {0, "SetArgByName"},
    {0, "SetGSRegisterBase"},
    {0, "SetProgramName"},
    {0, "SHA256Final"},
    {0, "SHA256Init"},
    {0, "SHA256StrOf"},
    {0, "SHA256StrOfContext"},
    {0, "SHA256ToStr"},
    {0, "SHA256Update"},
    {0, "SHA256UpdateZeros"},
    {0, "SpinDestroy"},
    {0, "SpinInit"},
    {0, "SpinLock"},
    {0, "SpinUnlock"},
    {0, "StructEq"},
    {0, "StructFindField"},
    {0, "TerminateEnclave"},
    {0, "TestStructPadding"},
    {0, "ThreadEqual"},
    {0, "ThreadGetSpecific"},
    {0, "ThreadKeyCreate"},
    {0, "ThreadKeyDelete"},
    {0, "ThreadSelf"},
    {0, "ThreadSetSpecific"},
    {0, NULL},
};

long nstrings = sizeof(strings) / sizeof(strings[0]) - 1;
