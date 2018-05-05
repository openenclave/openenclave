[Index](index.md)

---
# OE_VerifyReport()

Verify the integrity of the report and its signature.

## Syntax

    OE_Result OE_VerifyReport(const uint8_t *report, uint32_t reportSize, OE_Report *parsedReport)
## Description 

This function verifies that the report signature is valid. If the report is local, it verifies that it is correctly signed by the enclave platform. If the report is remote, it verifies that the signing authority is rooted to a trusted authority such as the enclave platform manufacturer.



## Parameters

#### report

The buffer containing the report to verify.

#### reportSize

The size of the **report** buffer.

#### parsedReport

Optional **OE_Report** structure to populate with the report properties in a standard format.

## Return value

#### OE_OK

The report was successfully created.

#### OE_INVALID_PARAMETER

At least one parameter is invalid.

---
[Index](index.md)

