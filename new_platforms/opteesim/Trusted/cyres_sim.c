/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
/* Licensed under the MIT Licence. */
#include <openenclave/enclave.h>
#include <pta_cyres.h>
#include <tee_api.h>

#include <riot_cyres.h>

/* Note that even though digest lengths are equivalent here, (and on most
 devices this will be the case) there is no requirement that DICE and RIoT
 use the same one-way function/digest length. */
#define DICE_DIGEST_LENGTH RIOT_DIGEST_LENGTH

/* Note also that there is no requirement on the UDS length for a device.
 A 256-bit UDS is recommended but this size may vary among devices. */
#define DICE_UDS_LENGTH 0x20

/* Estimate the buffer size needed, in bytes, for a TCPS ID. In our case
   we will not have more then two PUBKEYs and a FW measurement. */
#define CLAIM_BUFFER_LENGTH (TCPS_ID_PUBKEY_LENGTH * 2) + TCPS_ID_FWID_LENGTH

#define SIM_CERT_SIZE 500
#define DER_MAX_SIZE 300

#define CODE_AUTHORITY_SECRET "Authority Signer Secret"
#define CODE_AUTHORITY_SECRET_SIZE lblSize(CODE_AUTHORITY_SECRET)

/* Simulated Identity (one per app in the trust chain) */
typedef struct simulated_cyres_identity
{
    RIOT_ECC_PUBLIC pub;
    RIOT_ECC_PRIVATE priv;
    uint8_t fwid[DICE_DIGEST_LENGTH];
    size_t cert_size;
    uint8_t cert[SIM_CERT_SIZE];
} simulated_cyres_identity_t;

/* Simulated Identity Chain (one per device) */
typedef struct simulated_cyres_identity_chain
{
    uint8_t uds[DICE_DIGEST_LENGTH];
    simulated_cyres_identity_t root_id;
    simulated_cyres_identity_t ta_id;
} simulated_cyres_identity_chain_t;
simulated_cyres_identity_chain_t g_sic;

typedef enum cert_type
{
    ALIAS,
    DEVICE
} cert_type_t;

typedef void(build_cert_fp_t)(
    DERBuilderContext* der_ctx,
    simulated_cyres_identity_t* id,
    simulated_cyres_identity_t* signer,
    RIOT_ECC_PUBLIC* code_authority,
    RIOT_X509_TBS_DATA* tbs);

/* The static data fields that make up the "root" Cert */
RIOT_X509_TBS_DATA x509_root_tbs_data = {{0},
                                         "OE OP-TEE SIM Root",
                                         "SIM_TEST",
                                         "US",
                                         "170101000000Z",
                                         "370101000000Z",
                                         "OP-TEE SIM Root",
                                         "SIM_TEST",
                                         "US"};

/* The static data fields that make up the "Trusted App" Cert */
RIOT_X509_TBS_DATA x509_ta_tbs_data = {{0},
                                       "OE Trusted Application",
                                       "SIM_TEST",
                                       "US",
                                       "170101000000Z",
                                       "370101000000Z",
                                       "OETrusted Application",
                                       "SIM_TEST",
                                       "US"};

/* Generate a simulated identity key pair, derived from a mock FW measurement.
 */
static void gen_sim_id(
    const uint8_t* digest,
    size_t digest_size,
    simulated_cyres_identity_t* id)
{
    uint8_t dice_measurement[DICE_DIGEST_LENGTH] = {0};

    /* Simulate measurement of some code */
    TEE_GenerateRandom(dice_measurement, DICE_DIGEST_LENGTH);

    /* Derive code identity based on previous digest and the "measurement" */
    RiotCrypt_Hash2(
        id->fwid,
        DICE_DIGEST_LENGTH,
        digest,
        DICE_DIGEST_LENGTH,
        dice_measurement,
        DICE_DIGEST_LENGTH);

    /* Don't use identity directly */
    RiotCrypt_Hash(digest, RIOT_DIGEST_LENGTH, id->fwid, DICE_DIGEST_LENGTH);

    /* Derive ID key pair from identity hash */
    RIOT_STATUS riotStatus = RiotCrypt_DeriveEccKey(
        &id->pub,
        &id->priv,
        digest,
        RIOT_DIGEST_LENGTH,
        RIOT_LABEL_IDENTITY,
        lblSize(RIOT_LABEL_IDENTITY));
    oe_assert(riotStatus == RIOT_SUCCESS);
}

/* Construct and sign a device certificate */
static void build_device_cert(
    DERBuilderContext* der_ctx,
    simulated_cyres_identity_t* id,
    simulated_cyres_identity_t* signer,
    RIOT_ECC_PUBLIC* code_authority,
    RIOT_X509_TBS_DATA* tbs)
{
    /* Build the device identity */
    uint8_t device_id[CLAIM_BUFFER_LENGTH];
    uint32_t device_id_len = 0;
    uint8_t auth_buffer[65];
    uint32_t auth_size;

    RiotCrypt_ExportEccPub(code_authority, auth_buffer, &auth_size);
    RIOT_STATUS status = BuildDeviceClaim(
        &id->pub,
        auth_buffer,
        auth_size,
        NULL,
        0,
        device_id,
        CLAIM_BUFFER_LENGTH,
        &device_id_len);
    oe_assert(status == RIOT_SUCCESS);

    /* Create the device certificate */
    X509GetDeviceCertTBS(
        der_ctx, tbs, &id->pub, NULL, device_id, device_id_len, 1);

    /* Sign the Certificate's TBS region and create the final DER cert */
    RIOT_ECC_SIGNATURE tbs_sig = {0};
    RiotCrypt_Sign(&tbs_sig, der_ctx->Buffer, der_ctx->Position, &signer->priv);
    X509MakeAliasCert(der_ctx, &tbs_sig);
}

/* Construct and sign an alias certificate */
static void build_alias_cert(
    DERBuilderContext* der_ctx,
    simulated_cyres_identity_t* id,
    simulated_cyres_identity_t* signer,
    RIOT_ECC_PUBLIC* code_authority,
    RIOT_X509_TBS_DATA* tbs)
{
    /* Build the claim blob */
    uint8_t alias_claim[CLAIM_BUFFER_LENGTH];
    uint32_t alias_claim_len = 0;
    uint8_t auth_buffer[65];
    uint32_t auth_size;

    RiotCrypt_ExportEccPub(code_authority, auth_buffer, &auth_size);
    RIOT_STATUS status = BuildAliasClaim(
        auth_buffer,
        auth_size,
        id->fwid,
        sizeof(id->fwid),
        alias_claim,
        CLAIM_BUFFER_LENGTH,
        &alias_claim_len);
    oe_assert(status == RIOT_SUCCESS);

    /* Create the alias certificate */
    X509GetAliasCertTBS(
        der_ctx,
        tbs,
        &id->pub,
        &signer->pub,
        id->fwid,
        sizeof(id->fwid),
        alias_claim,
        alias_claim_len,
        0);

    /* Sign the Certificate's TBS region */
    RIOT_ECC_SIGNATURE tbs_sig = {0};
    RiotCrypt_Sign(&tbs_sig, der_ctx->Buffer, der_ctx->Position, &signer->priv);
    X509MakeAliasCert(der_ctx, &tbs_sig);
}

/* Generate a PEM encoded certificate of the type specified for an identity.
    The certificate will be issued by the provided signer identity. */
static void gen_cert(
    simulated_cyres_identity_t* id,
    simulated_cyres_identity_t* signer,
    RIOT_ECC_PUBLIC* code_authority,
    RIOT_X509_TBS_DATA* tbs,
    cert_type_t type)
{
    /* Derive a serial number for the certificate */
    uint8_t digest[DICE_DIGEST_LENGTH] = {0};
    RiotCrypt_Kdf(
        digest,
        sizeof(digest),
        (uint8_t*)&id->pub,
        sizeof(id->pub),
        NULL,
        0,
        (const uint8_t*)RIOT_LABEL_SERIAL,
        lblSize(RIOT_LABEL_SERIAL),
        sizeof(digest));
    digest[0] &= 0x7F; // Ensure that the serial number is positive
    digest[0] |= 0x01; // Ensure that there is no leading zero
    memcpy(tbs->SerialNum, digest, sizeof(tbs->SerialNum));

    build_cert_fp_t* cert_fp;
    switch (type)
    {
        case ALIAS:
            cert_fp = build_alias_cert;
            break;
        case DEVICE:
            cert_fp = build_device_cert;
            break;
    }

    DERBuilderContext der_ctx = {0};
    uint8_t der_buffer[DER_MAX_SIZE] = {0};
    DERInitContext(&der_ctx, der_buffer, DER_MAX_SIZE);

    cert_fp(&der_ctx, id, signer, code_authority, tbs);

    id->cert_size = sizeof(id->cert);
    oe_assert(DERtoPEM(&der_ctx, R_CERT_TYPE, id->cert, &id->cert_size) == 0);
}

/* Initialization of simulated identity */
static void init_sim()
{
    static int32_t init = 0;

    if (init)
        return;

    /* Start of simulated device identity chain creation */
    RIOT_ECC_PUBLIC auth_key_pub;
    RIOT_ECC_PRIVATE auth_key_pri;
    uint8_t digest[DICE_DIGEST_LENGTH] = {0};

    /* Generate the code authority. This simulates the authoritative signer of
     * each component in the chain */
    RiotCrypt_DeriveEccKey(
        &auth_key_pub,
        &auth_key_pri,
        (const uint8_t*)CODE_AUTHORITY_SECRET,
        CODE_AUTHORITY_SECRET_SIZE,
        (const uint8_t*)RIOT_LABEL_IDENTITY,
        lblSize(RIOT_LABEL_IDENTITY));

    TEE_GenerateRandom(g_sic.uds, DICE_UDS_LENGTH);

    /* Do not use UDS directly */
    RiotCrypt_Hash(digest, DICE_DIGEST_LENGTH, g_sic.uds, DICE_UDS_LENGTH);

    /* Generate a simulated root identity */
    gen_sim_id(digest, DICE_DIGEST_LENGTH, &g_sic.root_id);

    /* Self signed the root certificate*/
    gen_cert(
        &g_sic.root_id,
        &g_sic.root_id,
        &auth_key_pub,
        &x509_root_tbs_data,
        DEVICE);

    /* Generate the TA identity with the rolling digest */
    gen_sim_id(digest, DICE_DIGEST_LENGTH, &g_sic.ta_id);

    /* Issue a device certificate signed by the root */
    gen_cert(
        &g_sic.ta_id, &g_sic.root_id, &auth_key_pub, &x509_ta_tbs_data, ALIAS);

    init = 1;
}

/* Start of CYRES_PTA Handlers.
 * Improvement: Move things around a bit in the
 * actual PTA to improve simulation and reduce breaks from future changes */
static TEE_Result invoke_cyres_get_private_key(
    uint32_t paramTypes,
    TEE_Param params[TEE_NUM_PARAMS])
{
    uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if (exp_pt != paramTypes)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Construct a DER encoded buffer */
    DERBuilderContext der_builder;
    uint8_t derBuffer[DER_MAX_SIZE] = {0};
    DERInitContext(&der_builder, derBuffer, DER_MAX_SIZE);
    X509GetDEREccPub(&der_builder, g_sic.ta_id.pub);

    /* Convert to PEM, returning size if buffer is not sufficient */
    uint32_t length = params[0].memref.size;
    int res = DERtoPEM(
        &der_builder, R_ECC_PRIVATEKEY_TYPE, params[0].memref.buffer, &length);
    if (res != 0)
    {
        params[0].memref.size = length + 1;
        return TEE_ERROR_SHORT_BUFFER;
    }

    uint8_t* pem = params[0].memref.buffer;
    pem[length] = '\0';
    return TEE_SUCCESS;
}

static TEE_Result invoke_cyres_get_public_key(
    uint32_t paramTypes,
    TEE_Param params[TEE_NUM_PARAMS])
{
    uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if (exp_pt != paramTypes)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Construct a DER encoded buffer */
    DERBuilderContext der_builder;
    uint8_t derBuffer[DER_MAX_SIZE] = {0};
    DERInitContext(&der_builder, derBuffer, DER_MAX_SIZE);
    X509GetDEREcc(&der_builder, g_sic.ta_id.pub, g_sic.ta_id.priv);

    /* Convert to PEM, returning size if buffer is not sufficient */
    uint32_t length = params[0].memref.size;
    int res = DERtoPEM(
        &der_builder, R_PUBLICKEY_TYPE, params[0].memref.buffer, &length);
    if (res != 0)
    {
        params[0].memref.size = length + 1;
        return TEE_ERROR_SHORT_BUFFER;
    }

    uint8_t* pem = params[0].memref.buffer;
    pem[length] = '\0';
    return TEE_SUCCESS;
}

static TEE_Result invoke_cyres_get_cert_chain(
    uint32_t param_types,
    TEE_Param params[TEE_NUM_PARAMS])
{
    uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if (exp_pt != param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    size_t cur = g_sic.root_id.cert_size + g_sic.ta_id.cert_size + 1;
    if (params[0].memref.size < cur)
    {
        params[0].memref.size = cur;
        return TEE_ERROR_SHORT_BUFFER;
    }

    uint8_t* cert_bag = (uint8_t*)(params[0].memref.buffer);
    cur = 0;
    memcpy(&cert_bag[cur], g_sic.ta_id.cert, g_sic.ta_id.cert_size);
    cur += g_sic.ta_id.cert_size;

    memcpy(&cert_bag[cur], g_sic.root_id.cert, g_sic.root_id.cert_size);
    cur++;

    cert_bag[cur] = (uint8_t)'/0';

    return TEE_SUCCESS;
}

static TEE_Result invoke_cyres_get_seal_key(
    uint32_t param_types,
    TEE_Param params[TEE_NUM_PARAMS])
{
    uint32_t exp_pt;
    uint8_t digest[DICE_DIGEST_LENGTH] = {0};

    exp_pt = TEE_PARAM_TYPE_GET(param_types, 0);
    if (exp_pt != TEE_PARAM_TYPE_MEMREF_OUTPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    exp_pt = TEE_PARAM_TYPE_GET(param_types, 1);
    if (exp_pt != TEE_PARAM_TYPE_NONE && exp_pt != TEE_PARAM_TYPE_MEMREF_INPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Do not use the key directly */
    RiotCrypt_Hash(
        digest,
        DICE_DIGEST_LENGTH,
        &g_sic.ta_id.priv,
        sizeof(g_sic.ta_id.priv));

    RIOT_STATUS status = RiotCrypt_Kdf(
        params[0].memref.buffer,
        params[0].memref.size,
        digest,
        DICE_DIGEST_LENGTH,
        params[1].memref.buffer,
        params[1].memref.size,
        "PTA_SEAL_KDF",
        lblSize("PTA_SEAL_KDF"),
        params[1].memref.size);
    if (status != RIOT_SUCCESS)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}

/* Main mock handler for CyResPTA commands */
TEE_Result invoke_cyres_pta(
    uint32_t commandID,
    uint32_t param_types,
    TEE_Param params[TEE_NUM_PARAMS])
{
    init_sim();

    switch (commandID)
    {
        case PTA_CYRES_GET_PRIVATE_KEY:
            return invoke_cyres_get_private_key(param_types, params);
        case PTA_CYRES_GET_PUBLIC_KEY:
            return invoke_cyres_get_public_key(param_types, params);
        case PTA_CYRES_GET_CERT_CHAIN:
            return invoke_cyres_get_cert_chain(param_types, params);
        case PTA_CYRES_GET_SEAL_KEY:
            return invoke_cyres_get_seal_key(param_types, params);

        default:
            return TEE_ERROR_NOT_IMPLEMENTED;
    }
}