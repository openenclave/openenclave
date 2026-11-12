// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>

#include "../../../common/sgx/collateral.h"
#include "plugin_t.h"

#define COLLATERAL_FIELDS 7

static bool _active;
static bool _retry;
static size_t _field;
static size_t _calls;
static size_t _initial_capacities[COLLATERAL_FIELDS];
static size_t _capacities[COLLATERAL_FIELDS];

oe_result_t __real_oe_get_quote_verification_collateral_with_baseline_ocall(
    oe_result_t* retval,
    uint8_t fmspc[6],
    uint8_t collateral_provider,
    void* baseline,
    size_t baseline_size,
    void* tcb_info,
    size_t tcb_info_size,
    size_t* tcb_info_size_out,
    void* tcb_info_issuer_chain,
    size_t tcb_info_issuer_chain_size,
    size_t* tcb_info_issuer_chain_size_out,
    void* pck_crl,
    size_t pck_crl_size,
    size_t* pck_crl_size_out,
    void* root_ca_crl,
    size_t root_ca_crl_size,
    size_t* root_ca_crl_size_out,
    void* pck_crl_issuer_chain,
    size_t pck_crl_issuer_chain_size,
    size_t* pck_crl_issuer_chain_size_out,
    void* qe_identity,
    size_t qe_identity_size,
    size_t* qe_identity_size_out,
    void* qe_identity_issuer_chain,
    size_t qe_identity_issuer_chain_size,
    size_t* qe_identity_issuer_chain_size_out);

oe_result_t __wrap_oe_get_quote_verification_collateral_with_baseline_ocall(
    oe_result_t* retval,
    uint8_t fmspc[6],
    uint8_t collateral_provider,
    void* baseline,
    size_t baseline_size,
    void* tcb_info,
    size_t tcb_info_size,
    size_t* tcb_info_size_out,
    void* tcb_info_issuer_chain,
    size_t tcb_info_issuer_chain_size,
    size_t* tcb_info_issuer_chain_size_out,
    void* pck_crl,
    size_t pck_crl_size,
    size_t* pck_crl_size_out,
    void* root_ca_crl,
    size_t root_ca_crl_size,
    size_t* root_ca_crl_size_out,
    void* pck_crl_issuer_chain,
    size_t pck_crl_issuer_chain_size,
    size_t* pck_crl_issuer_chain_size_out,
    void* qe_identity,
    size_t qe_identity_size,
    size_t* qe_identity_size_out,
    void* qe_identity_issuer_chain,
    size_t qe_identity_issuer_chain_size,
    size_t* qe_identity_issuer_chain_size_out);

oe_result_t __wrap_oe_get_quote_verification_collateral_with_baseline_ocall(
    oe_result_t* retval,
    uint8_t fmspc[6],
    uint8_t collateral_provider,
    void* baseline,
    size_t baseline_size,
    void* tcb_info,
    size_t tcb_info_size,
    size_t* tcb_info_size_out,
    void* tcb_info_issuer_chain,
    size_t tcb_info_issuer_chain_size,
    size_t* tcb_info_issuer_chain_size_out,
    void* pck_crl,
    size_t pck_crl_size,
    size_t* pck_crl_size_out,
    void* root_ca_crl,
    size_t root_ca_crl_size,
    size_t* root_ca_crl_size_out,
    void* pck_crl_issuer_chain,
    size_t pck_crl_issuer_chain_size,
    size_t* pck_crl_issuer_chain_size_out,
    void* qe_identity,
    size_t qe_identity_size,
    size_t* qe_identity_size_out,
    void* qe_identity_issuer_chain,
    size_t qe_identity_issuer_chain_size,
    size_t* qe_identity_issuer_chain_size_out)
{
    if (!_active)
        return __real_oe_get_quote_verification_collateral_with_baseline_ocall(
            retval,
            fmspc,
            collateral_provider,
            baseline,
            baseline_size,
            tcb_info,
            tcb_info_size,
            tcb_info_size_out,
            tcb_info_issuer_chain,
            tcb_info_issuer_chain_size,
            tcb_info_issuer_chain_size_out,
            pck_crl,
            pck_crl_size,
            pck_crl_size_out,
            root_ca_crl,
            root_ca_crl_size,
            root_ca_crl_size_out,
            pck_crl_issuer_chain,
            pck_crl_issuer_chain_size,
            pck_crl_issuer_chain_size_out,
            qe_identity,
            qe_identity_size,
            qe_identity_size_out,
            qe_identity_issuer_chain,
            qe_identity_issuer_chain_size,
            qe_identity_issuer_chain_size_out);

    const size_t capacities[COLLATERAL_FIELDS] = {
        tcb_info_size,
        tcb_info_issuer_chain_size,
        pck_crl_size,
        root_ca_crl_size,
        pck_crl_issuer_chain_size,
        qe_identity_size,
        qe_identity_issuer_chain_size};
    size_t* sizes[COLLATERAL_FIELDS] = {
        tcb_info_size_out,
        tcb_info_issuer_chain_size_out,
        pck_crl_size_out,
        root_ca_crl_size_out,
        pck_crl_issuer_chain_size_out,
        qe_identity_size_out,
        qe_identity_issuer_chain_size_out};

    ++_calls;
    OE_TEST(_calls <= (_retry ? 2 : 1));
    for (size_t i = 0; i < COLLATERAL_FIELDS; ++i)
    {
        OE_TEST(capacities[i] > 0);
        if (_calls == 1)
        {
            if (!_initial_capacities[i])
                _initial_capacities[i] = capacities[i];
            OE_TEST(capacities[i] == _initial_capacities[i]);
        }
        else
            OE_TEST(capacities[i] == _capacities[i] + 16);
        _capacities[i] = capacities[i];
        *sizes[i] = capacities[i];
    }

    // Model hostile scalar returns without writing beyond any buffer.
    if (_retry && _calls == 1)
    {
        for (size_t i = 0; i < COLLATERAL_FIELDS; ++i)
            *sizes[i] += 16;
        *retval = OE_BUFFER_TOO_SMALL;
    }
    else
    {
        if (_field < COLLATERAL_FIELDS)
            ++*sizes[_field];
        *retval = OE_OK;
    }
    return OE_OK;
}

void test_collateral_sizes()
{
    printf("====== running test_collateral_sizes\n");
    _active = true;
    for (size_t retry = 0; retry < 2; ++retry)
    {
        _retry = retry != 0;
        for (_field = 0; _field <= COLLATERAL_FIELDS; ++_field)
        {
            oe_get_sgx_quote_verification_collateral_args_t args = {0};
            const oe_get_sgx_quote_verification_collateral_args_t before = args;
            _calls = 0;
            oe_result_t result =
                oe_get_sgx_quote_verification_collateral(&args);
            OE_TEST(_calls == (_retry ? 2 : 1));
            if (_field < COLLATERAL_FIELDS)
            {
                OE_TEST(result == OE_UNEXPECTED);
                OE_TEST(memcmp(&args, &before, sizeof(args)) == 0);
            }
            else
            {
                OE_TEST(result == OE_OK);
                OE_TEST(args.tcb_info_size == _capacities[0]);
                OE_TEST(args.tcb_info_issuer_chain_size == _capacities[1]);
                OE_TEST(args.pck_crl_size == _capacities[2]);
                OE_TEST(args.root_ca_crl_size == _capacities[3]);
                OE_TEST(args.pck_crl_issuer_chain_size == _capacities[4]);
                OE_TEST(args.qe_identity_size == _capacities[5]);
                OE_TEST(args.qe_identity_issuer_chain_size == _capacities[6]);
                oe_free_sgx_quote_verification_collateral_args(&args);
            }
        }
    }
    _active = false;
    printf("====== collateral sizes: 14 rejections and 2 controls passed\n");
}
