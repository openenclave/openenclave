// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oe_err.h"

#if defined(WIN32)
#define HAS_ENGINE_SUPPORT 0
#else
#define HAS_ENGINE_SUPPORT 1
#endif

int oedump(const char*);
#ifdef OE_WITH_EXPERIMENTAL_EEID
int oedump_eeid(const char* enclave);
#endif
int oesign(
    const char* enclave,
    const char* conffile,
    const char* keyfile,
    const char* digest_signature,
    const char* x509,
    const char* engine_id,
    const char* engine_load_path,
    const char* key_id);
int oedigest(
    const char* enclave,
    const char* conffile,
    const char* digest_file);

static const char _usage_gen[] =
    "Usage: %s <command> [options]\n"
    "\n"
    "Commands:\n"
    "  sign  -  Sign the specified enclave.\n"
    "  digest - Create a digest of the specified enclave for signing.\n"
    "  dump  -  Print out the Open Enclave metadata for the specified "
    "enclave.\n"
    "\n"
    "For help with a specific command, enter \"%s <command> --help\"\n";

static const char _usage_sign[] =
    "Usage: %s sign -e ENCLAVE_IMAGE [-c CONFIG_FILE] [SIGN_OPTIONS...]\n"
    "\n"
    "Options:\n"
    "  -e, --enclave-image      path of an enclave image file.\n"
    "  -c, --config-file        [optional] configuration file specifying\n"
    "                           the enclave properties.\n"
    "\n"
    "[SIGN_OPTIONS] can be one of the following sets of options:\n"
    "  -k, --key-file           path to a private key file in PEM\n"
    "                           format to sign enclave image with.\n"
    "\n"
    "  OR\n"
    "\n"
    "  -x, --x509               path to the PEM-encoded x509 public key\n"
    "                           certificate used to sign the digest file.\n"
    "  -d, --digest-file        path to the signed digest file matching the\n"
    "                           enclave image and specified configuration.\n"
#if HAS_ENGINE_SUPPORT
    "\n"
    "  OR\n"
    "\n"
    "  -n, --engine             name of the crypto engine to use, for example\n"
    "                           \"pkcs-11\".\n"
    "  -i, --key-id             engine-specific ID string specifying the\n"
    "                           desired enclave signing key from the engine.\n"
    "  -p, --load-path          [optional] absolute path to the shared object\n"
    "                           that implements the engine.\n"
#endif
    "\n"
    "Description:\n"
    "  This option (1) injects runtime properties into an enclave image\n"
    "  and (2) digitally signs that image.\n"
    "\n"
    "  The properties are read from the CONFIG_FILE. They override any\n"
    "  properties that were already defined inside the enclave image\n"
    "  through the use of the OE_SET_ENCLAVE_SGX macro. These properties\n"
    "  include:\n"
    "\n"
    "    Debug - whether enclave debug mode should be enabled (1) or not "
    "(0)\n"
    "    ProductID - the product identified number\n"
    "    SecurityVersion - the security version number\n"
    "    NumHeapPages - the number of heap pages for this enclave\n"
    "    NumStackPages - the number of stack pages for this enclave\n"
    "    NumTCS - the number of thread control structures for this "
    "enclave\n"
    "\n"
    "  The configuration file contains simple NAME=VALUE entries. For "
    "example:\n"
    "\n"
    "    Debug=1\n"
    "    NumHeapPages=1024\n"
    "\n"
    "  If specified, the key read from KEY_FILE and contains a private RSA "
    "key in PEM\n"
    "  format. The keyfile must contain the following header:\n"
    "\n"
    "    -----BEGIN RSA PRIVATE KEY-----\n"
    "\n"
    "  The resulting image is written to ENCLAVE_IMAGE.signed\n"
    "\n";

static const char _usage_digest[] =
    "Usage: %s digest -e ENCLAVE_IMAGE [-c CONFIG_FILE] -d DIGEST_FILE\n"
    "\n"
    "Options:\n"
    "  -e, --enclave-image      path of an enclave image file.\n"
    "  -c, --config-file        [optional] configuration file specifying\n"
    "                           the enclave properties.\n"
    "  -d, --digest-file        path to output the digest file.\n"
    "\n"
    "Description:\n"
    "  This option generates the digest for the enclave signature that can\n"
    "  be independently signed by a separate code signing authority. The\n"
    "  resulting signed digest can then be used to create the embedded\n"
    "  enclave signature with the oesign `sign` command, without requiring\n"
    "  that the private code signing key be made available to the environment\n"
    "  running oesign.\n"
    "\n"
    "  The properties to be used for generating the signature digest are read\n"
    "  from the CONFIG_FILE, if specified. They override any properties that\n"
    "  were already defined in the ENCLAVE_IMAGE by the OE_SET_ENCLAVE_SGX\n"
    "  macro. For a list of the enclave properties, run `oesign sign --help`.\n"
    "\n"
    "  The resulting digest value is written to the specified DIGEST_FILE in\n"
    "  raw binary form.\n"
    "\n";

static const char _usage_dump[] =
    "Usage: %s dump -e ENCLAVE_IMAGE\n"
    "\n"
    "Options:\n"
    "  -e, --enclave-image      path of an enclave image file.\n"
    "\n"
    "Description:\n"
    "  This option dumps the .oeinfo data segment and the embedded "
    "signature information for the specified enclave.\n"
    "\n";

int dump_parser(int argc, const char* argv[])
{
    int ret = 0;
    const char* enclave = NULL;

    const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"enclave-image", required_argument, NULL, 'e'},
        {NULL, 0, NULL, 0},
    };
    const char short_options[] = "he:";

    int c;
    do
    {
        c = getopt_long(
            argc, (char* const*)argv, short_options, long_options, NULL);
        if (c == -1)
        {
            // all the command-line options are parsed
            break;
        }

        switch (c)
        {
            case 'h':
                fprintf(stderr, _usage_dump, argv[0]);
                goto done;
            case 'e':
                enclave = optarg;
                break;
            case ':':
                // Missing option argument
                ret = 1;
                goto done;
            case '?':
            default:
                // Invalid option
                ret = 1;
                goto done;
        }
    } while (1);

    if (enclave == NULL)
    {
        oe_err("--enclave-image option is missing");
        ret = 1;
    }

    if (!ret)
    {
        /* dump oeinfo and signature information */
        ret = oedump(enclave);
    }

done:

    return ret;
}

#ifdef OE_WITH_EXPERIMENTAL_EEID
static const char _usage_dump_eeid[] =
    "Usage: %s dump-eeid -e ENCLAVE_IMAGE\n"
    "\n"
    "Options:\n"
    "  -e, --enclave-image      path of an enclave image file.\n"
    "\n"
    "Description:\n"
    "  This option dumps the .oeinfo data segment and the embedded signature "
    "information for the specified enclave and the extended enclave "
    "initialization data (EEID).\n"
    "\n";

int dump_eeid_parser(int argc, const char* argv[])
{
    int ret = 0;
    const char* enclave = NULL;

    const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"enclave-image", required_argument, NULL, 'e'},
        {NULL, 0, NULL, 0},
    };
    const char short_options[] = "he:";

    int c;
    do
    {
        c = getopt_long(
            argc, (char* const*)argv, short_options, long_options, NULL);
        if (c == -1)
        {
            // all the command-line options are parsed
            break;
        }

        switch (c)
        {
            case 'h':
                fprintf(stderr, _usage_dump_eeid, argv[0]);
                goto done;
            case 'e':
                enclave = optarg;
                break;
            case ':':
                // Missing option argument
                ret = 1;
                goto done;
            case '?':
            default:
                // Invalid option
                ret = 1;
                goto done;
        }
    } while (1);

    if (enclave == NULL)
    {
        oe_err("--enclave-image option is missing");
        ret = 1;
    }

    if (!ret)
    {
        /* dump oeinfo and signature information */
        ret = oedump(enclave);
        /* dump EEID-related information */
        ret = oedump_eeid(enclave);
    }

done:

    return ret;
}
#endif

int sign_parser(int argc, const char* argv[])
{
    int ret = 0;
    const char* enclave = NULL;
    const char* conffile = NULL;
    const char* keyfile = NULL;
    const char* digest_signature = NULL;
    const char* x509 = NULL;
    const char* engine_id = NULL;
    const char* engine_load_path = NULL;
    const char* key_id = NULL;

    const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"enclave-image", required_argument, NULL, 'e'},
        {"config-file", required_argument, NULL, 'c'},
        {"key-file", required_argument, NULL, 'k'},
        {"digest-signature", required_argument, NULL, 'd'},
        {"x509", required_argument, NULL, 'x'},
#if HAS_ENGINE_SUPPORT
        {"engine", required_argument, NULL, 'n'},
        {"load-path", required_argument, NULL, 'p'},
        {"key-id", required_argument, NULL, 'i'},
#endif
        {NULL, 0, NULL, 0},
    };
    const char short_options[] = "he:c:k:n:p:i:d:x:";

    int c;

    if (argc <= 2)
    {
        fprintf(stderr, _usage_sign, argv[0]);
        ret = 1;
        goto done;
    }

    do
    {
        c = getopt_long(
            argc, (char* const*)argv, short_options, long_options, NULL);
        if (c == -1)
        {
            // all the command-line options are parsed
            break;
        }

        switch (c)
        {
            case 'h':
                fprintf(stderr, _usage_sign, argv[0]);
                goto done;
            case 'e':
                enclave = optarg;
                break;
            case 'c':
                conffile = optarg;
                break;
            case 'k':
                keyfile = optarg;
                break;
            case 'd':
                digest_signature = optarg;
                break;
            case 'x':
                x509 = optarg;
                break;
#if HAS_ENGINE_SUPPORT
            case 'n':
                engine_id = optarg;
                break;
            case 'p':
                engine_load_path = optarg;
                break;
            case 'i':
                key_id = optarg;
                break;
#endif
            case ':':
                // Missing option argument
                ret = 1;
                goto done;
            case '?':
            default:
                // Invalid option
                ret = 1;
                goto done;
        }
    } while (1);

    if (enclave == NULL)
    {
        oe_err("--enclave-image option is missing");
        ret = 1;
        goto done;
    }

#if HAS_ENGINE_SUPPORT
    if (engine_id || engine_load_path || key_id)
    {
        if (keyfile)
        {
            oe_err("--key-file cannot be used with engine options");
            ret = 1;
            goto done;
        }
        if (digest_signature || x509)
        {
            oe_err("--digest-signature and --x509 cannot be used with engine "
                   "options");
            ret = 1;
            goto done;
        }
        if (!engine_id || !key_id)
        {
            oe_err("Both --key-id and its --engine must be specified");
            ret = 1;
            goto done;
        }
    }
    else
#endif
        if (digest_signature || x509)
    {
        if (keyfile)
        {
            oe_err("--key-file cannot be used with digest signing options");
            ret = 1;
            goto done;
        }
        if (!digest_signature || !x509)
        {
            oe_err("--digest-signature must be used with --x509");
            ret = 1;
            goto done;
        }
    }
    else if (!keyfile)
    {
        oe_err("One of the SIGN_OPTIONS like --key-file must be specified");
        ret = 1;
        goto done;
    }

    if (!ret)
    {
        ret = oesign(
            enclave,
            conffile,
            keyfile,
            digest_signature,
            x509,
            engine_id,
            engine_load_path,
            key_id);
    }

done:
    return ret;
}

int digest_parser(int argc, const char* argv[])
{
    int ret = 0;
    const char* enclave = NULL;
    const char* conffile = NULL;
    const char* digest_file = NULL;

    const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"enclave-image", required_argument, NULL, 'e'},
        {"config-file", required_argument, NULL, 'c'},
        {"digest-file", required_argument, NULL, 'd'},
        {NULL, 0, NULL, 0},
    };
    const char short_options[] = "he:c:d:";

    int c;

    if (argc <= 2)
    {
        fprintf(stderr, _usage_digest, argv[0]);
        ret = 1;
        goto done;
    }

    do
    {
        c = getopt_long(
            argc, (char* const*)argv, short_options, long_options, NULL);
        if (c == -1)
        {
            // all the command-line options are parsed
            break;
        }

        switch (c)
        {
            case 'h':
                fprintf(stderr, _usage_digest, argv[0]);
                goto done;
            case 'e':
                enclave = optarg;
                break;
            case 'c':
                conffile = optarg;
                break;
            case 'd':
                digest_file = optarg;
                break;
            case ':':
                // Missing option argument
                ret = 1;
                goto done;
            case '?':
            default:
                // Invalid option
                ret = 1;
                goto done;
        }
    } while (1);

    if (enclave == NULL)
    {
        oe_err("--enclave-image option is missing");
        ret = 1;
        goto done;
    }

    if (digest_file == NULL)
    {
        oe_err("--digest-file option is missing");
        ret = 1;
        goto done;
    }

    if (!ret)
    {
        ret = oedigest(enclave, conffile, digest_file);
    }

done:
    return ret;
}

int arg_handler(int argc, const char* argv[])
{
    int ret = 1;
    if ((strcmp(argv[1], "dump") == 0))
        ret = dump_parser(argc, argv);
#ifdef OE_WITH_EXPERIMENTAL_EEID
    else if ((strcmp(argv[1], "dump-eeid") == 0))
        ret = dump_eeid_parser(argc, argv);
#endif
    else if ((strcmp(argv[1], "sign") == 0))
        ret = sign_parser(argc, argv);
    else if ((strcmp(argv[1], "digest") == 0))
        ret = digest_parser(argc, argv);
    else
    {
        fprintf(stderr, _usage_gen, argv[0], argv[0]);
        exit(1);
    }
    return ret;
}

int main(int argc, const char* argv[])
{
    oe_set_err_program_name(argv[0]);
    int ret = 1;

    if (argc < 2)
    {
        fprintf(stderr, _usage_gen, argv[0], argv[0]);
        exit(1);
    }

    ret = arg_handler(argc, argv);
    return ret;
}
