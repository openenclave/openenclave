// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "test_t.h"

// For mounting host filesystem
#include <openenclave/internal/syscall/device.h>
#include <openenclave/internal/syscall/sys/mount.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/internal/tests.h>
#include <sys/mount.h>

#include <iostream>
#include <sstream>
#include <string>

#include <google/protobuf/util/json_util.h>
#include "types.pb.h"

int test_protobufs()
{
    // Verify that the version of the library that we linked against is
    // compatible with the version of the headers we compiled against.
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    // Create stocks.
    types::Market market;
    types::Stock* s1 = market.add_stock();
    s1->set_id(1);
    s1->set_symbol("MSFT");
    s1->set_display_name("Microsoft Corporation");
    s1->set_market_id(4);
    s1->set_price(232.38f);

    types::Stock* s2 = market.add_stock();
    s2->set_id(2);
    s2->set_symbol("INTC");
    s2->set_display_name("Intel Corporation");
    s2->set_market_id(8);
    s2->set_price(60.78f);
    std::cout << "Created objects.\n";

    // Serialize objects.
    std::ostringstream os;
    market.SerializeToOstream(&os);
    std::cout << "Serialized objects.\n";

    std::istringstream in(os.str());
    types::Market market2;
    market2.ParseFromIstream(&in);
    std::cout << "Deserialized objects.\n";

    std::string json;
    google::protobuf::util::MessageToJsonString(market2, &json);
    std::cout << json << std::endl;
    std::cout << " Converted to json.\n";

    types::Market market3;
    google::protobuf::util::JsonStringToMessage(json, &market3);
    std::cout << "Read from json.\n";

    std::string json2;
    google::protobuf::util::MessageToJsonString(market2, &json2);
    std::cout << "Converted back to json.\n";

    OE_TEST(json == json2);
    std::cout << "Json round-trip successful.\n";

    // Optional:  Delete all global objects allocated by libprotobuf.
    google::protobuf::ShutdownProtobufLibrary();

    return 0;
}

int enc_main(int argc, char** argv)
{
    OE_UNUSED(argc);
    OE_UNUSED(argv);

    return test_protobufs();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
