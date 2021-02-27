// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <iostream>
#include <vector>

#include <boost/bimap.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

// include headers that implement a archive in simple text format
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>

/////////////////////////////////////////////////////////////
// gps coordinate
//
// illustrates serialization for a simple type
//
class gps_position
{
  private:
    friend class boost::serialization::access;
    // When the class Archive corresponds to an output archive, the
    // & operator is defined similar to <<.  Likewise, when the class Archive
    // is a type of input archive the & operator is defined similar to >>.
    template <class Archive>
    void serialize(Archive& ar, const unsigned int version)
    {
        ar& degrees;
        ar& minutes;
        ar& seconds;
    }
    int degrees;
    int minutes;
    float seconds;

  public:
    gps_position(){};
    gps_position(int d, int m, float s) : degrees(d), minutes(m), seconds(s)
    {
    }

    bool operator==(const gps_position& other) const
    {
        return degrees == other.degrees && minutes == other.minutes &&
               seconds == other.seconds;
    }
};

int main_serialize()
{
    // create and open a character archive for output
    std::ostringstream ofs;

    // create class instance
    const gps_position g(35, 59, 24.567f);

    // save data to archive
    {
        boost::archive::text_oarchive oa(ofs);
        // write class instance to archive
        oa << g;
        // archive and stream closed when destructors are called
    }
    std::cout << "Serialized gps_position\n";

    // ... some time later restore the class instance to its orginal state
    gps_position newg;
    {
        // create and open an archive for input
        std::stringstream ifs(ofs.str());
        boost::archive::text_iarchive ia(ifs);
        // read class state from archive
        ia >> newg;
        // archive and stream closed when destructors are called
    }
    if (g == newg)
        std::cout << "Deserialization successful!\n";
    return 0;
}

template <class MapType>
void print_map(
    const MapType& map,
    const std::string& separator,
    std::ostream& os)
{
    typedef typename MapType::const_iterator const_iterator;

    for (const_iterator i = map.begin(), iend = map.end(); i != iend; ++i)
    {
        os << i->first << separator << i->second << std::endl;
    }
}

void boost_test()
{
    // bimap
    {
        // Soccer World cup
        typedef boost::bimap<std::string, int> results_bimap;
        typedef results_bimap::value_type position;

        results_bimap results;
        results.insert(position("Argentina", 1));
        results.insert(position("Spain", 2));
        results.insert(position("Germany", 3));
        results.insert(position("France", 4));

        std::cout << "The number of countries is " << results.size()
                  << std::endl;

        std::cout << "The winner is " << results.right.at(1) << std::endl
                  << std::endl;

        std::cout << "Countries names ordered by their final position:"
                  << std::endl;

        // results.right works like a std::map< int, std::string >

        print_map(results.right, ") ", std::cout);

        std::cout << std::endl
                  << "Countries names ordered alphabetically along with"
                     "their final position:"
                  << std::endl;

        // results.left works like a std::map< std::string, int >
        print_map(results.left, " ends in position ", std::cout);
    }

    // multiprecision
    {
        using boost::multiprecision::cpp_int;
        //
        // Print all the factorials that will fit inside a 128-bit integer.
        //
        // Begin by building a big table of factorials, once we know just how
        // large the largest is, we'll be able to "pretty format" the results.
        //
        // Calculate the largest number that will fit inside 128 bits, we could
        // also have used numeric_limits<int128_t>::max() for this value:
        cpp_int limit = (cpp_int(1) << 256) - 1;
        //
        // Our table of values:
        std::vector<cpp_int> results;
        //
        // Initial values:
        unsigned i = 1;
        cpp_int factorial = 1;
        //
        // Cycle through the factorials till we reach the limit:
        while (factorial < limit)
        {
            results.push_back(factorial);
            ++i;
            factorial *= i;
        }
        //
        // Lets see how many digits the largest factorial was:
        unsigned digits = results.back().str().size();
        //
        // Now print them out, using right justification, while we're at it
        // we'll indicate the limit of each integer type, so begin by defining
        // the limits for 16, 32, 64 etc bit integers:
        cpp_int limits[] = {
            (cpp_int(1) << 16) - 1,
            (cpp_int(1) << 32) - 1,
            (cpp_int(1) << 64) - 1,
            (cpp_int(1) << 128) - 1,
            (cpp_int(1) << 256) - 1,
        };
        std::string bit_counts[] = {"16", "32", "64", "128", "256"};
        unsigned current_limit = 0;
        for (unsigned j = 0; j < results.size(); ++j)
        {
            if (limits[current_limit] < results[j])
            {
                std::string message =
                    "Limit of " + bit_counts[current_limit] + " bit integers";
                std::cout << std::setfill('.') << std::setw(digits + 1)
                          << std::right << message << std::setfill(' ')
                          << std::endl;
                ++current_limit;
            }
            std::cout << std::setw(digits + 1) << std::right << results[j]
                      << std::endl;
        }
    }

    // serialization
    {
        main_serialize();
    }

    std::cout << "boost tests completed\n";
}
