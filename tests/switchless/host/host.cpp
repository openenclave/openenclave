// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <limits>
#include <thread>
#include <vector>

#include <time.h>
#include <climits>
#include <cstdlib>

#include "switchless_u.h"

static const size_t SAMPLE_SIZE = 10000;

// when DETAILED_TIME is 0, ecalls are timed in a batch
// when DETAILED_TIME non 0, each ecall is timed independently
#define DETAILED_TIME 1

struct test_data
{
    int arg1, arg2, sum;
    struct timespec start, stop;
};

void generate_test_data(test_data* begin_pos, test_data* end_pos)
{
    for (test_data* pos = begin_pos; pos != end_pos; ++pos)
    {
        pos->arg1 = rand() % (INT_MAX / 2);
        pos->arg2 = rand() % (INT_MAX / 2);
    }
}

bool operator<(timespec const& lhs, timespec const& rhs)
{
    return lhs.tv_sec < rhs.tv_sec ||
           (lhs.tv_sec == rhs.tv_sec && lhs.tv_nsec < rhs.tv_nsec);
}

bool operator<=(timespec const& lhs, timespec const& rhs)
{
    return lhs.tv_sec < rhs.tv_sec ||
           (lhs.tv_sec == rhs.tv_sec && lhs.tv_nsec <= rhs.tv_nsec);
}

static const long NS_PER_SEC = 1000000000;

timespec operator-(timespec const& lhs, timespec const& rhs)
{
    OE_TEST(!(lhs <= rhs));
    timespec out = {0, 0};
    if (rhs.tv_nsec > lhs.tv_nsec)
    {
        out.tv_sec = lhs.tv_sec - (rhs.tv_sec + 1);
        out.tv_nsec = NS_PER_SEC + lhs.tv_nsec - rhs.tv_nsec;
    }
    else
    {
        out.tv_sec = lhs.tv_sec - rhs.tv_sec;
        out.tv_nsec = lhs.tv_nsec - rhs.tv_nsec;
    }
    return out;
}

timespec operator+(timespec const& lhs, timespec const& rhs)
{
    timespec out = {0, 0};
    out.tv_sec = lhs.tv_sec + rhs.tv_sec;
    out.tv_nsec = lhs.tv_nsec + rhs.tv_nsec;
    while (NS_PER_SEC <= out.tv_nsec)
    {
        ++(out.tv_sec);
        (out.tv_nsec) -= NS_PER_SEC;
    }
    return out;
}

double timespec_to_sec(timespec const& ts)
{
    return static_cast<double>(ts.tv_nsec) / static_cast<double>(NS_PER_SEC) +
           static_cast<double>(ts.tv_sec);
}

void analyze_data(test_data* begin_pos, test_data* end_pos, double* total)
{
    printf("  <analyze_data>\n");
    int count = 0;
    int correct = 0;
    timespec total_time = {0, 0};
    timespec shortest_time = {INT_MAX, INT_MAX};
    timespec longest_time = {0, 0};
    for (test_data* pos = begin_pos; pos != end_pos; ++pos)
    {
        ++count;
        if (pos->sum == (pos->arg1 + pos->arg2))
        {
            ++correct;
        }

        // printf(
        //     "    pos->start (sec): %.8f\n",
        //     static_cast<float>(pos->start.tv_sec) +
        //         static_cast<float>(pos->start.tv_nsec) / 1000000000.0f);
        // printf(
        //     "    pos->stop (sec): %.8f\n",
        //     static_cast<float>(pos->stop.tv_sec) +
        //         static_cast<float>(pos->stop.tv_nsec) / 1000000000.0f);

        timespec delta = pos->stop - pos->start;
        total_time = total_time + delta;
        if (delta < shortest_time)
        {
            shortest_time = delta;
        }
        if (longest_time < delta)
        {
            longest_time = delta;
        }
    }
    printf("    count: %d\n", count);
    printf(
        "    correct: %d/%d (%.1f%%)\n",
        correct,
        count,
        static_cast<float>(correct * 100) / static_cast<float>(count));
    *total = timespec_to_sec(total_time);
    printf("    total_time (sec): %.8lf\n", *total);
    printf("    shortest_time (sec): %.8lf\n", timespec_to_sec(shortest_time));
    printf("    longest_time (sec): %.8lf\n", timespec_to_sec(longest_time));
    printf(
        "    average_time (sec): %.8lf\n", *total / static_cast<double>(count));
    printf("  </analyze_data>\n");
}

oe_result_t test_standard_enc_sum(oe_enclave_t* enclave, double* total)
{
    oe_result_t result = OE_OK;
    test_data data[SAMPLE_SIZE];

    generate_test_data(data, data + SAMPLE_SIZE);
    printf("<test_standard_enc_sum>\n");
#if (DETAILED_TIME)
    for (test_data *pos = data, *end_pos = data + SAMPLE_SIZE;
         OE_OK == result && pos != end_pos;
         ++pos)
    {
        clock_gettime(CLOCK_REALTIME, &(pos->start));
        result = standard_enc_sum(enclave, &(pos->sum), pos->arg1, pos->arg2);
        if (OE_OK != result)
        {
            printf("  FAILED: %s\n", oe_result_str(result));
        }
        clock_gettime(CLOCK_REALTIME, &(pos->stop));
    }
    analyze_data(data, data + SAMPLE_SIZE, total);
#else  // DETAILED_TIME
    timespec start;
    clock_gettime(CLOCK_REALTIME, &start);
    for (test_data *pos = data, *end_pos = data + SAMPLE_SIZE;
         OE_OK == result && pos != end_pos;
         ++pos)
    {
        result = standard_enc_sum(enclave, &(pos->sum), pos->arg1, pos->arg2);
        if (OE_OK != result)
        {
            printf("  FAILED: %s\n", oe_result_str(result));
        }
    }
    timespec stop;
    clock_gettime(CLOCK_REALTIME, &stop);
    timespec delta = stop - start;
    *total = timespec_to_sec(delta);
#endif // DETAILED_TIME
    printf("</test_standard_enc_sum>\n");
    return result;
}

#if (__SWITCHLESS__)
void test_single_thread_enc_queue()
{
    const size_t COUNT = 100;
    switchless_control sc;
    init_switchless_control(&sc, SC_RUNNING, 0x06FFFFFF);

    OE_TEST(nullptr == sc_pop_enc_queue(&sc));
    OE_TEST(nullptr == sc_pop_host_queue(&sc));

    sc_queue_node nodes[COUNT];
    for (sc_queue_node* pnode = nodes; pnode != nodes + COUNT; ++pnode)
    {
        sc_push_enc_queue(&sc, pnode);
    }
    for (size_t i = 0; i < COUNT; ++i)
    {
        sc_queue_node* pnode = sc_pop_enc_queue(&sc);
        OE_TEST(nodes + i == pnode);
    }

    for (sc_queue_node* pnode = nodes; pnode != nodes + COUNT; ++pnode)
    {
        sc_push_host_queue(&sc, pnode);
    }
    for (size_t i = 0; i < COUNT; ++i)
    {
        sc_queue_node* pnode = sc_pop_host_queue(&sc);
        OE_TEST(nodes + i == pnode);
    }

    OE_TEST(nullptr == sc_pop_enc_queue(&sc));
    OE_TEST(nullptr == sc_pop_host_queue(&sc));
}
#endif // __SWITCHLESS__

#if (__SWITCHLESS__)
void test_multi_thread_enc_queue_reader_thread(
    switchless_control* psc,
    sc_queue_node* pnodes,
    size_t count)
{
    // printf("  <test_multi_thread_enc_queue_reader_thread>\n");
    std::unique_ptr<size_t[]> counters(new size_t[count]);
    std::fill(counters.get(), counters.get() + count, 0);

    // pop all of the nodes
    for (size_t i = 0; i < count; ++i)
    {
        sc_queue_node* pnode = nullptr;
        do
        {
            pnode = sc_pop_enc_queue(psc);
        } while (nullptr == pnode);
        size_t index = static_cast<size_t>(std::distance(pnodes, pnode));
        OE_TEST(index < count);
        ++counters[index];
    }

    // test that each node was popped exactly once
    OE_TEST(
        count == static_cast<size_t>(
                     std::count(counters.get(), counters.get() + count, 1)));

    // test that the queue is now empty
    OE_TEST(nullptr == sc_pop_enc_queue(psc));
    // printf("  </test_multi_thread_enc_queue_reader_thread>\n");
}
#endif // __SWITCHLESS__

#if (__SWITCHLESS__)
void test_multi_thread_enc_queue_writer_thread(
    switchless_control* psc,
    sc_queue_node* pnodes,
    size_t count)
{
    // printf("  <test_multi_thread_enc_queue_writer_thread>\n");
    for (size_t i = 0; i < count; ++i)
    {
        sc_push_enc_queue(psc, pnodes + i);
    }
    // printf("  </test_multi_thread_enc_queue_writer_thread>\n");
}
#endif // __SWITCHLESS__

#if (__SWITCHLESS__)
void test_multi_thread_enc_queue()
{
    // printf("<test_multi_thread_enc_queue>\n");
    const size_t NODE_COUNT = 100000;
    const size_t WRITER_THREAD_COUNT = 5;
    const size_t WRITER_NODE_COUNT = NODE_COUNT / WRITER_THREAD_COUNT;
    switchless_control sc;
    init_switchless_control(&sc, SC_RUNNING, 0x06FFFFFF);
    sc_queue_node nodes[NODE_COUNT];

    std::thread reader_thread = std::thread(
        test_multi_thread_enc_queue_reader_thread, &sc, nodes, NODE_COUNT);
    std::thread writer_threads[WRITER_THREAD_COUNT];
    for (size_t i = 0; i < WRITER_THREAD_COUNT; ++i)
    {
        writer_threads[i] = std::thread(
            test_multi_thread_enc_queue_writer_thread,
            &sc,
            nodes + i * WRITER_NODE_COUNT,
            WRITER_NODE_COUNT);
    }
    for (size_t i = 0; i < WRITER_THREAD_COUNT; ++i)
    {
        writer_threads[i].join();
    }
    reader_thread.join();
    // printf("</test_multi_thread_enc_queue>\n");
}
#endif

#if (__SWITCHLESS__)
void enc_worker_thread(oe_enclave_t* enclave, switchless_control* psc)
{
    oe_result_t result = switchless_enc_worker_thread(enclave, psc);
    OE_TEST(OE_OK == result);
    // these next two lines are very likely to have race conditions in a
    // truly multi-threaded application when the psc is restarted
    OE_TEST(SC_STOPPED == sc_get_state(psc));
    sc_set_state(psc, SC_EXITED);
}
#endif // __SWITCHLESS__

#if (__SWITCHLESS__)
void test_switchless_infrastructure(oe_enclave_t* enclave)
{
    // test that the queues work
    test_single_thread_enc_queue();
    test_multi_thread_enc_queue();

    switchless_control sc;
    std::thread worker_thread;

    // test that the thread can be stopped
    init_switchless_control(
        &sc, SC_RUNNING, std::numeric_limits<size_t>::max());
    worker_thread = std::thread(enc_worker_thread, enclave, &sc);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    OE_TEST(SC_RUNNING == sc_get_state(&sc));
    sc_set_state(&sc, SC_STOPPING);
    worker_thread.join();
    OE_TEST(SC_EXITED == sc_get_state(&sc));

    // test that the thread can exit after the count expires
    init_switchless_control(&sc, SC_RUNNING, 0x06FFFFFF);
    worker_thread = std::thread(enc_worker_thread, enclave, &sc);
    worker_thread.join();
    OE_TEST(SC_EXITED == sc_get_state(&sc));
}
#endif // __SWITCHLESS__

#if (__SWITCHLESS__)
oe_result_t test_synchronous_enc_sum(oe_enclave_t* enclave, double* total)
{
    oe_result_t result = OE_OK;
    test_data data[SAMPLE_SIZE];

    generate_test_data(data, data + SAMPLE_SIZE);
    printf("<test_synchronous_enc_sum>\n");

    // start a worker thread
    switchless_control sc;
    init_switchless_control(&sc, SC_RUNNING, 0x06FFFFFFFF);
    std::thread worker_thread = std::thread(enc_worker_thread, enclave, &sc);

#if (DETAILED_TIME)
    for (test_data *pos = data, *end_pos = data + SAMPLE_SIZE;
         OE_OK == result && pos != end_pos;
         ++pos)
    {
        clock_gettime(CLOCK_REALTIME, &(pos->start));

        result = synchronous_switchless_enc_sum(
            &sc, &(pos->sum), pos->arg1, pos->arg2);
        if (OE_OK != result)
        {
            printf("  FAILED: %s\n", oe_result_str(result));
        }

        clock_gettime(CLOCK_REALTIME, &(pos->stop));
    }
    analyze_data(data, data + SAMPLE_SIZE, total);
#else  // DETAILED_TIME
    timespec start;
    clock_gettime(CLOCK_REALTIME, &start);

    for (test_data *pos = data, *end_pos = data + SAMPLE_SIZE;
         OE_OK == result && pos != end_pos;
         ++pos)
    {
        result = synchronous_switchless_enc_sum(
            &sc, &(pos->sum), pos->arg1, pos->arg2);
        if (OE_OK != result)
        {
            printf("  FAILED: %s\n", oe_result_str(result));
        }
    }
    timespec stop;
    clock_gettime(CLOCK_REALTIME, &stop);
    timespec delta = stop - start;
    *total = timespec_to_sec(delta);
#endif // DETAILED_TIME

    // kill the worker thread
    sc_set_state(&sc, SC_STOPPING);
    worker_thread.join();
    OE_TEST(SC_EXITED == sc_get_state(&sc));

    printf("</test_synchronous_enc_sum>\n");
    return result;
}
#endif // __SWITCHLESS

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();
    oe_enclave_t* enclave = nullptr;
    oe_result_t result = oe_create_switchless_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result != OE_OK)
    {
        oe_put_err("oe_create_switchless_enclave(): result=%u", result);
    }

    double standard_total = 0.0;
    // gather metrics for standard ecalls
    if (OE_OK != (result = test_standard_enc_sum(enclave, &standard_total)))
    {
        oe_put_err("test_standard_enc_sum: result=%u", result);
        OE_TEST(OE_OK == result && "test_standard_enc_sum");
    }

    // this is a valid unit test of the infrastructure but it takes time
    // test the switchless infrastructure
#if (__SWITCHLESS__)
    test_switchless_infrastructure(enclave);

    double synchronous_total = 0.0;
    // gather metrics for synchronous ecalls
    if (OE_OK !=
        (result = test_synchronous_enc_sum(enclave, &synchronous_total)))
    {
        oe_put_err("test_synchronous_enc_sum: result=%u", result);
        OE_TEST(OE_OK == result && "test_synchronous_enc_sum");
    }

    if (OE_OK == result)
    {
        printf("<results>\n");
        printf(
            "  switchless took %.2lf%% the time of standard.\n",
            100.0 * synchronous_total / standard_total);
        printf("</results>\n");
    }
#endif // __SWITCHLESS__

    if (OE_OK != (result = oe_terminate_enclave(enclave)))
    {
        oe_put_err("oe_terminate_enclave: result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
