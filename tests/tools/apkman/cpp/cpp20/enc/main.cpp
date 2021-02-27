// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <coroutine>
#include <iostream>
#include <stdexcept>
#include <thread>

auto switch_to_new_thread(std::jthread& out)
{
    struct awaitable
    {
        std::jthread* p_out;
        bool await_ready()
        {
            return false;
        }
        void await_suspend(std::coroutine_handle<> h)
        {
            std::jthread& out = *p_out;
            if (out.joinable())
                throw std::runtime_error("Output jthread parameter not empty");
            out = std::jthread([h] { h.resume(); });
            // Potential undefined behavior: accessing potentially destroyed
            // *this std::cout << "New thread ID: " << p_out->get_id() << '\n';
            std::cout << "New thread ID: " << out.get_id()
                      << '\n'; // this is OK
        }
        void await_resume()
        {
        }
    };
    return awaitable{&out};
}

struct task
{
    struct promise_type
    {
        task get_return_object()
        {
            return {};
        }
        std::suspend_never initial_suspend()
        {
            return {};
        }
        std::suspend_never final_suspend() noexcept
        {
            return {};
        }
        void return_void()
        {
        }
        void unhandled_exception()
        {
        }
    };
};

task resuming_on_new_thread(std::jthread& out)
{
    std::cout << "Coroutine started on thread: " << std::this_thread::get_id()
              << '\n';
    co_await switch_to_new_thread(out);
    // awaiter destroyed here
    std::cout << "Coroutine resumed on thread: " << std::this_thread::get_id()
              << '\n';
}

template <class T>
struct generator
{
    struct promise_type;
    using coro_handle = std::coroutine_handle<promise_type>;

    struct promise_type
    {
        T current_value;
        auto get_return_object()
        {
            return generator{coro_handle::from_promise(*this)};
        }
        auto initial_suspend()
        {
            return std::suspend_always{};
        }
        auto final_suspend()
        {
            return std::suspend_always{};
        }
        void unhandled_exception()
        {
            std::terminate();
        }
        auto yield_value(T value)
        {
            current_value = value;
            return std::suspend_always{};
        }
    };

    bool next()
    {
        return coro ? (coro.resume(), !coro.done()) : false;
    }
    T value()
    {
        return coro.promise().current_value;
    }

    generator(generator const& rhs) = delete;
    generator(generator&& rhs) : coro(rhs.coro)
    {
        rhs.coro = nullptr;
    }
    ~generator()
    {
        if (coro)
            coro.destroy();
    }

  private:
    generator(coro_handle h) : coro(h)
    {
    }
    coro_handle coro;
};

generator<int> fact_gen()
{
    int f = 1;
    int i = 1;
    while (true)
    {
        f *= i;
        co_yield i;
        ++i;
    }
}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    std::jthread out;
    resuming_on_new_thread(out);

    auto fgen = fact_gen();
    fgen.next();
    for (int i = 0; i < 10; ++i)
    {
        std::cout << " factorial: " << fgen.value() << std::endl;
        fgen.next();
    }
    return 0;
}
