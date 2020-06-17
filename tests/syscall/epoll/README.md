epoll test:
===========

This test uses epoll concurrently. One thread waits on an epoll instance while
another thread adds and deletes file descriptors.
