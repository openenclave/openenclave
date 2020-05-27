// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/syscall/device.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <set>
#include <string>
#include "../../cpio/commands.h"
#include "../../cpio/cpio.h"
#include "file_system.h"
#include "fs_t.h"

using namespace std;

static const char ALPHABET[] = "abcdefghijklmnopqrstuvwxyz";
static const mode_t MODE = 0644;

const char* mkpath(char buf[OE_PATH_MAX], const char* target, const char* path)
{
    strlcpy(buf, target, OE_PATH_MAX);
    strlcat(buf, "/", OE_PATH_MAX);
    strlcat(buf, path, OE_PATH_MAX);
    return buf;
}

class device_registrant
{
  public:
    device_registrant(uint64_t devid)
    {
        OE_TEST(oe_set_thread_devid(devid) == OE_OK);
    }

    ~device_registrant()
    {
        OE_TEST(oe_clear_thread_devid() == OE_OK);
    }
};

static void _touch(const char* path)
{
    FILE* stream;

    printf("Creating %s\n", path);

    OE_TEST((stream = fopen(path, "w")) != NULL);
    OE_TEST(fwrite("hello", 1, 5, stream) == 5);
    OE_TEST(fclose(stream) == 0);
}

void list(const char* dirname, set<string>& names)
{
    DIR* dir;
    struct dirent* ent;

    OE_TEST((dir = opendir(dirname)) != NULL);

    while ((ent = readdir(dir)))
        names.insert(ent->d_name);

    closedir(dir);
}

template <class FILE_SYSTEM>
static void cleanup(FILE_SYSTEM& fs, const char* tmp_dir)
{
    char path[OE_PAGE_SIZE];

    fs.unlink(mkpath(path, tmp_dir, "alphabet"));
    fs.unlink(mkpath(path, tmp_dir, "alphabet.renamed"));
    fs.unlink(mkpath(path, tmp_dir, "alphabet.linked"));

    mkpath(path, tmp_dir, "dir1");
    fs.rmdir(path);

    mkpath(path, tmp_dir, "dir2");
    fs.rmdir(path);
}

template <class FILE_SYSTEM>
static void test_create_file(FILE_SYSTEM& fs, const char* tmp_dir)
{
    char path[OE_PAGE_SIZE];
    typename FILE_SYSTEM::file_handle file;

    printf("--- %s()\n", __FUNCTION__);

    mkpath(path, tmp_dir, "alphabet");

    /* Open the file for output. */
    {
        const int flags = OE_O_CREAT | OE_O_TRUNC | OE_O_WRONLY;
        OE_TEST(file = fs.open(path, flags, MODE));
    }

    /* Write to the file. */
    {
        ssize_t n = fs.write(file, ALPHABET, sizeof(ALPHABET));
        OE_TEST(n == sizeof(ALPHABET));
    }

    /* Sync the file. */
    OE_TEST(fs.fdatasync(file) == 0);
    OE_TEST(fs.fsync(file) == 0);

    /* Close the file. */
    OE_TEST(fs.close(file) == 0);
}

template <class FILE_SYSTEM>
static void test_read_file(FILE_SYSTEM& fs, const char* tmp_dir)
{
    char path[OE_PAGE_SIZE];
    typename FILE_SYSTEM::file_handle file;
    char buf[OE_PAGE_SIZE];

    printf("--- %s()\n", __FUNCTION__);

    mkpath(path, tmp_dir, "alphabet");

    /* Open the file for input. */
    {
        const int flags = OE_O_RDONLY;
        file = fs.open(path, flags, 0);
        OE_TEST(file);
    }

    /* Read the whole file. */
    {
        ssize_t n = fs.read(file, buf, sizeof(buf));
        OE_TEST(n == sizeof(ALPHABET));
        OE_TEST(memcmp(buf, ALPHABET, sizeof(ALPHABET)) == 0);
    }

    /* Read "lmnop" */
    {
        OE_TEST(fs.lseek(file, 11, OE_SEEK_SET) == 11);
        OE_TEST(fs.read(file, buf, 5) == 5);
        OE_TEST(memcmp(buf, "lmnop", 5) == 0);
    }

    /* Read one character at a time. */
    {
        OE_TEST(fs.lseek(file, 0, OE_SEEK_SET) == 0);

        for (size_t i = 0; i < OE_COUNTOF(ALPHABET); i++)
        {
            OE_TEST(fs.read(file, buf, 1) == 1);
            OE_TEST(ALPHABET[i] == buf[0]);
        }
    }

    /* Close the file. */
    OE_TEST(fs.close(file) == 0);
}

template <class FILE_SYSTEM>
static void test_pread_file(FILE_SYSTEM& fs, const char* tmp_dir)
{
    char path[OE_PAGE_SIZE];
    typename FILE_SYSTEM::file_handle file;
    char buf[OE_PAGE_SIZE];

    printf("--- %s()\n", __FUNCTION__);

    mkpath(path, tmp_dir, "alphabet");

    /* Open the file for input. */
    {
        const int flags = OE_O_RDONLY;
        file = fs.open(path, flags, 0);
        OE_TEST(file);
    }

    /* pread the whole file. */
    {
        ssize_t n = fs.pread(file, buf, sizeof(buf), 0);
        OE_TEST(n == sizeof(ALPHABET));
        OE_TEST(memcmp(buf, ALPHABET, sizeof(ALPHABET)) == 0);
    }

    /* read "ab" */
    {
        OE_TEST(fs.read(file, buf, 2) == 2);
        OE_TEST(memcmp(buf, "ab", 2) == 0);
    }

    /* pread "lmnop" */
    {
        OE_TEST(fs.pread(file, buf, 5, 11) == 5);
        OE_TEST(memcmp(buf, "lmnop", 5) == 0);
    }

    /* read "cd" (pread should not have changed file offset) */
    {
        OE_TEST(fs.read(file, buf, 2) == 2);
        OE_TEST(memcmp(buf, "cd", 2) == 0);
    }

    /* Close the file. */
    OE_TEST(fs.close(file) == 0);
}

template <class FILE_SYSTEM>
static void test_pwrite_file(FILE_SYSTEM& fs, const char* tmp_dir)
{
    char path[OE_PAGE_SIZE];
    typename FILE_SYSTEM::file_handle file;
    char buf[OE_PAGE_SIZE];

    printf("--- %s()\n", __FUNCTION__);

    mkpath(path, tmp_dir, "alphabet");

    /* Open the file for input/output. */
    {
        const int flags = O_RDWR;
        file = fs.open(path, flags, 0);
        OE_TEST(file);
    }

    /* write "xx" at offset 3 */
    OE_TEST(fs.pwrite(file, "xx", 2, 3) == 2);

    /* read "abcxxfg" */
    {
        OE_TEST(fs.read(file, buf, 7) == 7);
        OE_TEST(memcmp(buf, "abcxxfg", 7) == 0);
    }

    /* Close the file. */
    OE_TEST(fs.close(file) == 0);
}

template <class FILE_SYSTEM>
static void test_stat_file(FILE_SYSTEM& fs, const char* tmp_dir)
{
    char path[OE_PAGE_SIZE];
    typename FILE_SYSTEM::stat_type buf, fbuf;

    printf("--- %s()\n", __FUNCTION__);

    mkpath(path, tmp_dir, "alphabet");

    /* Stat the file. */
    OE_TEST(fs.stat(path, &buf) == 0);

    /* Check stats. */
    OE_TEST(buf.st_size == sizeof(ALPHABET));
    OE_TEST(OE_S_ISREG(buf.st_mode));
    /* windows cannot return the whole mode in stat bits */
    OE_TEST(
        (buf.st_mode & ((OE_S_IFREG | MODE) & (OE_S_IRUSR | OE_S_IWUSR))) ==
        ((OE_S_IFREG | MODE) & (OE_S_IRUSR | OE_S_IWUSR)));

    /* fstat should return the same result as stat */
    const auto file = fs.open(path, 0, 0);
    OE_TEST(file);
    OE_TEST(fs.fstat(file, &fbuf) == 0);
    OE_TEST(fs.close(file) == 0);
    OE_TEST(fbuf.st_ino == buf.st_ino);
    OE_TEST(fbuf.st_nlink == buf.st_nlink);
    OE_TEST(fbuf.st_mode == buf.st_mode);
    OE_TEST(fbuf.st_uid == buf.st_uid);
    OE_TEST(fbuf.st_gid == buf.st_gid);
    OE_TEST(fbuf.st_size == buf.st_size);
    OE_TEST(fbuf.st_blksize == buf.st_blksize);
    OE_TEST(fbuf.st_blocks == buf.st_blocks);
}

template <class FILE_SYSTEM>
static void test_readdir(FILE_SYSTEM& fs, const char* tmp_dir)
{
    typename FILE_SYSTEM::dir_handle dir;
    typename FILE_SYSTEM::dirent_type* ent;
    size_t count = 0;
    char path[OE_PATH_MAX];

    printf("--- %s()\n", __FUNCTION__);

    /* Create directories: "dir1" and "dir2". */
    {
        mkpath(path, tmp_dir, "dir1");
        OE_TEST(fs.mkdir(path, 0777) == 0);

        mkpath(path, tmp_dir, "dir2");
        OE_TEST(fs.mkdir(path, 0777) == 0);
    }

    /* Test stat on a directory. */
    {
        typename FILE_SYSTEM::stat_type buf;
        OE_TEST(fs.stat(mkpath(path, tmp_dir, "dir1"), &buf) == 0);
        OE_TEST(OE_S_ISDIR(buf.st_mode));
    }

    /* Remove directory "dir2". */
    OE_TEST(fs.rmdir(mkpath(path, tmp_dir, "dir2")) == 0);

    dir = fs.opendir(tmp_dir);
    OE_TEST(dir);

    for (size_t i = 0; i < 8; i++)
    {
        bool found_alphabet = false;
        bool found_alphabet_renamed = false;
        bool found_dot = false;
        bool found_dot_dot = false;
        bool found_dir1 = false;
        bool found_dir2 = false;

        while ((ent = fs.readdir(dir)))
        {
            if (strcmp(ent->d_name, "alphabet") == 0)
                found_alphabet = true;

            if (strcmp(ent->d_name, "alphabet.renamed") == 0)
                found_alphabet_renamed = true;

            if (strcmp(ent->d_name, ".") == 0)
                found_dot = true;

            if (strcmp(ent->d_name, "..") == 0)
                found_dot_dot = true;

            if (strcmp(ent->d_name, "dir1") == 0)
                found_dir1 = true;

            if (strcmp(ent->d_name, "dir2") == 0)
                found_dir2 = true;

            count++;
        }

        OE_TEST(found_alphabet);
        OE_TEST(found_alphabet_renamed);
        OE_TEST(found_dot);
        OE_TEST(found_dot_dot);
        OE_TEST(found_dir1);
        OE_TEST(!found_dir2);

        fs.rewinddir(dir);
    }

    fs.closedir(dir);
}

template <class FILE_SYSTEM>
static void test_link_file(FILE_SYSTEM& fs, const char* tmp_dir)
{
    char oldname[OE_PAGE_SIZE];
    char newname[OE_PAGE_SIZE];
    typename FILE_SYSTEM::stat_type buf;

    printf("--- %s()\n", __FUNCTION__);

    mkpath(oldname, tmp_dir, "alphabet");
    mkpath(newname, tmp_dir, "alphabet.linked");

    OE_TEST(fs.link(oldname, newname) == 0);
    OE_TEST(fs.stat(oldname, &buf) == 0);
    OE_TEST(fs.stat(newname, &buf) == 0);
}

template <class FILE_SYSTEM>
static void test_rename_file(FILE_SYSTEM& fs, const char* tmp_dir)
{
    char oldname[OE_PAGE_SIZE];
    char newname[OE_PAGE_SIZE];
    typename FILE_SYSTEM::stat_type buf;

    printf("--- %s()\n", __FUNCTION__);

    mkpath(oldname, tmp_dir, "alphabet.linked");
    mkpath(newname, tmp_dir, "alphabet.renamed");

    OE_TEST(fs.rename(oldname, newname) == 0);
    OE_TEST(fs.stat(oldname, &buf) != 0);
    OE_TEST(fs.stat(newname, &buf) == 0);
}

template <class FILE_SYSTEM>
static void test_truncate_file(FILE_SYSTEM& fs, const char* tmp_dir)
{
    char path[OE_PAGE_SIZE];
    typename FILE_SYSTEM::stat_type buf;

    printf("--- %s()\n", __FUNCTION__);

    mkpath(path, tmp_dir, "alphabet");

    /* Remove the file. */
    OE_TEST(fs.truncate(path, 5) == 0);

    /* Stat the file. */
    OE_TEST(fs.stat(path, &buf) == 0);
    OE_TEST(buf.st_size == 5);
}

template <class FILE_SYSTEM>
static void test_unlink_file(FILE_SYSTEM& fs, const char* tmp_dir)
{
    char path[OE_PAGE_SIZE];
    typename FILE_SYSTEM::stat_type buf;

    printf("--- %s()\n", __FUNCTION__);

    mkpath(path, tmp_dir, "alphabet");

    /* Remove the file. */
    OE_TEST(fs.unlink(path) == 0);

    /* Stat the file. */
    OE_TEST(fs.stat(path, &buf) != 0);
}

template <class FILE_SYSTEM>
static void test_invalid_path(FILE_SYSTEM& fs)
{
    const char* const path = "doesnotexist";
    printf("--- %s()\n", __FUNCTION__);
    OE_TEST(fs.open(path, O_RDONLY, 0) == FILE_SYSTEM::invalid_file_handle);
    OE_TEST(fs.opendir(path) == FILE_SYSTEM::invalid_dir_handle);
    OE_TEST(fs.rmdir(path) == -1);
    OE_TEST(fs.truncate(path, 0) == -1);
}

template <class FILE_SYSTEM>
void test_common(FILE_SYSTEM& fs, const char* tmp_dir)
{
    cleanup(fs, tmp_dir);
    test_create_file(fs, tmp_dir);
    test_read_file(fs, tmp_dir);
    test_stat_file(fs, tmp_dir);
    test_link_file(fs, tmp_dir);
    test_rename_file(fs, tmp_dir);
    test_readdir(fs, tmp_dir);
    test_truncate_file(fs, tmp_dir);
    test_unlink_file(fs, tmp_dir);
    test_invalid_path(fs);
    cleanup(fs, tmp_dir);
}

template <class FILE_SYSTEM>
void test_pio(FILE_SYSTEM& fs, const char* tmp_dir)
{
    cleanup(fs, tmp_dir);
    test_create_file(fs, tmp_dir);
    test_pread_file(fs, tmp_dir);
    test_pwrite_file(fs, tmp_dir);
    cleanup(fs, tmp_dir);
}

void test_fprintf_fscanf(const char* tmp_dir)
{
    char path[OE_PAGE_SIZE];
    device_registrant registrant(OE_DEVID_HOST_FILE_SYSTEM);

    printf("--- %s()\n", __FUNCTION__);

    mkpath(path, tmp_dir, "fprintf");

    /* Write "5 five" to the file. */
    {
        FILE* stream;
        OE_TEST((stream = fopen(path, "w")));
        int n = fprintf(stream, "%d %s", 5, "five");
        OE_TEST(n == 6);
        OE_TEST(fclose(stream) == 0);
    }

    /* Read back the file. */
    {
        FILE* stream;
        int num;
        char str[16];

        OE_TEST((stream = fopen(path, "r")));
        int n = fscanf(stream, "%d %s", &num, str);
        OE_TEST(n == 2);
        OE_TEST(num = 5);
        OE_TEST(strcmp(str, "five") == 0);
        OE_TEST(fclose(stream) == 0);
    }
}

void _create_cpio_archive(const char* dirname, const char* archive)
{
    printf("DIRNAME{%s}\n", dirname);
    printf("ARCHIVE{%s}\n", archive);
}

void _test_mount(const char* tmp_dir)
{
    char target[OE_PATH_MAX];
    char source[OE_PATH_MAX];
    char path[OE_PATH_MAX];
    char pack_cpio[OE_PATH_MAX];
    char unpack_dir[OE_PATH_MAX];

    mkpath(source, tmp_dir, "source");
    mkpath(target, tmp_dir, "target");

    OE_TEST(oe_mount("/", "/", OE_DEVICE_NAME_HOST_FILE_SYSTEM, 0, NULL) == 0);
    oe_unlink(mkpath(path, source, "newfile"));
    oe_rmdir(source);
    oe_rmdir(target);

    OE_TEST(oe_mkdir(source, 0777) == 0);
    OE_TEST(oe_mkdir(target, 0777) == 0);
    OE_TEST(
        oe_mount(source, target, OE_DEVICE_NAME_HOST_FILE_SYSTEM, 0, NULL) ==
        0);

    _touch(mkpath(path, target, "file1"));
    _touch(mkpath(path, target, "file2"));
    OE_TEST(oe_mkdir(mkpath(path, target, "dir1"), 0777) == 0);
    _touch(mkpath(path, target, "dir1/file3"));

    {
        set<string> names;
        list(target, names);
        OE_TEST(names.find("file1") != names.end());
        OE_TEST(names.find("file2") != names.end());
        OE_TEST(names.find("nofile") == names.end());
    }

    mkpath(pack_cpio, tmp_dir, "pack.cpio");
    mkpath(unpack_dir, tmp_dir, "unpack.dir");

    OE_TEST(oe_cpio_pack(target, pack_cpio) == 0);

    OE_TEST(oe_cpio_unpack(pack_cpio, unpack_dir) == 0);

    OE_TEST(oe_cmp(target, unpack_dir) == 0);
    OE_TEST(oe_cmp(source, unpack_dir) == 0);

    OE_TEST(oe_umount(target) == 0);
    OE_TEST(oe_umount("/") == 0);
}

static void test_realpath(const char* tmp_dir)
{
    oe_syscall_path_t buf;

    printf("--- %s()\n", __FUNCTION__);

    OE_TEST(mount("/", "/", OE_DEVICE_NAME_HOST_FILE_SYSTEM, 0, NULL) == 0);

    OE_TEST(oe_realpath("/../../..", &buf));
    OE_TEST(strcmp(buf.buf, "/") == 0);

    char path_a[OE_PATH_MAX];
    char path_a_b[OE_PATH_MAX];
    char path_a_b_c[OE_PATH_MAX];

    mkpath(path_a, tmp_dir, "a");
    mkpath(path_a_b, tmp_dir, "a/b");
    mkpath(path_a_b_c, tmp_dir, "a/b/c");

    rmdir(path_a_b_c);
    rmdir(path_a_b);
    rmdir(path_a);

    OE_TEST(mkdir(path_a, 0777) == 0);
    OE_TEST(mkdir(path_a_b, 0777) == 0);
    OE_TEST(mkdir(path_a_b_c, 0777) == 0);

    OE_TEST(chdir(path_a_b_c) == 0);
    OE_TEST(getcwd(buf.buf, sizeof(buf.buf)));
    OE_TEST(strcmp(buf.buf, path_a_b_c) == 0);

    OE_TEST(oe_realpath("./.././../././", &buf));
    OE_TEST(strcmp(buf.buf, path_a) == 0);

    OE_TEST(chdir(tmp_dir) == 0);
    OE_TEST(getcwd(buf.buf, sizeof(buf)));
    OE_TEST(strcmp(buf.buf, tmp_dir) == 0);

    {
        struct stat st;
        OE_TEST(stat("./a", &st) == 0);
    }

    OE_TEST(chdir("/no/such/directory") == -1);

    OE_TEST(umount("/") == 0);
}

void test_zero_sized_iovs(void)
{
    struct oe_iovec iov;

    OE_TEST(oe_writev(OE_STDOUT_FILENO, &iov, 0) == 0);
    OE_TEST(oe_readv(OE_STDIN_FILENO, &iov, 0) == 0);
}

extern "C" void test_dup_case1(const char* tmp_dir)
{
    FILE* stream;

    printf("--- %s()\n", __FUNCTION__);

    OE_TEST(mount("/", "/", OE_DEVICE_NAME_HOST_FILE_SYSTEM, 0, NULL) == 0);

    /* Create and close a file. */
    int fd;
    {
        char path[OE_PATH_MAX];
        mkpath(path, tmp_dir, "dummy");
        fd = open(path, OE_O_CREAT | OE_O_TRUNC | OE_O_WRONLY, MODE);
        OE_TEST(fd >= 0);
        OE_TEST(close(fd) == 0);
    }

    OE_TEST(dup2(OE_STDERR_FILENO, fd) == fd);
    OE_TEST(close(OE_STDERR_FILENO) == 0);
    OE_TEST((stream = fdopen(fd, "w")));
    OE_TEST(dup2(fd, OE_STDERR_FILENO) == OE_STDERR_FILENO);
    fclose(stream);

    OE_TEST(umount("/") == 0);
}

extern "C" void test_dup_case2(const char* tmp_dir)
{
    char path[OE_PATH_MAX];
    int fd;

    printf("--- %s()\n", __FUNCTION__);

    OE_TEST(mount("/", "/", OE_DEVICE_NAME_HOST_FILE_SYSTEM, 0, NULL) == 0);

    /* Create a file named "STDOUT" */
    mkpath(path, tmp_dir, "STDOUT");
    fd = open(path, OE_O_CREAT | OE_O_TRUNC | OE_O_WRONLY, MODE);
    OE_TEST(fd >= 0);

    /* Close standard output. */
    int r = oe_close(OE_STDOUT_FILENO);
    OE_TEST(r == 0);

    /* Dup "STDOUT" file to STDOUT */
    OE_TEST(oe_dup2(fd, OE_STDOUT_FILENO) == OE_STDOUT_FILENO);

    OE_TEST(close(fd) == 0);

    OE_TEST(umount("/") == 0);
}

void test_fs(const char* src_dir, const char* tmp_dir)
{
    (void)src_dir;

    OE_TEST(oe_load_module_host_file_system() == OE_OK);
#if defined(TEST_SGXFS)
    OE_TEST(oe_load_module_sgx_file_system() == OE_OK);
#endif

    OE_TEST(oe_mkdir_d(OE_DEVID_HOST_FILE_SYSTEM, tmp_dir, 0777) == 0);

    printf("=== running common tests\n");
    printf("--- src_dir=%s\n", src_dir);
    printf("--- tmp_dir=%s\n", tmp_dir);

    /* Test the HOSTFS oe file descriptor interfaces. */
    {
        printf("=== testing oe-fd-hostfs:\n");

        oe_fd_hostfs_file_system fs;
        test_common(fs, tmp_dir);
    }

#if defined(TEST_SGXFS)
    /* Test the SGXFS oe file descriptor interfaces. */
    {
        printf("=== testing oe-fd-sgxfs:\n");

        oe_fd_sgxfs_file_system fs;
        test_common(fs, tmp_dir);
    }
#endif

    /* Test the HOSTFS standard C descriptor interfaces. */
    {
        printf("=== testing fd-hostfs:\n");

        fd_hostfs_file_system fs;
        test_common(fs, tmp_dir);
    }

#if defined(TEST_SGXFS)
    /* Test the SGXFS standard C descriptor interfaces. */
    {
        printf("=== testing fd-sgxfs:\n");

        fd_sgxfs_file_system fs;
        test_common(fs, tmp_dir);
    }
#endif

    /* Test stream I/O hostfs functions. */
    {
        printf("=== testing stream I/O hostfs functions:\n");

        stream_hostfs_file_system fs;
        test_common(fs, tmp_dir);
    }

#if defined(TEST_SGXFS)
    /* Test stream I/O sgxfs functions. */
    {
        printf("=== testing stream I/O sgxfs functions:\n");

        stream_sgxfs_file_system fs;
        test_common(fs, tmp_dir);
    }
#endif

    /* Test oe_set_thread_devid() */
    {
        printf("=== testing oe_set_thread_devid:\n");

        fd_file_system fs;
        device_registrant reg(OE_DEVID_HOST_FILE_SYSTEM);
        test_common(fs, tmp_dir);
    }

    /* Test reading from enclave relative path */
    {
        char path[OE_PATH_MAX];
        int fd;
        mkpath(path, tmp_dir, "testfile");

        // Create file in tmp dir
        OE_TEST(
            oe_mount("/", "/", OE_DEVICE_NAME_HOST_FILE_SYSTEM, 0, NULL) == 0);
        const int flags = OE_O_CREAT | OE_O_TRUNC | OE_O_WRONLY;
        OE_TEST((fd = oe_open(path, flags, MODE)) != -1);
        OE_TEST(close(fd) != -1);
        OE_TEST(oe_umount("/") == 0);

        // Open file in tmp dir using a relative path
        OE_TEST(
            oe_mount(
                tmp_dir, tmp_dir, OE_DEVICE_NAME_HOST_FILE_SYSTEM, 0, NULL) ==
            0);
        OE_TEST(oe_chdir(tmp_dir) == 0);
        OE_TEST((fd = oe_open("./testfile", OE_O_RDONLY, MODE)) != -1);
        OE_TEST(close(fd) != -1);
        OE_TEST(oe_umount(tmp_dir) == 0);

        // Change workdir back for other tests.
        OE_TEST(
            oe_mount("/", "/", OE_DEVICE_NAME_HOST_FILE_SYSTEM, 0, NULL) == 0);
        OE_TEST(oe_chdir("/") == 0);
        OE_TEST(oe_umount("/") == 0);
    }

    /* Test writing to a read-only mounted file system. */
    {
        char path[OE_PATH_MAX];
        mkpath(path, tmp_dir, "somefile");
        const int flags = OE_O_CREAT | OE_O_TRUNC | OE_O_WRONLY;

        // Create file
        OE_TEST(
            oe_mount(
                "/",
                "/",
                OE_DEVICE_NAME_HOST_FILE_SYSTEM,
                OE_MS_RDONLY,
                NULL) == 0);

        OE_TEST(oe_open(path, flags, MODE) == -1);
        OE_TEST(oe_errno == EPERM);

        OE_TEST(oe_umount("/") == 0);
    }

    /* Write the standard output and standard error. */
    {
        static const char DATA[] = "abcdefghijklmnopqrstuvwxyz\n";
        static const size_t n = sizeof(DATA) - 1;
        OE_TEST(oe_write(OE_STDOUT_FILENO, DATA, n) == n);
        OE_TEST(oe_write(OE_STDERR_FILENO, DATA, n) == n);
    }

    /* Test mounting. */
    _test_mount(tmp_dir);

    /* Test fprintf and fscanf. */
    test_fprintf_fscanf(tmp_dir);

    /* Test getcwd() */
    {
        char buf[OE_PATH_MAX];
        OE_TEST(oe_getcwd(buf, sizeof(buf)));
        OE_TEST(strcmp(buf, "/") == 0);
    }

    test_realpath(tmp_dir);

    test_zero_sized_iovs();

    /* Note: these must come last since they change STDOUT and STDERR. */
    test_dup_case1(tmp_dir);
    test_dup_case2(tmp_dir);
}

void test_fs_linux(const char* src_dir, const char* tmp_dir)
{
    (void)src_dir;

    OE_TEST(oe_load_module_host_file_system() == OE_OK);
#if defined(TEST_SGXFS)
    OE_TEST(oe_load_module_sgx_file_system() == OE_OK);
#endif

    OE_TEST(oe_mkdir_d(OE_DEVID_HOST_FILE_SYSTEM, tmp_dir, 0777) == 0);

    printf("=== running Linux-specific tests\n");
    printf("--- src_dir=%s\n", src_dir);
    printf("--- tmp_dir=%s\n", tmp_dir);

    /* Test the HOSTFS oe file descriptor interfaces. */
    {
        printf("=== testing oe-fd-hostfs:\n");

        oe_fd_hostfs_file_system fs;
        test_pio(fs, tmp_dir);
    }

#if defined(TEST_SGXFS)
    /* Test the SGXFS oe file descriptor interfaces. */
    {
        printf("=== testing oe-fd-sgxfs:\n");

        oe_fd_sgxfs_file_system fs;
        test_pio(fs, tmp_dir);
    }
#endif

    /* Test the HOSTFS standard C descriptor interfaces. */
    {
        printf("=== testing fd-hostfs:\n");

        fd_hostfs_file_system fs;
        test_pio(fs, tmp_dir);
    }

#if defined(TEST_SGXFS)
    /* Test the SGXFS standard C descriptor interfaces. */
    {
        printf("=== testing fd-sgxfs:\n");

        fd_sgxfs_file_system fs;
        test_pio(fs, tmp_dir);
    }
#endif

    /* Test stream I/O hostfs functions. */
    {
        printf("=== testing stream I/O hostfs functions:\n");

        stream_hostfs_file_system fs;
        test_pio(fs, tmp_dir);
    }

#if defined(TEST_SGXFS)
    /* Test stream I/O sgxfs functions. */
    {
        printf("=== testing stream I/O sgxfs functions:\n");

        stream_sgxfs_file_system fs;
        test_pio(fs, tmp_dir);
    }
#endif

    /* Test oe_set_thread_devid() */
    {
        printf("=== testing oe_set_thread_devid:\n");

        fd_file_system fs;
        device_registrant reg(OE_DEVID_HOST_FILE_SYSTEM);
        test_pio(fs, tmp_dir);
    }
}
OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
