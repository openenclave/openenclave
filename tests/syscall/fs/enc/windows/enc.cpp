// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../enc_shared.cpp"

template <class FILE_SYSTEM>
void test_all(FILE_SYSTEM& fs, const char* tmp_dir)
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
