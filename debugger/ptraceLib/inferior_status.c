// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "inferior_status.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <sys/wait.h>

typedef struct _sgx_inferior_info
{
    struct _sgx_inferior_info* next;
    pid_t pid;
    int64_t flags;
} sgx_inferior_info_t;

static sgx_inferior_info_t* g_inferior_info_head = NULL;
static pthread_mutex_t inferior_info_lock;

int sgx_track_inferior(pid_t pid)
{
    int ret = -1;
    pthread_mutex_lock(&inferior_info_lock);

    // Check if the inferior is already in the track list.
    sgx_inferior_info_t* inferior_info = g_inferior_info_head;
    while (inferior_info != NULL)
    {
        if (inferior_info->pid == pid)
        {
            goto cleanup;
        }

        inferior_info = inferior_info->next;
    }

    // Allocate a new node.
    inferior_info = (sgx_inferior_info_t*)malloc(sizeof(sgx_inferior_info_t));
    if (inferior_info == NULL)
    {
        goto cleanup;
    }
    memset(inferior_info, 0, sizeof(sgx_inferior_info_t));
    inferior_info->pid = pid;

    // Insert new node at the beginning of the track list.
    inferior_info->next = g_inferior_info_head;
    g_inferior_info_head = inferior_info;
    ret = 0;

cleanup:
    pthread_mutex_unlock(&inferior_info_lock);
    return ret;
}

int sgx_untrack_inferior(pid_t pid)
{
    int ret = -1;
    pthread_mutex_lock(&inferior_info_lock);

    sgx_inferior_info_t* prev_inferior_info = NULL;
    sgx_inferior_info_t* cur_inferior_info = g_inferior_info_head;

    while (cur_inferior_info != NULL)
    {
        if (cur_inferior_info->pid != pid)
        {
            prev_inferior_info = cur_inferior_info;
            cur_inferior_info = cur_inferior_info->next;
            continue;
        }

        if (prev_inferior_info != NULL)
        {
            prev_inferior_info->next = cur_inferior_info->next;
        }
        else
        {
            g_inferior_info_head = cur_inferior_info->next;
        }

        free(cur_inferior_info);
        ret = 0;
        goto cleanup;
    }

cleanup:
    pthread_mutex_unlock(&inferior_info_lock);
    return ret;
}

/*
**==============================================================================
**
** sgx_get_inferior_flags()
**
**     This function is used to get the flags of a tracked inferior.
**
** Parameters:
**     pid - The process ID.
**     flags - A pointer to receive the flags.
**
** Returns:
**     0 - Success.
**     -1 - Failure.
**
**==============================================================================
*/

int sgx_get_inferior_flags(pid_t pid, int64_t* flags)
{
    int ret = -1;
    pthread_mutex_lock(&inferior_info_lock);

    sgx_inferior_info_t* inferior_info = g_inferior_info_head;
    while (inferior_info != NULL)
    {
        if (inferior_info->pid == pid)
        {
            *flags = inferior_info->flags;
            ret = 0;
            goto cleanup;
        }

        inferior_info = inferior_info->next;
    }

cleanup:
    pthread_mutex_unlock(&inferior_info_lock);
    return ret;
}

/*
**==============================================================================
**
** sgx_set_inferior_flags()
**
**     This function is used to set the flags of a tracked inferior.
**
** Parameters:
**     pid - The process ID.
**     flags - The new flags.
**
** Returns:
**     0 - Success.
**     -1 - Failure.
**
**==============================================================================
*/

int sgx_set_inferior_flags(pid_t pid, int64_t flags)
{
    int ret = -1;
    pthread_mutex_lock(&inferior_info_lock);

    sgx_inferior_info_t* inferior_info = g_inferior_info_head;
    while (inferior_info != NULL)
    {
        if (inferior_info->pid == pid)
        {
            inferior_info->flags = flags;
            ret = 0;
            goto cleanup;
        }

        inferior_info = inferior_info->next;
    }

cleanup:
    pthread_mutex_unlock(&inferior_info_lock);
    return ret;
}
