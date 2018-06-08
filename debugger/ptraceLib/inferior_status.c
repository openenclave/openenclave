// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "inferior_status.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <sys/wait.h>

typedef struct _OE_Inferior_Info
{
    struct _OE_Inferior_Info* next;
    pid_t pid;
    int64_t flags;
} OE_Inferior_Info;

static OE_Inferior_Info* g_inferior_info_head = NULL;
static pthread_mutex_t inferior_info_lock;

int _OE_TrackInferior(pid_t pid)
{
    int ret = -1;
    pthread_mutex_lock(&inferior_info_lock);

    // Check if the inferior is already in the track list.
    OE_Inferior_Info* inferior_info = g_inferior_info_head;
    while (inferior_info != NULL)
    {
        if (inferior_info->pid == pid)
        {
            goto cleanup;
        }

        inferior_info = inferior_info->next;
    }

    // Allocate a new node.
    inferior_info = (OE_Inferior_Info*)malloc(sizeof(OE_Inferior_Info));
    if (inferior_info == NULL)
    {
        goto cleanup;
    }
    memset(inferior_info, 0, sizeof(OE_Inferior_Info));
    inferior_info->pid = pid;

    // Insert new node at the beginning of the track list.
    inferior_info->next = g_inferior_info_head;
    g_inferior_info_head = inferior_info;
    ret = 0;

cleanup:
    pthread_mutex_unlock(&inferior_info_lock);
    return ret;
}

int _OE_UntrackInferior(pid_t pid)
{
    int ret = -1;
    pthread_mutex_lock(&inferior_info_lock);

    OE_Inferior_Info* prev_inferior_info = NULL;
    OE_Inferior_Info* cur_inferior_info = g_inferior_info_head;

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
** _OE_GetInferiorFlags()
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

int _OE_GetInferiorFlags(pid_t pid, int64_t* flags)
{
    int ret = -1;
    pthread_mutex_lock(&inferior_info_lock);

    OE_Inferior_Info* inferior_info = g_inferior_info_head;
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
** _OE_SetInferiorFlags()
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

int _OE_SetInferiorFlags(pid_t pid, int64_t flags)
{
    int ret = -1;
    pthread_mutex_lock(&inferior_info_lock);

    OE_Inferior_Info* inferior_info = g_inferior_info_head;
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