#ifndef _OE_INFERIOR_STATUS_H_
#define _OE_INFERIOR_STATUS_H_

typedef enum _OE_Inferior_Flags {
    OE_INFERIOR_SINGLE_STEP = 0X1
} OE_Inferior_Flags;

int _OE_TrackInferior(pid_t pid);

int _OE_UntrackInferior(pid_t pid);

int _OE_GetInferiorFlags(pid_t pid, long* flags);

int _OE_SetInferiorFlags(pid_t pid, long flags);

#endif