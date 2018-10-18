
/*
 *  Copyright (C) 2001-2003 Hewlett-Packard Co.
 *      Contributed by Stephane Eranian <eranian@hpl.hp.com>
 *
 *  Copyright (C) 2001 Silicon Graphics, Inc.
 *      Contributed by Brent Casavant <bcasavan@sgi.com>
 *
 *  Copyright (C) 2006-2009 Intel Corporation
 *      Contributed by Fenghua Yu <fenghua.yu@intel.com>
 *      Contributed by Bibo Mao <bibo.mao@intel.com>
 *      Contributed by Chandramouli Narayanan <mouli@linux.intel.com>
 *
 * This file is part of the ELILO, the EFI Linux boot loader.
 *
 *  ELILO is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  ELILO is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ELILO; see the file COPYING.  If not, write to the Free
 *  Software Foundation, 59 Temple Place - Suite 330, Boston, MA
 *  02111-1307, USA.
 *
 * Please check out the elilo.txt for complete documentation on how
 * to use this program.
 */


#include <efi.h>
#include <efilib.h>
#include <argify.h>



#define	MAX_ARGS 256

#define CHAR_SPACE L' '

#define DEBUG 0

INTN
argify(CHAR16 *buf, UINTN len, CHAR16 **argv)   
{

        UINTN     i=0, j=0;
        CHAR16   *p = buf;
	
        if (buf == 0) { 
		argv[0] = NULL;
		return 0;
	}
	/* len represents the number of bytes, not the number of 16 bytes chars */
	len = len >> 1;

	/*
	 * Here we use CHAR_NULL as the terminator rather than the length
	 * because it seems like the EFI shell return rather bogus values for it.
	 * Apparently, we are guaranteed to find the '\0' character in the buffer
	 * where the real input arguments stop, so we use it instead.
	 */
	for(;;) {
		while (buf[i] == CHAR_SPACE && buf[i] != CHAR_NULL && i < len) i++;

		if (buf[i] == CHAR_NULL || i == len) goto end;

		p = buf+i;
		i++;

		while (buf[i] != CHAR_SPACE && buf[i] != CHAR_NULL && i < len) i++;

		argv[j++] = p;

		if (buf[i] == CHAR_NULL) goto end;

		buf[i]  = CHAR_NULL;

		if (i == len)  goto end;

		i++;

		if (j == MAX_ARGS-1) {
			Print(L"too many arguments (%d) truncating\n", j);
			goto end;
		}
	}
end:
        argv[j] = NULL;
	return j;
}

