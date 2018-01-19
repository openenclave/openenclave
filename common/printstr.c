/**
 * This file is only intended as an include into typeinfo.c for 
 * defining char and wchar_t strings in the absence of templates in C.
 * FUNCTION, TYPE, PREFIX and FORMAT are all expected to be macro substitutions.
 */
static void FUNCTION(
    const TYPE* str,
    size_t len)
{
    size_t i;

    printf("%s", PREFIX);
    printf("\"");

    for (i = 0; *str && i < len; str++)
    {
        TYPE c = *str;

        if (isprint(c))
        {
            printf(FORMAT, c);
        }
        else
        {
            switch (c)
            {
                case '\r':
                    printf("\\r");
                    break;
                case '\n':
                    printf("\\n");
                    break;
                case '\t':
                    printf("\\t");
                    break;
                case '\f':
                    printf("\\f");
                    break;
                case '\b':
                    printf("\\b");
                    break;
                case '\a':
                    printf("\\a");
                    break;
                default:
                    printf("\\%03o", (uint32_t)c);
                    break;
            }
        }
    }

    printf("\"");
}
