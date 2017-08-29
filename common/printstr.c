static void FUNCTION(
    const TYPE* str,
    size_t len)
{
    size_t i;

    PRINTF("%s", PREFIX);
    PRINTF("\"");

    for (i = 0; *str && i < len; str++)
    {
        TYPE c = *str;

        if (isprint(c))
        {
            PRINTF(FORMAT, c);
        }
        else
        {
            switch (c)
            {
                case '\r':
                    PRINTF("\\r");
                    break;
                case '\n':
                    PRINTF("\\n");
                    break;
                case '\t':
                    PRINTF("\\t");
                    break;
                case '\f':
                    PRINTF("\\f");
                    break;
                case '\b':
                    PRINTF("\\b");
                    break;
                case '\a':
                    PRINTF("\\a");
                    break;
                default:
                    PRINTF("\\%03o", (unsigned int)c);
                    break;
            }
        }
    }

    PRINTF("\"");
}
