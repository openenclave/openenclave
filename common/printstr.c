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
                    printf("\\%03o", (unsigned int)c);
                    break;
            }
        }
    }

    printf("\"");
}
