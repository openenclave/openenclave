#ifndef __ELIBC_ENDIAN_H
#define __ELIBC_ENDIAN_H

#include <features.h>
#include <bits/alltypes.h>

#ifndef __BYTE_ORDER__
# error "__BYTE_ORDER__ undefined"
#endif

#define BYTE_ORDER __BYTE_ORDER__
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321

__ELIBC_BEGIN

__ELIBC_INLINE uint16_t __bswap16(uint16_t x)
{
    return
        ((uint16_t)((x & 0x00FF) << 8)) |
        ((uint16_t)((x & 0xFF00) >> 8));
}

__ELIBC_INLINE uint32_t __bswap32(uint32_t x)
{
    return
        ((uint32_t)((x & 0x000000FF) << 24)) |
        ((uint32_t)((x & 0x0000FF00) << 8)) |
        ((uint32_t)((x & 0x00FF0000) >> 8)) |
        ((uint32_t)((x & 0xFF000000) >> 24));
}

__ELIBC_INLINE uint64_t __bswap64(uint64_t x)
{
    return 
        ((uint64_t)((x & 0xFF) << 56)) |
        ((uint64_t)((x & 0xFF00) << 40)) |
        ((uint64_t)((x & 0xFF0000) << 24)) |
        ((uint64_t)((x & 0xFF000000) << 8)) |
        ((uint64_t)((x & 0xFF00000000) >> 8)) |
        ((uint64_t)((x & 0xFF0000000000) >> 24)) |
        ((uint64_t)((x & 0xFF000000000000) >> 40)) |
        ((uint64_t)((x & 0xFF00000000000000) >> 56));
}

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define htobe16(x) __bswap16(x)
# define be16toh(x) __bswap16(x)
# define betoh16(x) __bswap16(x)
# define htobe32(x) __bswap32(x)
# define be32toh(x) __bswap32(x)
# define betoh32(x) __bswap32(x)
# define htobe64(x) __bswap64(x)
# define be64toh(x) __bswap64(x)
# define betoh64(x) __bswap64(x)
# define htole16(x) (uint16_t)(x)
# define le16toh(x) (uint16_t)(x)
# define letoh16(x) (uint16_t)(x)
# define htole32(x) (uint32_t)(x)
# define le32toh(x) (uint32_t)(x)
# define letoh32(x) (uint32_t)(x)
# define htole64(x) (uint64_t)(x)
# define le64toh(x) (uint64_t)(x)
# define letoh64(x) (uint64_t)(x)
#else
# define htobe16(x) (uint16_t)(x)
# define be16toh(x) (uint16_t)(x)
# define betoh16(x) (uint16_t)(x)
# define htobe32(x) (uint32_t)(x)
# define be32toh(x) (uint32_t)(x)
# define betoh32(x) (uint32_t)(x)
# define htobe64(x) (uint64_t)(x)
# define be64toh(x) (uint64_t)(x)
# define betoh64(x) (uint64_t)(x)
# define htole16(x) __bswap16(x)
# define le16toh(x) __bswap16(x)
# define letoh16(x) __bswap16(x)
# define htole32(x) __bswap32(x)
# define le32toh(x) __bswap32(x)
# define letoh32(x) __bswap32(x)
# define htole64(x) __bswap64(x)
# define le64toh(x) __bswap64(x)
# define letoh64(x) __bswap64(x)
#endif

__ELIBC_END

#endif /* __ELIBC_ENDIAN_H */
