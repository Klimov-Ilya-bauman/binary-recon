#include "hashes.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <vector>

namespace {

// =============================================================================
//                     ВСПОМОГАТЕЛЬНЫЕ УТИЛИТЫ
// =============================================================================

/**
 * Циклический сдвиг 32-битного значения влево на n позиций.
 * Базовая операция в большинстве хеш-функций.
 *
 * Пример: rotl32(0x12345678, 8) == 0x34567812
 *
 * Маска (n & 31) защищает от undefined behavior при n >= 32.
 */
inline uint32_t rotl32(uint32_t x, uint32_t n) {
    return (x << (n & 31)) | (x >> ((32 - n) & 31));
}

/**
 * Циклический сдвиг 32-битного значения вправо на n позиций.
 * Используется в SHA-256.
 */
inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> (n & 31)) | (x << ((32 - n) & 31));
}

/**
 * Преобразование байтового массива в hex-строку нижнего регистра.
 * Для каждого байта печатает 2 hex-символа с ведущими нулями.
 */
std::string toHex(const uint8_t* data, size_t length) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

// =============================================================================
//                              MD5 (RFC 1321)
// =============================================================================
//
// Размер блока:    512 бит (64 байта)
// Размер состояния: 128 бит (4 регистра по 32 бита: A, B, C, D)
// Раундов:         64 (4 группы по 16, у каждой группы своя F-функция)
// Размер дайджеста: 128 бит = 16 байт = 32 hex-символа
//
// Структура раунда:
//   A = B + ROTL(A + F(B,C,D) + M[g] + K[i], s[i])
//   потом сдвиг регистров: D ← C ← B ← A (с переименованием)
//
// =============================================================================

// Сдвиги для каждого из 64 раундов (см. RFC 1321 секция 3.4).
constexpr uint32_t MD5_S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

// Константы K[i] для раундов. Получены как floor(2^32 × |sin(i+1)|),
// где i — номер раунда от 0 до 63, аргумент sin в радианах.
// Гарантируют отсутствие математических закономерностей в константах
// (так называемые "nothing-up-my-sleeve numbers").
constexpr uint32_t MD5_K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

// Начальные значения регистров (IV — initialization vector).
// Заданы константно в спецификации.
constexpr uint32_t MD5_INIT_A = 0x67452301;
constexpr uint32_t MD5_INIT_B = 0xefcdab89;
constexpr uint32_t MD5_INIT_C = 0x98badcfe;
constexpr uint32_t MD5_INIT_D = 0x10325476;

/**
 * Обработка одного 512-битного блока.
 * Изменяет состояние [a, b, c, d] на месте.
 */
void md5ProcessBlock(uint32_t state[4], const uint8_t block[64]) {
    // Распаковываем блок в 16 little-endian uint32_t слов.
    uint32_t M[16];
    for (int i = 0; i < 16; ++i) {
        M[i] = static_cast<uint32_t>(block[i * 4 + 0])
             | (static_cast<uint32_t>(block[i * 4 + 1]) << 8)
             | (static_cast<uint32_t>(block[i * 4 + 2]) << 16)
             | (static_cast<uint32_t>(block[i * 4 + 3]) << 24);
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];

    // 64 раунда сжатия. Логика из RFC 1321 секция 3.4.
    for (int i = 0; i < 64; ++i) {
        uint32_t f;
        uint32_t g;  // индекс слова M[g] для этого раунда

        if (i < 16) {
            // Раунды 0-15: F(B,C,D) = (B AND C) OR (NOT B AND D)
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            // Раунды 16-31: G(B,C,D) = (D AND B) OR (NOT D AND C)
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            // Раунды 32-47: H(B,C,D) = B XOR C XOR D
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            // Раунды 48-63: I(B,C,D) = C XOR (B OR NOT D)
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }

        // Основное преобразование раунда.
        const uint32_t temp = d;
        d = c;
        c = b;
        b = b + rotl32(a + f + MD5_K[i] + M[g], MD5_S[i]);
        a = temp;
    }

    // Прибавляем результат к текущему состоянию (Davies-Meyer construction).
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

// =============================================================================
//                           SHA-256 (FIPS 180-4)
// =============================================================================
//
// Размер блока:     512 бит (64 байта)  — как у MD5
// Размер состояния:  256 бит (8 регистров H0..H7)
// Раундов:          64
// Размер дайджеста: 256 бит = 32 байта = 64 hex-символа
//
// =============================================================================

// Константы K[i] — первые 32 бита дробных частей кубических корней
// первых 64 простых чисел (2, 3, 5, 7, 11, ..., 311).
constexpr uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Начальные значения H[0..7] — первые 32 бита дробных частей квадратных
// корней первых 8 простых чисел (2, 3, 5, 7, 11, 13, 17, 19).
constexpr uint32_t SHA256_INIT[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/**
 * Обработка одного 512-битного блока для SHA-256.
 */
void sha256ProcessBlock(uint32_t state[8], const uint8_t block[64]) {
    // Расширение блока в 64 слова (W[0..63]).
    // W[0..15] — это сам блок, прочитанный как big-endian uint32_t.
    uint32_t W[64];
    for (int i = 0; i < 16; ++i) {
        W[i] = (static_cast<uint32_t>(block[i * 4 + 0]) << 24)
             | (static_cast<uint32_t>(block[i * 4 + 1]) << 16)
             | (static_cast<uint32_t>(block[i * 4 + 2]) << 8)
             | (static_cast<uint32_t>(block[i * 4 + 3]));
    }
    // W[16..63] — генерируются из предыдущих по специальной формуле.
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = rotr32(W[i - 15], 7) ^ rotr32(W[i - 15], 18) ^ (W[i - 15] >> 3);
        const uint32_t s1 = rotr32(W[i - 2], 17) ^ rotr32(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    // Рабочие переменные.
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    // 64 раунда сжатия.
    for (int i = 0; i < 64; ++i) {
        const uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t temp1 = h + S1 + ch + SHA256_K[i] + W[i];

        const uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // Прибавляем к состоянию.
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// =============================================================================
//                       PADDING (общий для MD5 и SHA-256)
// =============================================================================
//
// Обе функции дополняют сообщение по схеме Меркла-Дамгарда:
//   1. Добавить байт 0x80 (бит '1' за которым нули).
//   2. Добавить нули до тех пор, пока (длина_в_байтах mod 64) == 56.
//   3. Добавить 8 байт — длину ОРИГИНАЛЬНОГО сообщения В БИТАХ.
//
// Различия:
//   - MD5     записывает длину как little-endian uint64_t.
//   - SHA-256 записывает длину как big-endian uint64_t.
//
// =============================================================================

std::vector<uint8_t> padMessage(const uint8_t* data, size_t length, bool bigEndian) {
    const uint64_t bitLength = static_cast<uint64_t>(length) * 8;

    // Размер с padding'ом: исходные байты + 0x80 + zeros + 8 байт длины,
    // выровненный до кратного 64.
    size_t paddedLen = length + 1;  // +1 байт для 0x80
    while (paddedLen % 64 != 56) {
        paddedLen++;
    }
    paddedLen += 8;  // для длины

    std::vector<uint8_t> padded(paddedLen, 0);
    std::memcpy(padded.data(), data, length);
    padded[length] = 0x80;

    // Записываем длину в битах в последние 8 байт.
    if (bigEndian) {
        for (int i = 0; i < 8; ++i) {
            padded[paddedLen - 1 - i] = static_cast<uint8_t>((bitLength >> (i * 8)) & 0xff);
        }
    } else {
        for (int i = 0; i < 8; ++i) {
            padded[paddedLen - 8 + i] = static_cast<uint8_t>((bitLength >> (i * 8)) & 0xff);
        }
    }

    return padded;
}

} // anonymous namespace

// =============================================================================
//                          ПУБЛИЧНЫЙ ИНТЕРФЕЙС
// =============================================================================

std::string Hashes::md5(const uint8_t* data, size_t length) {
    // Padding (little-endian для длины — особенность MD5).
    const std::vector<uint8_t> padded = padMessage(data, length, /*bigEndian=*/false);

    // Инициализация состояния.
    uint32_t state[4] = {MD5_INIT_A, MD5_INIT_B, MD5_INIT_C, MD5_INIT_D};

    // Обработка блок за блоком.
    for (size_t offset = 0; offset < padded.size(); offset += 64) {
        md5ProcessBlock(state, padded.data() + offset);
    }

    // Сериализация состояния в little-endian байтовый массив.
    uint8_t digest[16];
    for (int i = 0; i < 4; ++i) {
        digest[i * 4 + 0] = static_cast<uint8_t>(state[i] & 0xff);
        digest[i * 4 + 1] = static_cast<uint8_t>((state[i] >> 8) & 0xff);
        digest[i * 4 + 2] = static_cast<uint8_t>((state[i] >> 16) & 0xff);
        digest[i * 4 + 3] = static_cast<uint8_t>((state[i] >> 24) & 0xff);
    }

    return toHex(digest, 16);
}

std::string Hashes::sha256(const uint8_t* data, size_t length) {
    // Padding (big-endian для длины — особенность SHA-256).
    const std::vector<uint8_t> padded = padMessage(data, length, /*bigEndian=*/true);

    // Инициализация состояния.
    uint32_t state[8];
    std::memcpy(state, SHA256_INIT, sizeof(state));

    // Обработка блоков.
    for (size_t offset = 0; offset < padded.size(); offset += 64) {
        sha256ProcessBlock(state, padded.data() + offset);
    }

    // Сериализация в big-endian.
    uint8_t digest[32];
    for (int i = 0; i < 8; ++i) {
        digest[i * 4 + 0] = static_cast<uint8_t>((state[i] >> 24) & 0xff);
        digest[i * 4 + 1] = static_cast<uint8_t>((state[i] >> 16) & 0xff);
        digest[i * 4 + 2] = static_cast<uint8_t>((state[i] >> 8) & 0xff);
        digest[i * 4 + 3] = static_cast<uint8_t>(state[i] & 0xff);
    }

    return toHex(digest, 32);
}
