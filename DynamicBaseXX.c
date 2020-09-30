// Usage (encryption): DynamicBaseXX -C/c plaintext.file ciphertext.file password
// Usage (decryption): DynamicBaseXX -P/p ciphertext.file plaintext.file password
// Compiled on MacOS, Linux and *BSD in X86_64 platform.
// Talk is SO EASY, show you my GOD.
// Simple is beautiful.

#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// also Base32 encoding, Base16 encoding
// Each value of 64 numbers of encoded table that you can set randomly, but the value is no more than 256.
unsigned char aucBase64Encode[64] = {
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
    97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 43, 47};

// also Base32 decoding, Base16 decoding
// It's for easy decoding.
unsigned char aucBase64Decode[123] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62, 255, 255, 255, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255, 255, 255, 255,
    255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255,
    255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51};

// generate random number of "JunTai" distribution
void JunTai(unsigned char *pucPassword, unsigned long ulPasswordLength)
{
// encoded table convert 64 bytes of data at a time in order to generate the random number of "JunTai" distribution
    for(unsigned long i = 0; i < 64; ++i)
    {
        unsigned char ucIndex, ucTemp;

        ucIndex = pucPassword[i % ulPasswordLength] % 64;

        ucTemp = aucBase64Encode[i];

        aucBase64Encode[i] = aucBase64Encode[ucIndex];

        aucBase64Encode[ucIndex] = ucTemp;
    }
}

void changePassword(unsigned char *pucPassword, unsigned long ulPasswordLength)
{
// use encoded table's value to change the password
    for(unsigned long j = 0; j < ulPasswordLength; ++j)
    {
        pucPassword[j] = aucBase64Encode[pucPassword[j] % 64];
    }
}

void Encrypt(char *argv[])
{
// any password length
    unsigned long ulPasswordLength = -1;

// get password length
    while(argv[2][++ulPasswordLength]);

    struct stat statFileSize;

    stat(argv[0], &statFileSize);

// get the plaintext length and ciphertext length
    unsigned long ulPlaintextLength = statFileSize.st_size, ulCiphertextLength = ulPlaintextLength % 3 ? 4 * (ulPlaintextLength / 3 + 1) : 4 * ulPlaintextLength / 3;

// allocate storage space
    unsigned char *pucPlaintext = (unsigned char*)malloc(ulPlaintextLength), *pucCiphertext = (unsigned char*)malloc(ulCiphertextLength);

// open plaintext file
    int iPlaintextOrCiphertext = open(argv[0], O_RDONLY, S_IRUSR | S_IWUSR);

// read data from plaintext file
    read(iPlaintextOrCiphertext, pucPlaintext, ulPlaintextLength);

    close(iPlaintextOrCiphertext);

// magic
    pucPlaintext[ulPlaintextLength] = 0;

// process plaintext data
    for(unsigned long i = 0, k = 0; i < ulPlaintextLength; i += 12)
    {
        JunTai((unsigned char*)argv[2], ulPasswordLength);

// encode Base64
        for(unsigned long j = 0; j < 12 && i + j < ulPlaintextLength; j += 3, k += 4)
        {
            unsigned int *puiPlaintext = (unsigned int*)(pucPlaintext + i + j);

            pucCiphertext[k] = aucBase64Encode[*puiPlaintext & 0x3f];

            pucCiphertext[k + 1] = aucBase64Encode[*puiPlaintext >> 6 & 0x3f];

            pucCiphertext[k + 2] = aucBase64Encode[*puiPlaintext >> 12 & 0x3f];

            pucCiphertext[k + 3] = aucBase64Encode[*puiPlaintext >> 18 & 0x3f];
        }

        changePassword((unsigned char*)argv[2], ulPasswordLength);
    }

// Missing 1 byte or 2 bytes of finishing processing according to Base64 coding rules.
    if(ulPlaintextLength % 3 > 0)
    {
        pucCiphertext[ulCiphertextLength - 1] = '=';

        if(ulPlaintextLength % 3 == 1)
        {
            pucCiphertext[ulCiphertextLength - 2] = '=';
        }
    }

// open ciphertext file
    iPlaintextOrCiphertext = open(argv[1], O_CREAT | O_WRONLY, S_IREAD | S_IWRITE);

// write data to ciphertext file
    write(iPlaintextOrCiphertext, pucCiphertext, ulCiphertextLength);

    close(iPlaintextOrCiphertext);

    free(pucCiphertext);

    free(pucPlaintext);
}

void Decrypt(char *argv[])
{
// any password length
    unsigned long ulPasswordLength = -1;

// get password length
    while(argv[2][++ulPasswordLength]);

    struct stat statFileSize;

    stat(argv[0], &statFileSize);

// get the ciphertext length and the plaintext length
    unsigned long ulCiphertextLength = statFileSize.st_size, ulPlaintextLength = 3 * ulCiphertextLength / 4;

// allocate storage space
    unsigned char *pucCiphertext = (unsigned char*)malloc(ulCiphertextLength), *pucPlaintext = (unsigned char*)malloc(ulPlaintextLength);

// open ciphertext file
    int iCiphertextOrPlaintext = open(argv[0], O_RDONLY, S_IRUSR | S_IWUSR);

// read data from ciphertext file
    read(iCiphertextOrPlaintext, pucCiphertext, ulCiphertextLength);

    close(iCiphertextOrPlaintext);

// process ciphertext data
    for(unsigned long i = 0, k = 0; i < ulCiphertextLength; i += 16)
    {
        JunTai((unsigned char*)argv[2], ulPasswordLength);

// decoded table transformations
        for(unsigned long l = 0; l < 64; ++l)
        {
            aucBase64Decode[aucBase64Encode[l]] = l;
        }

// decode Base64
        for(unsigned long j = 0; j < 16 && i + j < ulCiphertextLength; j += 4, k += 3)
        {
            pucPlaintext[k] = aucBase64Decode[pucCiphertext[i + j]] | aucBase64Decode[pucCiphertext[i + j + 1]] << 6;

            pucPlaintext[k + 1] = aucBase64Decode[pucCiphertext[i + j + 1]] >> 2 | aucBase64Decode[pucCiphertext[i + j + 2]] << 4;

            pucPlaintext[k + 2] = aucBase64Decode[pucCiphertext[i + j + 2]] >> 4 | aucBase64Decode[pucCiphertext[i + j + 3]] << 2;
        }

        changePassword((unsigned char*)argv[2], ulPasswordLength);
    }

// More than 1 byte or 2 bytes of finishing processing according to Base64 coding rules.
    if(pucCiphertext[ulCiphertextLength - 2] == '=')
    {
        ulPlaintextLength -= 2;
    }
    else if(pucCiphertext[ulCiphertextLength - 1] == '=')
    {
        --ulPlaintextLength;
    }

// open plaintext file
    iCiphertextOrPlaintext = open(argv[1], O_CREAT | O_WRONLY, S_IREAD | S_IWRITE);

// write data to plaintext file
    write(iCiphertextOrPlaintext, pucPlaintext, ulPlaintextLength);

    close(iCiphertextOrPlaintext);

    free(pucPlaintext);

    free(pucCiphertext);
}

int main(int argc, char *argv[])
{
    if(argv[1][0] == '-')
    {
        if(argv[1][1] == 'C' || argv[1][1] == 'c')
        {
            Encrypt(argv + 2);
        }
        else if(argv[1][1] == 'P' || argv[1][1] == 'p')
        {
            Decrypt(argv + 2);
        }
    }

    return 0;
}
