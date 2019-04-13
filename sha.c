// SHA1 algorithm
// RFC: https://tools.ietf.org/pdf/rfc3174.pdf
// German Wiki: https://de.wikipedia.org/wiki/Secure_Hash_Algorithm
// Good Explanation: https://brilliant.org/wiki/secure-hashing-algorithms/
// Good Inspiration: http://www.hoozi.com/posts/secure-hash-algorithm-sha-1-reference-implementation-in-cc-with-comments-2/
// Holy Moly: https://github.com/clibs/sha1/blob/master/sha1.c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>


#define MAGIC_COOKIE_1 0x5A827999
#define MAGIC_COOKIE_2 0x6ED9EBA1
#define MAGIC_COOKIE_3 0x8F1BBCDC
#define MAGIC_COOKIE_4 0xCA62C1D6

#define MAGIC_INPUT_COOKIE_0 0x67452301
#define MAGIC_INPUT_COOKIE_1 0xEFCDAB89
#define MAGIC_INPUT_COOKIE_2 0x98BADCFE
#define MAGIC_INPUT_COOKIE_3 0x10325476
#define MAGIC_INPUT_COOKIE_4 0xC3D2E1F0

// Defining a Macro: http://www.c-howto.de/tutorial/praeprozessor/makros/
// Rotate Bits: https://www.geeksforgeeks.org/rotate-bits-of-an-integer/

#define ROTATELEFT(value ,n) (((value) << (n))|((value) >> (32 - (n))))
#define WORDITERATION(w, index) (*w[index]=ROTATELEFT((*w[index-3]^*w[index-8]^*w[index-14]^*w[index-16]),1))

#define ROUND_1_1(a, b, c, d, e, w) e+=((b&c)|((~b)&d))+MAGIC_COOKIE_1+ROTATELEFT(a,5)+w;b=ROTATELEFT(b,30);
#define ROUND_1_2(a, b, c, d, e, w, index) e+=((b&c)|((~b)&d))+MAGIC_COOKIE_1+ROTATELEFT(a,5)+WORDITERATION(w,index);b=ROTATELEFT(b,30);
#define ROUND_2(a, b, c, d, e, w, index) e+=((b^c^d)+MAGIC_COOKIE_2+ROTATELEFT(a,5)+WORDITERATION(w,index));b=ROTATELEFT(b,30);
#define ROUND_3(a, b, c, d, e, w, index) e+=((b&c)|(b&d)|(c&d))+MAGIC_COOKIE_3+ROTATELEFT(a,5)+WORDITERATION(w,index);b=ROTATELEFT(b,30);
#define ROUND_4(a, b, c, d, e, w, index) e+=(b^c^d)+MAGIC_COOKIE_4+ROTATELEFT(a,5)+WORDITERATION(w,index);b=ROTATELEFT(b,30);


int main(int argc, unsigned char *argv[]){

	unsigned char *ucInputMessage;
	unsigned long ulMessageLength;
	unsigned long ulBitMessageLength;
	unsigned long ulNextArrayIndex;
	uint32_t ulWordArray[80];
	unsigned long ulTempScum;
	unsigned long ulHashValue = 0;

	unsigned int h0 = MAGIC_INPUT_COOKIE_0;
	unsigned int h1 = MAGIC_INPUT_COOKIE_1;
	unsigned int h2 = MAGIC_INPUT_COOKIE_2;
	unsigned int h3 = MAGIC_INPUT_COOKIE_3;
	unsigned int h4 = MAGIC_INPUT_COOKIE_4;

	uint32_t a = h0;
	uint32_t b = h1;
	uint32_t c = h2;
	uint32_t d = h3;
	uint32_t e = h4;

	ucInputMessage = (unsigned char *)malloc(strlen((const char *)argv[1])+64);
	strcpy((char *)ucInputMessage,(const char *)argv[1]);

	ulMessageLength = strlen(ucInputMessage);

	ulNextArrayIndex = ulMessageLength;

	if(ulMessageLength < 56){
		ucInputMessage[ulNextArrayIndex] = 0x80;
		ulNextArrayIndex++;
		for(ulNextArrayIndex; ulNextArrayIndex < 56; ulNextArrayIndex++){
			ucInputMessage[ulNextArrayIndex] = 0x00;
		}
	}

	for(ulNextArrayIndex; ulNextArrayIndex < 61; ulNextArrayIndex++){
		ucInputMessage[ulNextArrayIndex] = 0x00;
	}

	ulBitMessageLength = ulMessageLength * 8;

	ucInputMessage[ulNextArrayIndex] = 0x00 | (ulBitMessageLength >> 16);
	ucInputMessage[ulNextArrayIndex+1] = 0x00 | (ulBitMessageLength >> 8);
	ucInputMessage[ulNextArrayIndex+2] = 0x00 | ulBitMessageLength;

	for(int i = 0; i < 16; i++){
		ulWordArray[i]=(ucInputMessage[i*4] << 24) | (ucInputMessage[i*4+1] << 16) | (ucInputMessage[i*4+2] << 8) | ucInputMessage[i*4+3];
		//printf("%x\n" ,(int)ulWordArray[i]);
	}

	ROUND_1_1(a, b, c, d, e, ulWordArray[0]);
	ROUND_1_1(e, a, b, c, d, ulWordArray[1]);
	ROUND_1_1(d, e, a, b, c, ulWordArray[2]);
	ROUND_1_1(c, d, e, a, b, ulWordArray[3]);
	ROUND_1_1(b, c, d, e, a, ulWordArray[4]);
	ROUND_1_1(a, b, c, d, e, ulWordArray[5]);
	ROUND_1_1(e, a, b, c, d, ulWordArray[6]);
	ROUND_1_1(d, e, a, b, c, ulWordArray[7]);
	ROUND_1_1(c, d, e, a, b, ulWordArray[8]);
	ROUND_1_1(b, c, d, e, a, ulWordArray[9]);
	ROUND_1_1(a, b, c, d, e, ulWordArray[10]);
	ROUND_1_1(e, a, b, c, d, ulWordArray[11]);
	ROUND_1_1(d, e, a, b, c, ulWordArray[12]);
	ROUND_1_1(c, d, e, a, b, ulWordArray[13]);
	ROUND_1_1(b, c, d, e, a, ulWordArray[14]);
	ROUND_1_1(a, b, c, d, e, ulWordArray[15]);
	ROUND_1_2(e, a, b, c, d, &ulWordArray, 16);
	ROUND_1_2(d, e, a, b, c, &ulWordArray, 17);
	ROUND_1_2(c, d, e, a, b, &ulWordArray, 18);
	ROUND_1_2(b, c, d, e, a, &ulWordArray, 19);
	ROUND_2(a, b, c, d, e, &ulWordArray, 20);
	ROUND_2(e, a, b, c, d, &ulWordArray, 21);
	ROUND_2(d, e, a, b, c, &ulWordArray, 22);
	ROUND_2(c, d, e, a, b, &ulWordArray, 23);
	ROUND_2(b, c, d, e, a, &ulWordArray, 24);
	ROUND_2(a, b, c, d, e, &ulWordArray, 25);
	ROUND_2(e, a, b, c, d, &ulWordArray, 26);
	ROUND_2(d, e, a, b, c, &ulWordArray, 27);
	ROUND_2(c, d, e, a, b, &ulWordArray, 28);
	ROUND_2(b, c, d, e, a, &ulWordArray, 29);
	ROUND_2(a, b, c, d, e, &ulWordArray, 30);
	ROUND_2(e, a, b, c, d, &ulWordArray, 31);
	ROUND_2(d, e, a, b, c, &ulWordArray, 32);
	ROUND_2(c, d, e, a, b, &ulWordArray, 33);
	ROUND_2(b, c, d, e, a, &ulWordArray, 34);
	ROUND_2(a, b, c, d, e, &ulWordArray, 35);
	ROUND_2(e, a, b, c, d, &ulWordArray, 36);
	ROUND_2(d, e, a, b, c, &ulWordArray, 37);
	ROUND_2(c, d, e, a, b, &ulWordArray, 38);
	ROUND_2(b, c, d, e, a, &ulWordArray, 39);
	ROUND_3(a, b, c, d, e, &ulWordArray, 40);
	ROUND_3(e, a, b, c, d, &ulWordArray, 41);
	ROUND_3(d, e, a, b, c, &ulWordArray, 42);
	ROUND_3(c, d, e, a, b, &ulWordArray, 43);
	ROUND_3(b, c, d, e, a, &ulWordArray, 44);
	ROUND_3(a, b, c, d, e, &ulWordArray, 45);
	ROUND_3(e, a, b, c, d, &ulWordArray, 46);
	ROUND_3(d, e, a, b, c, &ulWordArray, 47);
	ROUND_3(c, d, e, a, b, &ulWordArray, 48);
	ROUND_3(b, c, d, e, a, &ulWordArray, 49);
	ROUND_3(a, b, c, d, e, &ulWordArray, 50);
	ROUND_3(e, a, b, c, d, &ulWordArray, 51);
	ROUND_3(d, e, a, b, c, &ulWordArray, 52);
	ROUND_3(c, d, e, a, b, &ulWordArray, 53);
	ROUND_3(b, c, d, e, a, &ulWordArray, 54);
	ROUND_3(a, b, c, d, e, &ulWordArray, 55);
	ROUND_3(e, a, b, c, d, &ulWordArray, 56);
	ROUND_3(d, e, a, b, c, &ulWordArray, 57);
	ROUND_3(c, d, e, a, b, &ulWordArray, 58);
	ROUND_3(b, c, d, e, a, &ulWordArray, 59);
	ROUND_4(a, b, c, d, e, &ulWordArray, 60);
	ROUND_4(e, a, b, c, d, &ulWordArray, 61);
	ROUND_4(d, e, a, b, c, &ulWordArray, 62);
	ROUND_4(c, d, e, a, b, &ulWordArray, 63);
	ROUND_4(b, c, d, e, a, &ulWordArray, 64);
	ROUND_4(a, b, c, d, e, &ulWordArray, 65);
	ROUND_4(e, a, b, c, d, &ulWordArray, 66);
	ROUND_4(d, e, a, b, c, &ulWordArray, 67);
	ROUND_4(c, d, e, a, b, &ulWordArray, 68);
	ROUND_4(b, c, d, e, a, &ulWordArray, 69);
	ROUND_4(a, b, c, d, e, &ulWordArray, 70);
	ROUND_4(e, a, b, c, d, &ulWordArray, 71);
	ROUND_4(d, e, a, b, c, &ulWordArray, 72);
	ROUND_4(c, d, e, a, b, &ulWordArray, 73);
	ROUND_4(b, c, d, e, a, &ulWordArray, 74);
	ROUND_4(a, b, c, d, e, &ulWordArray, 75);
	ROUND_4(e, a, b, c, d, &ulWordArray, 76);
	ROUND_4(d, e, a, b, c, &ulWordArray, 77);
	ROUND_4(c, d, e, a, b, &ulWordArray, 78);
	ROUND_4(b, c, d, e, a, &ulWordArray, 79);

	h0 = h0 + a;
	h1 = h1 + b;
	h2 = h2 + c;
	h3 = h3 + d;
	h4 = h4 + e;

	printf("0x%X\n" , h0);
	printf("0x%X\n" , h1);
	printf("0x%X\n" , h2);
	printf("0x%X\n" , h3);
	printf("0x%X\n" , h4);

	return ulHashValue;

}
