/*

 Password requirements /
	1. Minimum password length is 6 characters
	2. The password must not contain repetitive obvious combinations

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint16_t getLen(char* str) {
	uint16_t res = 0;
	while (*(str+res) != 0) {
		res++;
	}
	return res;
}

uint8_t countBits(char ch) {
	uint8_t res = 0;
	for (int e = 0; e<8; e++) {
		if ((ch & (0x01 << e)) == (0x01 << e)) {
			res++;
		}
	}
	return res;
}

void blockShuffle(unsigned char* data, unsigned char* key, uint8_t ed /*0-shuffle/1-deshuffle*/ ) {

	// hello world! -> o!hodedl rlwl -> hello world!

	uint16_t keyLen = getLen(key);
	uint16_t cleanKL = keyLen;
	if (keyLen % 2 != 0) {cleanKL = keyLen-1;}
	uint16_t dataLen = getLen(data);
	uint8_t* blocksToSh = (uint8_t*)malloc(cleanKL);
	for (int i = 0; i<cleanKL; i++) { // get each key's letter and count how many 1 in bytes
		blocksToSh[i] = countBits(key[i]) % dataLen;
		for (int e = 0; e+i<cleanKL && countBits(key[i+e]) > 1; e++) {
			blocksToSh[i] = (blocksToSh[i] + countBits(key[i+e])) % dataLen;
		}
	}
	// shuffle blocks
	if (ed == 0) {
		for (int i = 0; i<cleanKL; i = i+2) {
			if (blocksToSh[i] == blocksToSh[i+1]) {
				continue;
			}
			char tb = data[blocksToSh[i+1]];
			data[blocksToSh[i+1]] = data[blocksToSh[i]];
			data[blocksToSh[i]] = tb;
		}
	} else {
		for (int i = cleanKL-1; i>0; i = i-2) {
    	if (blocksToSh[i-1] == blocksToSh[i]) {
    	  continue;
    	}
    	char tb = data[blocksToSh[i]];
    	data[blocksToSh[i]] = data[blocksToSh[i-1]];
    	data[blocksToSh[i-1]] = tb;
		}
	}
}

void sharedXor(unsigned char* data, unsigned char* key) {
	uint16_t dataLen = getLen(data);
	uint16_t keyLen = getLen(key) % 32; // sharedXor passLen limit is 32
	for (int i = 0; i<dataLen; i++) {
		for (int e = 0; e<keyLen; e++) {
			*(data+i) = *(data+i) ^ *(key+e);
		}
	}
}

void privateXor(unsigned char* data, unsigned char* key) {
	uint16_t dataLen = getLen(data);
	uint16_t keyLen = getLen(key);
	unsigned char* keyK = (unsigned char*)malloc(dataLen+4);
	for (int i = 0; i<dataLen+4; i++) {
		keyK[i] = key[i%keyLen];
	}
	uint16_t e = 0;
	for (int i = 0; i<dataLen; i++) {
		if (countBits(*(keyK+i)) > 2) {
			*(keyK+i) = *(keyK+i) ^ *(keyK+i) ^ *(keyK+i+1) ^ *(keyK+i+2); // invert and xor with next byte
		}
		e = (i+e) % keyLen;
		*(data+i) = *(data+i) ^ *(keyK+i) ^ *(keyK+i+e);
	}
	free(keyK);
}

void fcsEncrypt(unsigned char* data, unsigned char* key) {
	// shuffle blocks -> shared xor -> private xor
	uint16_t dataLen = getLen(data);
	blockShuffle(data, key, 0);
	sharedXor(data, key);
	privateXor(data, key);
}

void fcsDecrypt(unsigned char* data, unsigned char* key) {
	// private xor -> shared xor -> shuffle blocks
	privateXor(data, key);
	sharedXor(data, key);
	blockShuffle(data, key, 1);
}
