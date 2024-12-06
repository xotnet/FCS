/*

 Password requirements /
	1. Minimum password length is 6 characters
	2. The password must not contain repetitive obvious combinations
 Lib usage /
	1. Encrypt: fcsEncrypt(char* data, char* key, int dataLength)
	2. Decrypt: fcsDecrypt(char* data, char* key, int dataLength)
	?. The data buffer will be overwritten.

*/

#include <stdlib.h>
#include <stdint.h>

uint8_t countBits(char ch) {
	uint8_t res = 0;
	for (int e = 0; e<8; e++) {
		if ((ch & (0x01 << e)) == (0x01 << e)) {
			res++;
		}
	}
	return res;
}

int8_t cmpStr(char* str1, char* str2, uint16_t len) {
	for (int i = 0; i<len; i++) {
		if (*(str1+i) != *(str2+i)) {
			return -1;
		}
	}
	return 0;
}

void copyStr(char* str, char* copy, uint16_t len) {
	for (int i = 0; i<len; i++) {
		*(copy+i) = *(str+1);
	}
}

void blockShuffle(unsigned char* data, unsigned char* key, uint8_t ed /*0-shuffle/1-deshuffle*/, uint16_t dataLen, uint16_t keyLen ) {

	// hello world! -> o!hodedl rlwl -> hello world!

	uint16_t cleanKL = keyLen;
	if (keyLen % 2 != 0) {cleanKL = keyLen-1;}
	uint8_t* blocksToSh = (uint8_t*)malloc(cleanKL);
	for (int i = 0; i<cleanKL; i++) { // get each key's letter and count how many 1 in bytes
		blocksToSh[i] = countBits(key[i]) % dataLen;
		for (int e = 0; e+i<cleanKL && countBits(key[i+e]) > 0; e++) {
			blocksToSh[i] = (blocksToSh[i] * countBits(key[i+e])) % dataLen;
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

void sharedXor(unsigned char* data, unsigned char* key, uint16_t dataLen, uint16_t keyLen) {
	keyLen = keyLen % 32; // sharedXor passLen limit is 32
	for (int i = 0; i<dataLen; i++) {
		for (int e = 0; e<keyLen; e++) {
			*(data+i) = *(data+i) ^ *(key+e);
		}
	}
}

void privateXor(unsigned char* data, unsigned char* key, uint16_t dataLen, uint16_t keyLen) {
	unsigned char* keyMask = (unsigned char*)malloc(dataLen+4);
	for (uint16_t i = 0; i<dataLen+4; i++) { // Fill keyMask key's copies
		keyMask[i] = key[i%keyLen];
	}
	for (uint16_t i = 0; i<dataLen; i++) {
		*(data+i) = *(data+i) ^ *(keyMask+i);
		if (countBits(keyMask[i]) % 2 == 0) {
			*(data+i) = *(data+i) ^ *(keyMask+i+1);
		}
		if (countBits(keyMask[i]) > 3) {
			*(data+i) = *(data+i) ^ *(keyMask+i+2);
		}
	}
	free(keyMask);
}

void fcsCryptoError(char* data, uint16_t dataLen) {
	for (int i = 0; i<dataLen; i++) {
		*(data+i) = 0;
	}
}

int8_t fcsEncrypt(unsigned char* data, unsigned char* key, uint16_t dataLen, uint16_t keyLen) {
	// shuffle blocks -> shared xor -> private xor
	unsigned char* dataCopy = (unsigned char*)malloc(dataLen);
	copyStr(data, dataCopy, dataLen);

	blockShuffle(data, key, 0, dataLen, keyLen);
	if (cmpStr(data, dataCopy, dataLen) == 0) {
		fcsCryptoError(data, dataLen);
		return -1;
	}
	copyStr(data, dataCopy, dataLen);

	sharedXor(data, key, dataLen, keyLen);
	if (cmpStr(data, dataCopy, dataLen) == 0) {
    fcsCryptoError(data, dataLen);
    return -1;
  }
	copyStr(data, dataCopy, dataLen);

	privateXor(data, key, dataLen, keyLen);
	if (cmpStr(data, dataCopy, dataLen) == 0) {
    fcsCryptoError(data, dataLen);
    return -1;
  }
	return 0;
}

int8_t fcsDecrypt(unsigned char* data, unsigned char* key, uint16_t dataLen, uint16_t keyLen) {
	// private xor -> shared xor -> shuffle blocks
	unsigned char* dataCopy = (unsigned char*)malloc(dataLen);
  copyStr(data, dataCopy, dataLen);

  privateXor(data, key, dataLen, keyLen);
  if (cmpStr(data, dataCopy, dataLen) == 0) {
    fcsCryptoError(data, dataLen);
    return -1;
  }
  copyStr(data, dataCopy, dataLen);

  sharedXor(data, key, dataLen, keyLen);
  if (cmpStr(data, dataCopy, dataLen) == 0) {
    fcsCryptoError(data, dataLen);
    return -1;
  }
  copyStr(data, dataCopy, dataLen);

  blockShuffle(data, key, 1, dataLen, keyLen);
  if (cmpStr(data, dataCopy, dataLen) == 0) {
    fcsCryptoError(data, dataLen);
    return -1;
  }
  return 0;
}
