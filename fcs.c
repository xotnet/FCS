/*

 Password requirements /
	1. Minimum password length is 6 characters
	2. The password must not contain repetitive obvious combinations
 Lib usage /
	1. Encrypt: fcsEncrypt(char* data, char* key, int dataLength, int keyLength)
	2. Decrypt: fcsDecrypt(char* data, char* key, int dataLength, int keyLength)
	?. The data buffer will be overwritten.

*/

#include <stdlib.h>
#include <stdint.h>
uint8_t countBits(char ch) {
	uint8_t res = 0;
	for (uint8_t e = 0; e<8; e++) {
		if ((ch & (0x01 << e)) == (0x01 << e)) {
			res++;
		}
	}
	return res;
}

int8_t cmpStr(char* str1, char* str2, uint32_t len) {
	for (uint32_t i = 0; i<len; i++) {
		if (*(str1+i) != *(str2+i)) {
			return -1;
		}
	}
	return 0;
}

void copyStr(char* str, char* copy, uint32_t len) {
	for (uint32_t i = 0; i<len; i++) {
		*(copy+i) = *(str+1);
	}
}

void fcsLettersShuffle(char* data, char* key, uint8_t ed /*0-encrypt/1-decrypt*/, uint32_t dataLen, uint32_t keyLen ) {
	// hello world! -> o!hodedl rlwl -> hello world!
	uint32_t cleanKL = keyLen;
	if (keyLen % 2 != 0) {cleanKL = keyLen-1;}
	uint8_t* blocksToSh = (uint8_t*)malloc(cleanKL);
	for (uint32_t i = 0; i<cleanKL; i++) {
		blocksToSh[i] = countBits(key[i]) % dataLen;
		uint32_t g = 0;
		for (uint32_t e = 0; e+i<cleanKL && countBits(key[i+e]) > 0 && g < 32; e++) {
			uint8_t ieCount = countBits(key[i+e]);
			blocksToSh[i] = (blocksToSh[i] * ieCount + dataLen-ieCount) % dataLen;
			g++;
		}
	}
	// shuffle blocks
	if (ed == 0) {
		for (uint32_t i = 0; i<cleanKL; i = i+2) {
			if (blocksToSh[i] == blocksToSh[i+1]) {
				continue;
			}
			char tb = data[blocksToSh[i+1]];
			data[blocksToSh[i+1]] = data[blocksToSh[i]];
			data[blocksToSh[i]] = tb;
		}
	} else {
		for (int32_t i = cleanKL-1; i>0; i = i-2) {
    	if (blocksToSh[i-1] == blocksToSh[i]) {
    	  continue;
    	}
    	char tb = data[blocksToSh[i]];
    	data[blocksToSh[i]] = data[blocksToSh[i-1]];
    	data[blocksToSh[i-1]] = tb;
		}
	}
}

void fcsSharedXor(char* data, char* key, uint32_t dataLen, uint32_t keyLen) {
	keyLen = keyLen % 32; // fcsSharedXor passLen limit is 32
	for (uint32_t i = 0; i<dataLen; i++) {
		for (uint32_t e = 0; e<keyLen; e++) {
			*(data+i) = *(data+i) ^ *(key+e);
		}
	}
}

void fcsPrivateXor(char* data, char* key, uint32_t dataLen, uint32_t keyLen) {
	char* keyMask = (char*)malloc(dataLen+4);
	for (uint32_t i = 0; i<dataLen+4; i++) { // Fill keyMask key's copies
		keyMask[i] = key[i%keyLen];
	}
	for (uint32_t i = 0; i<dataLen; i++) {
		*(data+i) = *(data+i) ^ *(keyMask+i);
		if (countBits(keyMask[i]) % 2 == 0) {
			*(data+i) = *(data+i) ^ *(keyMask+i+1);
		}
		if (countBits(keyMask[i]) > 3) {
			*(data+i) = *(data+i) ^ *(keyMask+i+2);
		}
		if (countBits(keyMask[i] > 4)) {
			*(data+i) = *(data+i) ^ *(keyMask+i+3);
		}
		if (countBits(keyMask[i]) == 4) {
			*(data+i) = *(data+i) ^ *(keyMask+i+4);
		}
	}
	free(keyMask);
}

void fcsMathCrypt(char* data, char* key, uint8_t ed, uint32_t dataLen, uint32_t keyLen) {
	int8_t seed = 0;
	int8_t buf = 0;
	for (uint32_t i = 0; i<dataLen; i++) {
		uint32_t g = 0;
		do {
			buf = countBits(key[g % keyLen]);
			seed = seed + buf;
			g++;
		} while (buf > 1 && g < 32);
		if ((key[i%keyLen] | 0b00000001) == 0b00000001) {
			seed = -seed;
		}
		if (ed == 0) {
			*(data+i) = *(data+i) + seed;
		} else {
			*(data+i) = *(data+i) - seed;
		}
	}
}

void fcsCryptoError(char* data, uint32_t dataLen) {
	for (uint32_t i = 0; i<dataLen; i++) {
		*(data+i) = 0;
	}
}

int8_t fcsEncrypt(char* data, char* key, uint32_t dataLen, uint32_t keyLen) {
	// shuffle blocks -> shared xor -> private xor
	char* dataCopy = (char*)malloc(dataLen);
	copyStr(data, dataCopy, dataLen);

	fcsLettersShuffle(data, key, 0, dataLen, keyLen);
	if (cmpStr(data, dataCopy, dataLen) == 0) {
		fcsCryptoError(data, dataLen);
		return -1;
	}
	copyStr(data, dataCopy, dataLen);

	fcsSharedXor(data, key, dataLen, keyLen);
	if (cmpStr(data, dataCopy, dataLen) == 0) {
    fcsCryptoError(data, dataLen);
    return -1;
  }
	copyStr(data, dataCopy, dataLen);

	fcsPrivateXor(data, key, dataLen, keyLen);
	if (cmpStr(data, dataCopy, dataLen) == 0) {
    fcsCryptoError(data, dataLen);
    return -1;
  }
  copyStr(data, dataCopy, dataLen);

  fcsMathCrypt(data, key, 0, dataLen, keyLen);
	if (cmpStr(data, dataCopy, dataLen) == 0) {
    fcsCryptoError(data, dataLen);
    return -1;
  }
	return 0;
}

int8_t fcsDecrypt(char* data, char* key, uint32_t dataLen, uint32_t keyLen) {
	// private xor -> shared xor -> shuffle blocks
	char* dataCopy = (char*)malloc(dataLen);
  copyStr(data, dataCopy, dataLen);

  fcsMathCrypt(data, key, 1, dataLen, keyLen);
	if (cmpStr(data, dataCopy, dataLen) == 0) {
    fcsCryptoError(data, dataLen);
    return -1;
  }
  copyStr(data, dataCopy, dataLen);

  fcsPrivateXor(data, key, dataLen, keyLen);
  if (cmpStr(data, dataCopy, dataLen) == 0) {
    fcsCryptoError(data, dataLen);
    return -1;
  }
  copyStr(data, dataCopy, dataLen);

  fcsSharedXor(data, key, dataLen, keyLen);
  if (cmpStr(data, dataCopy, dataLen) == 0) {
    fcsCryptoError(data, dataLen);
    return -1;
  }
  copyStr(data, dataCopy, dataLen);
  fcsLettersShuffle(data, key, 1, dataLen, keyLen);
  if (cmpStr(data, dataCopy, dataLen) == 0) {
    fcsCryptoError(data, dataLen);
    return -1;
  }
  return 0;
}
