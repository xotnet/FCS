Symmetric encryption algorithm

The following encryption methods are used: **Character shuffling; Generic xor (unsafe on its own); Overlaying data on the password mask**

|Hello world encryption stages| --- |
|----|----|
|Hello world!| 1. Clean test |
|oHlwrloel!d| 2. Jumbled letters |
|hOkpukhbk&c| 3. Shared XOR |
|Ht>W7Ko?sc7| 4. Shifting key mask overlay |

**Lib usage**
  1. Encrypt: **fcsEncrypt**(char* **data**, char* **key**, int **dataLength**, int **keyLength**)
  2. Decrypt: **fcsDecrypt**(char* **data**, char* **key**, int **dataLength**, int **keyLength**)

[Download library header](https://github.com/xotnet/FCS/releases/latest/download/fcs.h)
