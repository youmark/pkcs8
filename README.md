lokks307-pkcs8
===
This repository is forked from [youmark/pkcs8](https://github.com/youmark/pkcs8). The below is from youmark's original repository.

***
OpenSSL can generate private keys in both "traditional format" and PKCS#8 format. Newer applications are advised to use more secure PKCS#8 format. Go standard crypto package provides a [function](http://golang.org/pkg/crypto/x509/#ParsePKCS8PrivateKey) to parse private key in PKCS#8 format. There is a limitation to this function. It can only handle unencrypted PKCS#8 private keys. To use this function, the user has to save the private key in file without encryption, which is a bad practice to leave private keys unprotected on file systems. In addition, Go standard package lacks the functions to convert RSA/ECDSA private keys into PKCS#8 format.

pkcs8 package fills the gap here. It implements functions to process private keys in PKCS#8 format, as defined in [RFC5208](https://tools.ietf.org/html/rfc5208) and [RFC5958](https://tools.ietf.org/html/rfc5958). It can handle both unencrypted PKCS#8 PrivateKeyInfo format and EncryptedPrivateKeyInfo format with PKCS#5 (v2.0) algorithms.
***

### Notice

This repository is for enhancing original library in serveral aspects. Mainly, we fixed pbkdf2 parameter to support optional key length be compatible with other crypto libraries such as Botan. And we did some improvements.

### License

- The original youmark/pkcs8 is under MIT license.
- The our fixed codes is under Chicken-ware license. If we meet some day, and you think this stuff is worth it, you can buy us a fried chicken in return.
