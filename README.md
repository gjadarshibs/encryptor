# encryptor
A flutter package for handling sensitive data. Here this package encrypt and decrypt data based on the following standards
* AES
* RSA
* Salsa20
* Fernet

## How to consume this package ? 
* Copy and paste the encryption package into your workspace.
* Mention the package in the pubspec.yaml file on your project. Refer the below snapshot 
```
sensitive_data_handler:
    path: ‘package location’
```
* Import the local package into your project.  
````
import 'package:encryptor/encryptor.dart';
````
* ‘plain text’.encryptAESCrypto(securedKey:’key’) will return the AES encrypted data. Similarly ‘encrypted text’ decryptAESCrypto(securedKey:’key’) will return the decrypted raw data.
* The Salsa20 and Fernet encryption and decryption approach is same as AES. 
    * ‘plain text’.encryptSalsaCrypto(securedKey:’key’)'
    * ’plain text’.encryptFernetCrypto(securedKey:’key’)'
    * ‘encrypted text’.decryptSalsaCrypto(securedKey:’key’)’
    * ‘encrypted text’.decryptFernetCrypto(securedKey:’key’)’
* The RSA encryption and decryption is an asynchronous operation as it need to load the .pem file located in your workspace that contains the private and public key.

## Example for AES, Salsa20, Fernet
```
try {
                /// AES encryption example
                final secretKey = 'rr4555xhhSecsKey';
                final encryptedAES = 'Text to encrypt'.encryptAESCrypto(securedKey: secretKey);
                print('AES ' + encryptedAES);
                final decryptedAES = encryptedAES.decryptAESCrypto(securedKey: secretKey);
                print('AES ' + decryptedAES);

                /// Salsa20 encryption example
                final encryptedSalsa =
                    'Text to encrypt'.encryptSalsaCrypto(securedKey: secretKey);
                print('Salsa ' + encryptedSalsa);
                final decryptedSalsa =
                    encryptedSalsa.decryptSalsaCrypto(securedKey: secretKey);
                print('Salsa ' + decryptedSalsa);

                /// Fernet encryption example
                final encryptedFernet = 'Text to encrypt'
                    .encryptFernetCrypto(securedKey: secretKey);
                print('Fernet ' + encryptedFernet);
                final decryptedFernet =
                    encryptedFernet.decryptFernetCrypto(securedKey: secretKey);
                print('Fernet ' + decryptedFernet);

} catch (e) {
	print("ERROR $e");
}

```
## Example for RSA
```
                /// RSA encryption example
                var plainText = 'Data to be encrypted';
                var encryptedRSA = await plainText.encryptRSACrypto(
                  publicKeyPath: 'assets/public.pem',
                );
                print('RSA Encripted $encryptedRSA');
                var decryptedRSA = await encryptedRSA.decryptRSACrypto(
                    privateKeyPath: 'assets/private.pem');
                print('RSA Decrypted $decryptedRSA');

```








