import 'package:encryptor/encryptor.dart';
import 'package:flutter/material.dart';

class Example extends StatefulWidget {
  @override
  _ExampleState createState() => _ExampleState();
}

class _ExampleState extends State<Example> {
  @override
  Widget build(BuildContext context) {
    return Container(
      color: Colors.blue,
      child: Center(
        child: RawMaterialButton(
            child: Text('Encrypt/Decrypt'),
            onPressed: () async {
              try {
                /// AES encryption example
                final secretKey = 'rr4555xhhSecsKey';
                final encryptedAES =
                    'Text to encrypt'.encryptAESCrypto(securedKey: secretKey);
                print('AES ' + encryptedAES);
                final decryptedAES =
                    encryptedAES.decryptAESCrypto(securedKey: secretKey);
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

                /// RSA encryption example
                var plainText = 'Data to be encrypted';
                var encryptedRSA = await plainText.encryptRSACrypto(
                  publicKeyPath: 'assets/public.pem',
                );
                print('RSA Encripted $encryptedRSA');
                var decryptedRSA = await encryptedRSA.decryptRSACrypto(
                    privateKeyPath: 'assets/private.pem');
                print('RSA Decrypted $decryptedRSA');
              } catch (e) {
                print("ERROR $e");
              }
            }),
      ),
    );
  }
}
