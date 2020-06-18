import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:tuple/tuple.dart';

/// AES encryption and decryption will be done on a given String based on a secret key.
extension CryptoAES on String {
  ///[securedKey] is the key used for decryption and return encrypted data.
  ///[aesMode] is the AES mode to be enabled like cbc, ctr etc.
  ///
  String encryptAESCrypto({@required String securedKey, AESMode aesMode}) {
    try {
      final keyExtension = genRandomWithNonZero(8);
      var keyAndIV = deriveKeyAndIV(securedKey, keyExtension);
      final key = encrypt.Key(keyAndIV.item1);
      final iv = encrypt.IV(keyAndIV.item2);

      final encrypter = encrypt.Encrypter(encrypt.AES(key,
          mode: aesMode ?? encrypt.AESMode.cbc, padding: 'PKCS7'));
      final encrypted = encrypter.encrypt(this, iv: iv);
      final encryptedBytesWithSalt = Uint8List.fromList(
          createUint8ListFromString('Salted__') +
              keyExtension +
              encrypted.bytes);
      return base64.encode(encryptedBytesWithSalt);
    } catch (error) {
      rethrow;
    }
  }

  /// [securedKey] is the key used for decryption and return raw data.
  ///[aesMode] is the AES mode to be enabled like cbc, ctr etc.
  ///
  String decryptAESCrypto({@required String securedKey, AESMode aesMode}) {
    try {
      final encryptedBytesWithSalt = base64.decode(this);

      final encryptedBytes =
          encryptedBytesWithSalt.sublist(16, encryptedBytesWithSalt.length);
      final keyExtension = encryptedBytesWithSalt.sublist(8, 16);
      var keyAndIV = deriveKeyAndIV(securedKey, keyExtension);
      final key = encrypt.Key(keyAndIV.item1);
      final iv = encrypt.IV(keyAndIV.item2);

      final encrypter = encrypt.Encrypter(encrypt.AES(key,
          mode: aesMode ?? encrypt.AESMode.cbc, padding: 'PKCS7'));
      final decrypted =
          encrypter.decrypt64(base64.encode(encryptedBytes), iv: iv);
      return decrypted;
    } catch (error) {
      rethrow;
    }
  }
}

/// Salsa20 encryption and decryption will be done on a given String based on a secret key.
/// IV for Salsa20 should be exactly 8 bits.
extension CryptoSalsa on String {
  ///[securedKey] is the key used for decryption and return encrypted data.
  ///
  String encryptSalsaCrypto({@required String securedKey}) {
    try {
      final keyExtension = genRandomWithNonZero(8);
      var keyAndIV = deriveKeyAndIV(securedKey, keyExtension);
      final key = encrypt.Key(keyAndIV.item1);
      final iv = IV.fromLength(8);

      final encrypter = encrypt.Encrypter(Salsa20(key));
      final encrypted = encrypter.encrypt(this, iv: iv);
      final encryptedBytesWithSalt = Uint8List.fromList(
          createUint8ListFromString('Salted__') +
              keyExtension +
              encrypted.bytes);
      return base64.encode(encryptedBytesWithSalt);
    } catch (error) {
      rethrow;
    }
  }

  /// [securedKey] is the key used for decryption and return raw data.
  String decryptSalsaCrypto({@required String securedKey}) {
    try {
      final encryptedBytesWithSalt = base64.decode(this);

      final encryptedBytes =
          encryptedBytesWithSalt.sublist(16, encryptedBytesWithSalt.length);
      final keyExtension = encryptedBytesWithSalt.sublist(8, 16);
      var keyAndIV = deriveKeyAndIV(securedKey, keyExtension);
      final key = encrypt.Key(keyAndIV.item1);
      final iv = IV.fromLength(8);

      final encrypter = encrypt.Encrypter(Salsa20(key));

      final decrypted =
          encrypter.decrypt64(base64.encode(encryptedBytes), iv: iv);
      return decrypted;
    } catch (error) {
      rethrow;
    }
  }
}

/// Fernet encryption and decryption will be done on a given String based on a secret key.
/// IV for Fernet should be exactly 16 bits.
extension CryptoFernet on String {
  ///[securedKey] is the key used for decryption and return encrypted data.
  ///
  String encryptFernetCrypto({@required String securedKey}) {
    try {
      final keyExtension = genRandomWithNonZero(8);
      var keyAndIV = deriveKeyAndIV(securedKey, keyExtension);
      final key = encrypt.Key(keyAndIV.item1);
      final iv = IV.fromLength(16);

      final b64key = encrypt.Key.fromUtf8(base64Url.encode(key.bytes));
      // if you need to use the ttl feature, you'll need to use APIs in the algorithm itself
      final fernet = Fernet(b64key);
      final encrypter = Encrypter(fernet);
      final encrypted = encrypter.encrypt(this, iv: iv);
      final encryptedBytesWithSalt = Uint8List.fromList(
          createUint8ListFromString('Salted__') +
              keyExtension +
              encrypted.bytes);
      return base64.encode(encryptedBytesWithSalt);
    } catch (error) {
      rethrow;
    }
  }

  /// [securedKey] is the key used for decryption and return raw data.
  String decryptFernetCrypto({
    @required String securedKey,
  }) {
    try {
      final encryptedBytesWithSalt = base64.decode(this);

      final encryptedBytes =
          encryptedBytesWithSalt.sublist(16, encryptedBytesWithSalt.length);
      final keyExtension = encryptedBytesWithSalt.sublist(8, 16);
      var keyAndIV = deriveKeyAndIV(securedKey, keyExtension);
      final key = encrypt.Key(keyAndIV.item1);
      final b64key = encrypt.Key.fromUtf8(base64Url.encode(key.bytes));
      final fernet = Fernet(b64key);
      final encrypter = Encrypter(fernet);

      final decrypted = encrypter.decrypt64(
        base64.encode(encryptedBytes),
      );

      return decrypted;
    } catch (error) {
      rethrow;
    }
  }
}

/// RSA encryption and decryption will be done here based on the private and public keys.
extension CryptoRSA on String {
  /// Return RSA encrypted data.
  ///[privateKeyPath] is the private key .pem file path.
  ///[publicKeyPath] is the public key .pem file path.
  ///
  Future<String> encryptRSACrypto({@required String publicKeyPath}) async {
    try {
      var rsaEncryptor = await _getRSAEncryptor(publicKeyPath: publicKeyPath);
      final encrypter = Encrypter(rsaEncryptor);
      final encrypted = encrypter.encrypt(this);
      print(encrypted.base64);
      return encrypted.base64;
    } catch (error) {
      rethrow;
    }
  }

  /// Return RSA decrypted data.
  ///[privateKeyPath] is the private key .pem file path
  ///[publicKeyPath] is the public key .pem file path
  ///
  Future<String> decryptRSACrypto({@required String privateKeyPath}) async {
    try {
      final rsaEncryptor =
          await _getRSAEncryptor(privateKeyPath: privateKeyPath);
      final encrypter = Encrypter(rsaEncryptor);
      final decrypted = encrypter.decrypt64(this);
      return decrypted;
    } catch (error) {
      rethrow;
    }
  }
}

Future _getRSAEncryptor(
    {String privateKeyPath = '', String publicKeyPath = ''}) async {
  var rsaEncryptor;
  if (privateKeyPath.isNotEmpty) {
    final privateKey = await parseKeyFromFile<RSAPrivateKey>(privateKeyPath);
    rsaEncryptor = RSA(privateKey: privateKey);
  } else if (publicKeyPath.isNotEmpty) {
    final publicKey = await parseKeyFromFile<RSAPublicKey>(publicKeyPath);
    rsaEncryptor = RSA(publicKey: publicKey);
  } else {
    throw NullThrownError();
  }
  return rsaEncryptor;
}

/// Here the encryption key and the initialization vector will be generated and return as Bites
///
/// [securityKey] is the secret key used for encryption
/// [keyExtension] contains random Bytes which will be used along with the secret key to maintain the required minimum key length.
Tuple2<Uint8List, Uint8List> deriveKeyAndIV(
    String securityKey, Uint8List keyExtension) {
  var data = createUint8ListFromString(securityKey);
  var concatenatedHashes = Uint8List(0);
  var currentHash = Uint8List(0);
  var enoughBytesForKey = false;
  var preHash = Uint8List(0);

  while (!enoughBytesForKey) {
    //int preHashLength = currentHash.length + data.length + keyExtension.length;
    if (currentHash.isNotEmpty) {
      preHash = Uint8List.fromList(currentHash + data + keyExtension);
    } else {
      preHash = Uint8List.fromList(data + keyExtension);
    }

    currentHash = md5.convert(preHash).bytes;
    concatenatedHashes = Uint8List.fromList(concatenatedHashes + currentHash);
    if (concatenatedHashes.length >= 48) enoughBytesForKey = true;
  }

  var keyBtyes = concatenatedHashes.sublist(0, 32);
  var ivBtyes = concatenatedHashes.sublist(32, 48);
  return Tuple2(keyBtyes, ivBtyes);
}

/// Convert string into Bytes
///
/// [s] is the string need to be converted.
Uint8List createUint8ListFromString(String s) {
  var ret = Uint8List(s.length);
  for (var i = 0; i < s.length; i++) {
    ret[i] = s.codeUnitAt(i);
  }
  return ret;
}

/// Generate random Bytes with respect to the length provided.
///
/// [seedLength] is the length random Bytes needed.
Uint8List genRandomWithNonZero(int seedLength) {
  final random = Random.secure();
  const randomMax = 245;
  final uint8list = Uint8List(seedLength);
  for (var i = 0; i < seedLength; i++) {
    uint8list[i] = random.nextInt(randomMax) + 1;
  }
  return uint8list;
}

/// RSA encryption keys will be stored somewere in assets, this will be loaded and parsed into RSAAsymmetricKey format.
///
/// [filePath] is the absolute path of the .pem key file.
Future<T> parseKeyFromFile<T extends RSAAsymmetricKey>(String filePath) async {
  final key = await rootBundle.loadStructuredData(filePath, (String s) async {
    return s;
  });
  final parser = RSAKeyParser();
  return parser.parse(key) as T;
}
