import 'package:encryptor/encryptor.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  setUpAll(() {
    TestWidgetsFlutterBinding.ensureInitialized();
  });
  group('Encryption Test', () {
    test('AES', () {
      const key = 'secreatk!';
      const data = 'Text to encrypt 😀';

      final encrypted = data.encryptAESCrypto(securedKey: key);
      final decrypted = encrypted.decryptAESCrypto(securedKey: key);

      expect(data, equals(decrypted));
    });

    test('Salsa20', () {
      const key = 'secreatk!';
      const data = 'Text to encrypt 😀';

      final encrypted = data.encryptSalsaCrypto(securedKey: key);
      final decrypted = encrypted.decryptSalsaCrypto(securedKey: key);

      expect(data, equals(decrypted));
    });

    test('Fernet', () {
      const key = 'secreatk!';
      const data = 'Text to encrypt 😀';

      final encrypted = data.encryptFernetCrypto(securedKey: key);
      final decrypted = encrypted.decryptFernetCrypto(securedKey: key);

      expect(data, equals(decrypted));
    });

    test('RSA', () async {
      const data = 'Text to encrypt 😀';
      final encrypted =
          await data.encryptRSACrypto(publicKeyPath: 'assets/public.pem');
      final decrypted = await encrypted.decryptRSACrypto(
        privateKeyPath: 'assets/private.pem',
      );
      expect(data, equals(decrypted));
    });
  });
}
