import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'value_container.dart';

class CipherTextIvMac {
  final Uint8List cipherText;
  final Uint8List iv;
  final Uint8List mac;

  CipherTextIvMac(this.cipherText, this.iv, this.mac);

  @override
  String toString() {
    ValueContainer object = ValueContainer(
        iv: base64Encode(iv),
        value: base64Encode(cipherText),
        mac: base64Encode(mac));

    var json = jsonEncode(object.toJson());
    print(json);
    return base64Encode(json.codeUnits);
  }

  CipherTextIvMac.fromJson(dynamic json)
      : iv = json['iv'],
        cipherText = json['value'],
        mac = json['mac'];
}

Uint8List generateIv() {
  final _sGen = Random.secure();
  final _seed =
      Uint8List.fromList(List.generate(32, (n) => _sGen.nextInt(256)));
  SecureRandom sec = SecureRandom("Fortuna")..seed(KeyParameter(_seed));
  return sec.nextBytes(16);
}

CipherTextIvMac encrypt(Uint8List plaintext, String key) {
  final iv = generateIv();

  var keyToBytes = Uint8List.fromList(utf8.encode(key));

  var cipherText = aesCbcEncrypt(keyToBytes, iv, plaintext);

  var base64Text = base64Encode(cipherText);

  var mac = generateHashWithHmac256(iv, base64Text, key);

  return CipherTextIvMac(cipherText, iv, toBytes(mac));
}

Uint8List decrypt(CipherTextIvMac civ, String key) {
  var decrypted = aesCbcDecrypt(toBytes(key), civ.iv, civ.cipherText);

  return toBytes(decrypted);
}

String generateHashWithHmac256(Uint8List iv, String base64text, String key) {
  var stringIv = base64Encode(iv);

  var message = stringIv + base64text;

  var hmac = hmacSha256(toBytes(key), toBytes(message));

  return bytesToHex(hmac);
}

String bytesToHex(Uint8List bytes) {
  var hexString = '';
  for (var i = 0; i < bytes.length; i++) {
    var hex = bytes[i].toRadixString(16);
    hexString += (hex.length == 1) ? '0' + hex : hex;
  }
  return hexString.toLowerCase();
}

Uint8List hmacSha256(Uint8List hmacKey, Uint8List data) {
  final hmac = Mac('SHA-256/HMAC')..init(KeyParameter(hmacKey));

  return hmac.process(data);
}

Uint8List toBytes(String value) {
  return Uint8List.fromList(utf8.encode(value));
}

Uint8List aesCbcEncrypt(Uint8List key, Uint8List iv, Uint8List plaintext) {
  final ParametersWithIV<KeyParameter> ivParams =
      ParametersWithIV(KeyParameter(key), iv);

  final cipher = CBCBlockCipher(AESEngine());

  final paddedCipher = PaddedBlockCipherImpl(PKCS7Padding(), cipher)
    ..init(true, PaddedBlockCipherParameters(ivParams, null));

  var paddedPlainText = paddedCipher.process(plaintext);

  return paddedPlainText;
}

String aesCbcDecrypt(Uint8List key, Uint8List iv, Uint8List cipherText) {
  final ParametersWithIV<KeyParameter> ivParams =
      ParametersWithIV(KeyParameter(key), iv);

  final cipher = CBCBlockCipher(AESEngine());

  final paddedCipher = PaddedBlockCipherImpl(PKCS7Padding(), cipher)
    ..init(false, PaddedBlockCipherParameters(ivParams, null));

  final decryptedPaddedPlaintext = paddedCipher.process(cipherText);

  final plaintext = base64Encode(decryptedPaddedPlaintext);

  return plaintext;
}
