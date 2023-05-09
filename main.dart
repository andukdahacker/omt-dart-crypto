import 'dart:convert';
import 'dart:typed_data';

import 'cipher_text_iv_mac.dart';

const mockData = {
  "data": {"key": "value"}
};

void main() {
  var bytes =
      Uint8List.fromList(utf8.encode(mockData.toString())); // data being hashed

  var encryptionKey = "3pphDIan7b6qRZIMs7X8xSxoM9QguYRZ";

  var newString = encrypt(bytes, encryptionKey);
  var decrypted = decrypt(newString, encryptionKey);
  print(base64Encode(decrypted));
  print(newString.toString());
}
