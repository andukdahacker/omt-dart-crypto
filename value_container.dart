class ValueContainer {
  String? iv;
  String? value;
  String? mac;

  ValueContainer({required this.iv, required this.value, required this.mac});

  ValueContainer.fromJson(dynamic json) {
    iv = json['iv'];
    value = json['value'];
    mac = json['mac'];
  }

  Map<String, dynamic> toJson() => {
        'iv': this.iv,
        'value': this.value,
        'mac': this.mac,
      };
}
