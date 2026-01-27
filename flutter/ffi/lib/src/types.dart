import 'dart:typed_data';

/// Generic EqualX FFI error.
class EqualXException implements Exception {
  const EqualXException(this.code, this.context);

  final int code;
  final String context;

  @override
  String toString() => 'EqualXException(code: $code, context: $context)';
}

class MoneroKeypair {
  const MoneroKeypair({required this.spendKey, required this.viewKey});

  final Uint8List spendKey;
  final Uint8List viewKey;
}

class MoneroSubaddress {
  const MoneroSubaddress({
    required this.address,
    required this.derivedSpendKey,
  });

  final String address;
  final Uint8List derivedSpendKey;
}

class EvmKeypair {
  const EvmKeypair({required this.privateKey, required this.address});

  final Uint8List privateKey;
  final Uint8List address;
}

class RefundData {
  const RefundData({required this.transaction, required this.lockTime});

  final Uint8List transaction;
  final int lockTime;
}

class EncodedCall {
  const EncodedCall({
    required this.data,
    required this.value,
    required this.gasLimit,
  });

  final Uint8List data;
  final Uint8List value;
  final int gasLimit;
}

class EscrowLogEntry {
  const EscrowLogEntry({
    required this.kind,
    required this.backend,
    required this.swapId,
    required this.amountBigEndian,
  });

  final int kind;
  final int backend;
  final Uint8List swapId;
  final Uint8List amountBigEndian;
}

class EscrowEventDecoded {
  const EscrowEventDecoded({
    required this.kind,
    required this.backend,
    required this.digest,
    required this.swapId,
    required this.amountBigEndian,
  });

  final int kind;
  final int backend;
  final Uint8List digest;
  final Uint8List swapId;
  final Uint8List amountBigEndian;
}

const int swapIdLength = 32;
const int addressLength = 20;
const int scalarLength = 32;
const int u256Length = 32;
