import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkg_ffi;

import 'equalx_bindings.dart';
import 'equalx_library.dart';
import 'types.dart';

/// High-level, memory-safe wrappers for the EqualX C ABI.
///
/// Each method marshals `Uint8List` inputs into caller-owned native buffers,
/// invokes the corresponding C entrypoint, and copies results back into Dart
/// objects before releasing the temporary allocations. Callers never receive
/// borrowed pointers and remain responsible for providing appropriately sized
/// capacities where noted (e.g. calldata buffers).
class EqualXApi {
  EqualXApi(this.bindings);

  factory EqualXApi.fromDefaultLibrary() {
    return EqualXApi(EqualXBindings(EqualXLibrary.instance()));
  }

  final EqualXBindings bindings;

  /// Returns the wire-format version advertised by the native library.
  int wireVersion() => bindings.wireVersion();

  /// CLSAG backend identifier reported by the SDK.
  int backendClsagId() => bindings.backendClsagId();

  /// Generates a Monero spend/view keypair.
  ///
  /// Outputs are caller-owned fresh byte arrays.
  MoneroKeypair generateMoneroKeypair() {
    final arena = pkg_ffi.Arena();
    try {
      final spendPtr = arena.allocate<ffi.Uint8>(scalarLength);
      final viewPtr = arena.allocate<ffi.Uint8>(scalarLength);
      _check(
        bindings.generateMoneroKeypair(spendPtr, viewPtr),
        'generate_monero_keypair',
      );
      return MoneroKeypair(
        spendKey: Uint8List.fromList(spendPtr.asTypedList(scalarLength)),
        viewKey: Uint8List.fromList(viewPtr.asTypedList(scalarLength)),
      );
    } finally {
      arena.releaseAll();
    }
  }

  /// Derives a subaddress and its spend key.
  ///
  /// The returned address is ASCII without a trailing NUL terminator.
  MoneroSubaddress deriveMoneroSubaddress({
    required Uint8List viewKey,
    required Uint8List spendKey,
    required int index,
    int addressCapacity = 256,
  }) {
    _requireLength(viewKey, scalarLength, 'viewKey');
    _requireLength(spendKey, scalarLength, 'spendKey');
    if (addressCapacity <= 0) {
      throw ArgumentError.value(
        addressCapacity,
        'addressCapacity',
        'must be > 0',
      );
    }
    final arena = pkg_ffi.Arena();
    try {
      final viewPtr = _bytesToNative(viewKey, arena);
      final spendPtr = _bytesToNative(spendKey, arena);
      final addrPtr = arena.allocate<ffi.Uint8>(addressCapacity);
      final addrLenPtr = arena.allocate<ffi.Uint32>(1);
      final derivedPtr = arena.allocate<ffi.Uint8>(scalarLength);
      _check(
        bindings.moneroDeriveSubaddress(
          viewPtr,
          spendPtr,
          index,
          addrPtr,
          addressCapacity,
          addrLenPtr,
          derivedPtr,
        ),
        'monero_derive_subaddress',
      );
      final addrLen = addrLenPtr.value;
      final ascii = addrPtr.asTypedList(addrLen);
      return MoneroSubaddress(
        address: String.fromCharCodes(ascii),
        derivedSpendKey: Uint8List.fromList(
          derivedPtr.asTypedList(scalarLength),
        ),
      );
    } finally {
      arena.releaseAll();
    }
  }

  /// Computes the Monero key image for `[txPubKey, spendKey]`.
  Uint8List computeMoneroKeyImage({
    required Uint8List txPubKey,
    required Uint8List spendKey,
  }) {
    _requireLength(txPubKey, scalarLength, 'txPubKey');
    _requireLength(spendKey, scalarLength, 'spendKey');
    final arena = pkg_ffi.Arena();
    try {
      final txPtr = _bytesToNative(txPubKey, arena);
      final spendPtr = _bytesToNative(spendKey, arena);
      final outPtr = arena.allocate<ffi.Uint8>(scalarLength);
      _check(
        bindings.moneroComputeKeyImage(txPtr, spendPtr, outPtr),
        'monero_compute_key_image',
      );
      return Uint8List.fromList(outPtr.asTypedList(scalarLength));
    } finally {
      arena.releaseAll();
    }
  }

  /// Generates an EVM secp256k1 keypair (private key + 20-byte address).
  EvmKeypair generateEvmKeypair() {
    final arena = pkg_ffi.Arena();
    try {
      final privPtr = arena.allocate<ffi.Uint8>(scalarLength);
      final addrPtr = arena.allocate<ffi.Uint8>(addressLength);
      _check(
        bindings.generateEvmKeypair(privPtr, addrPtr),
        'generate_evm_keypair',
      );
      return EvmKeypair(
        privateKey: Uint8List.fromList(privPtr.asTypedList(scalarLength)),
        address: Uint8List.fromList(addrPtr.asTypedList(addressLength)),
      );
    } finally {
      arena.releaseAll();
    }
  }

  /// Signs a 32-byte message with an EVM private key.
  Uint8List signEvmMessage({
    required Uint8List privateKey,
    required Uint8List message32,
  }) {
    _requireLength(privateKey, scalarLength, 'privateKey');
    _requireLength(message32, scalarLength, 'message32');
    final arena = pkg_ffi.Arena();
    try {
      final privPtr = _bytesToNative(privateKey, arena);
      final msgPtr = _bytesToNative(message32, arena);
      final sigPtr = arena.allocate<ffi.Uint8>(65);
      _check(
        bindings.signEvmMessage(privPtr, msgPtr, sigPtr),
        'sign_evm_message',
      );
      return Uint8List.fromList(sigPtr.asTypedList(65));
    } finally {
      arena.releaseAll();
    }
  }

  /// Creates a CLSAG pre-signature container.
  ///
  /// [outputCapacity] must match the caller-owned buffer size that receives the
  /// serialized container. Increase it if you expect larger witness maps.
  Uint8List clsagMakePreSignature({
    required Uint8List message,
    required Uint8List ring,
    required int realIndex,
    required Uint8List swapId,
    required Uint8List settlementCtx,
    int outputCapacity = 4096,
  }) {
    if (message.isEmpty) {
      throw ArgumentError('message must not be empty');
    }
    if (ring.isEmpty || ring.length % 32 != 0) {
      throw ArgumentError('ring must be a non-empty multiple of 32 bytes');
    }
    if (outputCapacity <= 0) {
      throw ArgumentError.value(
        outputCapacity,
        'outputCapacity',
        'must be > 0',
      );
    }
    _requireLength(swapId, swapIdLength, 'swapId');
    final arena = pkg_ffi.Arena();
    try {
      final msgPtr = _bytesToNative(message, arena);
      final ringPtr = _bytesToNative(ring, arena);
      final swapPtr = _bytesToNative(swapId, arena);
      final ctxPtr = _bytesToNative(settlementCtx, arena, allowEmpty: false);
      final outPtr = arena.allocate<ffi.Uint8>(outputCapacity);
      final outLenPtr = arena.allocate<ffi.Uint32>(1);
      _check(
        bindings.clsagMakePreSig(
          msgPtr,
          message.length,
          ringPtr,
          ring.length,
          realIndex,
          swapPtr,
          ctxPtr,
          settlementCtx.length,
          outPtr,
          outLenPtr,
        ),
        'clsag_make_pre_sig',
      );
      final outLen = outLenPtr.value;
      return Uint8List.fromList(outPtr.asTypedList(outLen));
    } finally {
      arena.releaseAll();
    }
  }

  /// Completes a CLSAG signature in-place.
  Uint8List clsagComplete({
    required Uint8List preSignature,
    required Uint8List adaptorSecret,
    int outputCapacity = 2048,
  }) {
    if (preSignature.isEmpty) {
      throw ArgumentError('preSignature must not be empty');
    }
    _requireLength(adaptorSecret, scalarLength, 'adaptorSecret');
    if (outputCapacity <= 0) {
      throw ArgumentError.value(
        outputCapacity,
        'outputCapacity',
        'must be > 0',
      );
    }
    final arena = pkg_ffi.Arena();
    try {
      final prePtr = _bytesToNative(preSignature, arena);
      final secretPtr = _bytesToNative(adaptorSecret, arena);
      final outPtr = arena.allocate<ffi.Uint8>(outputCapacity);
      final outLenPtr = arena.allocate<ffi.Uint32>(1);
      _check(
        bindings.clsagComplete(
          prePtr,
          preSignature.length,
          secretPtr,
          adaptorSecret.length,
          outPtr,
          outLenPtr,
        ),
        'clsag_complete',
      );
      final outLen = outLenPtr.value;
      return Uint8List.fromList(outPtr.asTypedList(outLen));
    } finally {
      arena.releaseAll();
    }
  }

  /// Verifies that a final CLSAG matches the pre-signature transcript.
  bool clsagVerify({
    required Uint8List preSignature,
    required Uint8List finalSignature,
  }) {
    if (preSignature.isEmpty || finalSignature.isEmpty) {
      throw ArgumentError('preSignature/finalSignature must not be empty');
    }
    final arena = pkg_ffi.Arena();
    try {
      final prePtr = _bytesToNative(preSignature, arena);
      final finalPtr = _bytesToNative(finalSignature, arena);
      final okPtr = arena.allocate<ffi.Uint8>(1);
      _check(
        bindings.clsagVerify(
          prePtr,
          preSignature.length,
          finalPtr,
          finalSignature.length,
          okPtr,
        ),
        'clsag_verify',
      );
      return okPtr.value != 0;
    } finally {
      arena.releaseAll();
    }
  }

  /// Extracts the adaptor secret scalar from a pre/final signature pair.
  Uint8List clsagExtractAdaptorSecret({
    required Uint8List preSignature,
    required Uint8List finalSignature,
  }) {
    if (preSignature.isEmpty || finalSignature.isEmpty) {
      throw ArgumentError('preSignature/finalSignature must not be empty');
    }
    final arena = pkg_ffi.Arena();
    try {
      final prePtr = _bytesToNative(preSignature, arena);
      final finalPtr = _bytesToNative(finalSignature, arena);
      final outPtr = arena.allocate<ffi.Uint8>(scalarLength);
      _check(
        bindings.clsagExtract(
          prePtr,
          preSignature.length,
          finalPtr,
          finalSignature.length,
          outPtr,
        ),
        'clsag_extract_t',
      );
      return Uint8List.fromList(outPtr.asTypedList(scalarLength));
    } finally {
      arena.releaseAll();
    }
  }

  /// Prepares a Monero refund transaction template.
  RefundData prepareRefund({
    required Uint8List settlementCtx,
    required Uint8List swapId,
    required int xmrLockHeight,
    required int ethExpiry,
    required int delta,
    required Uint8List templateBytes,
    int txCapacity = 8192,
  }) {
    _requireLength(swapId, swapIdLength, 'swapId');
    if (txCapacity <= 0) {
      throw ArgumentError.value(txCapacity, 'txCapacity', 'must be > 0');
    }
    final arena = pkg_ffi.Arena();
    try {
      final ctxPtr = _bytesToNative(settlementCtx, arena);
      final swapPtr = _bytesToNative(swapId, arena);
      final tmplPtr = _bytesToNative(templateBytes, arena, allowEmpty: true);
      final outPtr = arena.allocate<ffi.Uint8>(txCapacity);
      final outLenPtr = arena.allocate<ffi.Uint32>(1);
      final lockPtr = arena.allocate<ffi.Uint64>(1);
      _check(
        bindings.prepareRefund(
          ctxPtr,
          settlementCtx.length,
          swapPtr,
          xmrLockHeight,
          ethExpiry,
          delta,
          tmplPtr,
          templateBytes.length,
          outPtr,
          txCapacity,
          outLenPtr,
          lockPtr,
        ),
        'prepare_refund',
      );
      final txLen = outLenPtr.value;
      return RefundData(
        transaction: Uint8List.fromList(outPtr.asTypedList(txLen)),
        lockTime: lockPtr.value,
      );
    } finally {
      arena.releaseAll();
    }
  }

  /// Encodes the calldata/value pair for `Escrow.lockETH`.
  EncodedCall encodeEscrowLockEth({
    required Uint8List escrowAddress,
    required Uint8List swapId,
    required Uint8List taker,
    required Uint8List adaptorHash,
    required Uint8List maker,
    required Uint8List amountBigEndian,
    required Uint8List tipBigEndian,
    required int expiry,
    required int backendId,
    required Uint8List settleDigest,
    int? gasLimit,
    int dataCapacity = 512,
  }) {
    _requireLength(escrowAddress, addressLength, 'escrowAddress');
    _requireLength(swapId, swapIdLength, 'swapId');
    _requireLength(taker, addressLength, 'taker');
    _requireLength(adaptorHash, scalarLength, 'adaptorHash');
    _requireLength(maker, addressLength, 'maker');
    _requireLength(amountBigEndian, u256Length, 'amountBigEndian');
    _requireLength(tipBigEndian, u256Length, 'tipBigEndian');
    _requireLength(settleDigest, scalarLength, 'settleDigest');
    if (dataCapacity <= 0) {
      throw ArgumentError.value(dataCapacity, 'dataCapacity', 'must be > 0');
    }
    final arena = pkg_ffi.Arena();
    try {
      final escrowPtr = _bytesToNative(escrowAddress, arena);
      final swapPtr = _bytesToNative(swapId, arena);
      final takerPtr = _bytesToNative(taker, arena);
      final adaptorPtr = _bytesToNative(adaptorHash, arena);
      final makerPtr = _bytesToNative(maker, arena);
      final amountPtr = _bytesToNative(amountBigEndian, arena);
      final tipPtr = _bytesToNative(tipBigEndian, arena);
      final digestPtr = _bytesToNative(settleDigest, arena);
      final outPtr = arena.allocate<ffi.Uint8>(dataCapacity);
      final outLenPtr = arena.allocate<ffi.Uint32>(1);
      final valuePtr = arena.allocate<ffi.Uint8>(u256Length);
      final gasPtr = arena.allocate<ffi.Uint64>(1);
      _check(
        bindings.lockEth(
          escrowPtr,
          swapPtr,
          takerPtr,
          adaptorPtr,
          makerPtr,
          amountPtr,
          tipPtr,
          expiry,
          backendId,
          digestPtr,
          gasLimit ?? 0,
          outPtr,
          dataCapacity,
          outLenPtr,
          valuePtr,
          gasPtr,
        ),
        'escrow_lock_eth_call',
      );
      return _encodedCallFromPointers(
        outPtr,
        outLenPtr.value,
        valuePtr,
        gasPtr.value,
      );
    } finally {
      arena.releaseAll();
    }
  }

  /// Encodes the calldata/value pair for `Escrow.refund`.
  EncodedCall encodeEscrowRefund({
    required Uint8List escrowAddress,
    required Uint8List swapId,
    int? gasLimit,
    int dataCapacity = 256,
  }) {
    _requireLength(escrowAddress, addressLength, 'escrowAddress');
    _requireLength(swapId, swapIdLength, 'swapId');
    if (dataCapacity <= 0) {
      throw ArgumentError.value(dataCapacity, 'dataCapacity', 'must be > 0');
    }
    final arena = pkg_ffi.Arena();
    try {
      final escrowPtr = _bytesToNative(escrowAddress, arena);
      final swapPtr = _bytesToNative(swapId, arena);
      final outPtr = arena.allocate<ffi.Uint8>(dataCapacity);
      final outLenPtr = arena.allocate<ffi.Uint32>(1);
      final valuePtr = arena.allocate<ffi.Uint8>(u256Length);
      final gasPtr = arena.allocate<ffi.Uint64>(1);
      _check(
        bindings.escrowRefund(
          escrowPtr,
          swapPtr,
          gasLimit ?? 0,
          outPtr,
          dataCapacity,
          outLenPtr,
          valuePtr,
          gasPtr,
        ),
        'escrow_refund_call',
      );
      return _encodedCallFromPointers(
        outPtr,
        outLenPtr.value,
        valuePtr,
        gasPtr.value,
      );
    } finally {
      arena.releaseAll();
    }
  }

  /// Decodes escrow logs into structured events.
  List<EscrowEventDecoded> decodeEscrowEvents({
    required Uint8List settlementCtx,
    required List<EscrowLogEntry> logs,
    int maxEvents = 8,
  }) {
    if (maxEvents <= 0) {
      throw ArgumentError.value(maxEvents, 'maxEvents', 'must be > 0');
    }
    final arena = pkg_ffi.Arena();
    try {
      final ctxPtr = _bytesToNative(settlementCtx, arena);
      final logsPtr = logs.isEmpty
          ? ffi.nullptr.cast<NativeEscrowLog>()
          : arena.allocate<NativeEscrowLog>(logs.length);
      if (logs.isNotEmpty) {
        for (var i = 0; i < logs.length; i++) {
          final dst = logsPtr.elementAt(i).ref;
          final entry = logs[i];
          dst.kind = entry.kind;
          dst.backend = entry.backend;
          _requireLength(entry.swapId, swapIdLength, 'logs[$i].swapId');
          _requireLength(
            entry.amountBigEndian,
            u256Length,
            'logs[$i].amountBigEndian',
          );
          _writeArray(dst.swapId, entry.swapId);
          _writeArray(dst.amountBe, entry.amountBigEndian);
        }
      }
      final outPtr = arena.allocate<NativeEscrowEvent>(maxEvents);
      final writtenPtr = arena.allocate<ffi.Uint32>(1);
      _check(
        bindings.decodeEvents(
          ctxPtr,
          settlementCtx.length,
          logsPtr,
          logs.length,
          outPtr,
          maxEvents,
          writtenPtr,
        ),
        'decode_escrow_events',
      );
      final written = writtenPtr.value;
      final events = <EscrowEventDecoded>[];
      for (var i = 0; i < written; i++) {
        final src = outPtr.elementAt(i).ref;
        events.add(
          EscrowEventDecoded(
            kind: src.kind,
            backend: src.backend,
            digest: _arrayToBytes(src.digest),
            swapId: _arrayToBytes(src.swapId),
            amountBigEndian: _arrayToBytes(src.amountBe),
          ),
        );
      }
      return events;
    } finally {
      arena.releaseAll();
    }
  }

  /// Encodes calldata/value for `QuoteBoard.postTxHash`.
  EncodedCall encodePostTxHash({
    required Uint8List boardAddress,
    required Uint8List swapId,
    required Uint8List moneroTxHash,
    Uint8List? tauPublic,
    required Uint8List evmPrivateKey,
    int? gasLimit,
    int dataCapacity = 512,
  }) {
    _requireLength(boardAddress, addressLength, 'boardAddress');
    _requireLength(swapId, swapIdLength, 'swapId');
    _requireLength(moneroTxHash, swapIdLength, 'moneroTxHash');
    _requireLength(evmPrivateKey, scalarLength, 'evmPrivateKey');
    if (dataCapacity <= 0) {
      throw ArgumentError.value(dataCapacity, 'dataCapacity', 'must be > 0');
    }
    final arena = pkg_ffi.Arena();
    try {
      final tauBytes = tauPublic ?? Uint8List(0);
      final boardPtr = _bytesToNative(boardAddress, arena);
      final swapPtr = _bytesToNative(swapId, arena);
      final txPtr = _bytesToNative(moneroTxHash, arena);
      final tauPtr = _bytesToNative(tauBytes, arena, allowEmpty: true);
      final privPtr = _bytesToNative(evmPrivateKey, arena);
      final outPtr = arena.allocate<ffi.Uint8>(dataCapacity);
      final outLenPtr = arena.allocate<ffi.Uint32>(1);
      final valuePtr = arena.allocate<ffi.Uint8>(u256Length);
      final gasPtr = arena.allocate<ffi.Uint64>(1);
      _check(
        bindings.postTxHash(
          boardPtr,
          swapPtr,
          txPtr,
          tauPtr,
          tauBytes.length,
          privPtr,
          gasLimit ?? 0,
          outPtr,
          dataCapacity,
          outLenPtr,
          valuePtr,
          gasPtr,
        ),
        'post_tx_hash_call',
      );
      return _encodedCallFromPointers(
        outPtr,
        outLenPtr.value,
        valuePtr,
        gasPtr.value,
      );
    } finally {
      arena.releaseAll();
    }
  }

  /// Encodes calldata/value for `Escrow.settle`.
  EncodedCall encodeEscrowSettle({
    required Uint8List escrowAddress,
    required Uint8List swapId,
    required Uint8List adaptorSecret,
    int? gasLimit,
    int dataCapacity = 256,
  }) {
    _requireLength(escrowAddress, addressLength, 'escrowAddress');
    _requireLength(swapId, swapIdLength, 'swapId');
    _requireLength(adaptorSecret, scalarLength, 'adaptorSecret');
    if (dataCapacity <= 0) {
      throw ArgumentError.value(dataCapacity, 'dataCapacity', 'must be > 0');
    }
    final arena = pkg_ffi.Arena();
    try {
      final escrowPtr = _bytesToNative(escrowAddress, arena);
      final swapPtr = _bytesToNative(swapId, arena);
      final secretPtr = _bytesToNative(adaptorSecret, arena);
      final outPtr = arena.allocate<ffi.Uint8>(dataCapacity);
      final outLenPtr = arena.allocate<ffi.Uint32>(1);
      final valuePtr = arena.allocate<ffi.Uint8>(u256Length);
      final gasPtr = arena.allocate<ffi.Uint64>(1);
      _check(
        bindings.escrowSettle(
          escrowPtr,
          swapPtr,
          secretPtr,
          gasLimit ?? 0,
          outPtr,
          dataCapacity,
          outLenPtr,
          valuePtr,
          gasPtr,
        ),
        'escrow_settle_call',
      );
      return _encodedCallFromPointers(
        outPtr,
        outLenPtr.value,
        valuePtr,
        gasPtr.value,
      );
    } finally {
      arena.releaseAll();
    }
  }

  /// Encodes calldata/value for `Escrow.lockERC20`.
  EncodedCall encodeEscrowLockErc20({
    required Uint8List escrowAddress,
    required Uint8List swapId,
    required Uint8List taker,
    required Uint8List token,
    required Uint8List amountBigEndian,
    required Uint8List tipBigEndian,
    required Uint8List adaptorHash,
    required Uint8List maker,
    required int expiry,
    required int backendId,
    required Uint8List settleDigest,
    Uint8List? permit,
    int? gasLimit,
    int dataCapacity = 512,
  }) {
    _requireLength(escrowAddress, addressLength, 'escrowAddress');
    _requireLength(swapId, swapIdLength, 'swapId');
    _requireLength(taker, addressLength, 'taker');
    _requireLength(token, addressLength, 'token');
    _requireLength(amountBigEndian, u256Length, 'amountBigEndian');
    _requireLength(tipBigEndian, u256Length, 'tipBigEndian');
    _requireLength(adaptorHash, scalarLength, 'adaptorHash');
    _requireLength(maker, addressLength, 'maker');
    _requireLength(settleDigest, scalarLength, 'settleDigest');
    if (dataCapacity <= 0) {
      throw ArgumentError.value(dataCapacity, 'dataCapacity', 'must be > 0');
    }
    final arena = pkg_ffi.Arena();
    try {
      final escrowPtr = _bytesToNative(escrowAddress, arena);
      final swapPtr = _bytesToNative(swapId, arena);
      final takerPtr = _bytesToNative(taker, arena);
      final tokenPtr = _bytesToNative(token, arena);
      final amountPtr = _bytesToNative(amountBigEndian, arena);
      final tipPtr = _bytesToNative(tipBigEndian, arena);
      final adaptorPtr = _bytesToNative(adaptorHash, arena);
      final makerPtr = _bytesToNative(maker, arena);
      final digestPtr = _bytesToNative(settleDigest, arena);
      final permitBytes = permit ?? Uint8List(0);
      final permitPtr = _bytesToNative(permitBytes, arena, allowEmpty: true);
      final outPtr = arena.allocate<ffi.Uint8>(dataCapacity);
      final outLenPtr = arena.allocate<ffi.Uint32>(1);
      final valuePtr = arena.allocate<ffi.Uint8>(u256Length);
      final gasPtr = arena.allocate<ffi.Uint64>(1);
      _check(
        bindings.lockErc20(
          escrowPtr,
          swapPtr,
          takerPtr,
          tokenPtr,
          amountPtr,
          tipPtr,
          adaptorPtr,
          makerPtr,
          expiry,
          backendId,
          digestPtr,
          permitPtr,
          permitBytes.length,
          gasLimit ?? 0,
          outPtr,
          dataCapacity,
          outLenPtr,
          valuePtr,
          gasPtr,
        ),
        'escrow_lock_erc20_call',
      );
      return _encodedCallFromPointers(
        outPtr,
        outLenPtr.value,
        valuePtr,
        gasPtr.value,
      );
    } finally {
      arena.releaseAll();
    }
  }

  EncodedCall _encodedCallFromPointers(
    ffi.Pointer<ffi.Uint8> dataPtr,
    int dataLen,
    ffi.Pointer<ffi.Uint8> valuePtr,
    int gasLimit,
  ) {
    final data = Uint8List.fromList(dataPtr.asTypedList(dataLen));
    final value = Uint8List.fromList(valuePtr.asTypedList(u256Length));
    return EncodedCall(data: data, value: value, gasLimit: gasLimit);
  }

  void _check(int rc, String context) {
    if (rc != 0) {
      throw EqualXException(rc, context);
    }
  }
}

ffi.Pointer<ffi.Uint8> _bytesToNative(
  Uint8List data,
  pkg_ffi.Arena arena, {
  bool allowEmpty = false,
}) {
  if (data.isEmpty) {
    if (!allowEmpty) {
      throw ArgumentError('Input buffer cannot be empty');
    }
    return ffi.nullptr.cast<ffi.Uint8>();
  }
  final ptr = arena.allocate<ffi.Uint8>(data.length);
  ptr.asTypedList(data.length).setAll(0, data);
  return ptr;
}

void _requireLength(Uint8List data, int expected, String name) {
  if (data.length != expected) {
    throw ArgumentError.value(data.length, name, 'must be $expected bytes');
  }
}

void _writeArray(ffi.Array<ffi.Uint8> target, Uint8List bytes) {
  for (var i = 0; i < bytes.length; i++) {
    target[i] = bytes[i];
  }
}

Uint8List _arrayToBytes(ffi.Array<ffi.Uint8> array,
    {int length = scalarLength}) {
  final out = Uint8List(length);
  for (var i = 0; i < length; i++) {
    out[i] = array[i];
  }
  return out;
}
