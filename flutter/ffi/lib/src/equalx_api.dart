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

  /// Returns runtime library capabilities and advertised API groups.
  CapabilityDescriptor capabilityQuery() {
    final arena = pkg_ffi.Arena();
    try {
      final out = arena.allocate<NativeCapabilityDescriptor>(1);
      _check(bindings.capabilityQuery(out), 'capability_query');
      final value = out.ref;
      return CapabilityDescriptor(
        versionMajor: value.versionMajor,
        versionMinor: value.versionMinor,
        versionPatch: value.versionPatch,
        backends: value.backends,
        apiGroups: value.apiGroups,
        wireVersion: value.wireVersion,
      );
    } finally {
      arena.releaseAll();
    }
  }

  /// Registers a compressed secp256k1 encryption pubkey for an owner address.
  void registerEncPub({
    required Uint8List ownerAddress,
    required Uint8List compressedPubkey,
  }) {
    _requireLength(ownerAddress, addressLength, 'ownerAddress');
    _requireLength(compressedPubkey, 33, 'compressedPubkey');
    final arena = pkg_ffi.Arena();
    try {
      final ownerPtr = _bytesToNative(ownerAddress, arena);
      final keyPtr = _bytesToNative(compressedPubkey, arena);
      _check(
        bindings.registerEncPub(ownerPtr, keyPtr, compressedPubkey.length),
        'register_enc_pub',
      );
    } finally {
      arena.releaseAll();
    }
  }

  /// Returns the registered compressed pubkey for an owner.
  Uint8List getEncPub({required Uint8List ownerAddress}) {
    _requireLength(ownerAddress, addressLength, 'ownerAddress');
    final arena = pkg_ffi.Arena();
    try {
      final ownerPtr = _bytesToNative(ownerAddress, arena);
      final outPtrPtr = arena.allocate<ffi.Pointer<ffi.Uint8>>(1);
      final outLenPtr = arena.allocate<ffi.Uint32>(1);
      _check(bindings.getEncPub(ownerPtr, outPtrPtr, outLenPtr), 'get_enc_pub');
      return _consumeOwnedBuffer(outPtrPtr.value, outLenPtr.value);
    } finally {
      arena.releaseAll();
    }
  }

  /// Returns whether an owner has a key registered.
  bool isRegistered({required Uint8List ownerAddress}) {
    _requireLength(ownerAddress, addressLength, 'ownerAddress');
    final arena = pkg_ffi.Arena();
    try {
      final ownerPtr = _bytesToNative(ownerAddress, arena);
      final outRegistered = arena.allocate<ffi.Uint8>(1);
      _check(bindings.isRegistered(ownerPtr, outRegistered), 'is_registered');
      return outRegistered.value != 0;
    } finally {
      arena.releaseAll();
    }
  }

  /// Publishes an encrypted taker-context envelope to mailbox storage.
  void publishContext({
    required Uint8List reservationId,
    required Uint8List envelope,
  }) {
    _publishMailbox(
      op: bindings.publishContext,
      context: 'publish_context',
      reservationId: reservationId,
      envelope: envelope,
    );
  }

  /// Publishes an encrypted presig envelope to mailbox storage.
  void publishPresig({
    required Uint8List reservationId,
    required Uint8List envelope,
  }) {
    _publishMailbox(
      op: bindings.publishPresig,
      context: 'publish_presig',
      reservationId: reservationId,
      envelope: envelope,
    );
  }

  /// Publishes an encrypted final-signature envelope to mailbox storage.
  void publishFinalSig({
    required Uint8List reservationId,
    required Uint8List envelope,
  }) {
    _publishMailbox(
      op: bindings.publishFinalSig,
      context: 'publish_final_sig',
      reservationId: reservationId,
      envelope: envelope,
    );
  }

  /// Fetches all mailbox messages for a reservation.
  List<Uint8List> fetchMessages({required Uint8List reservationId}) {
    _requireLength(reservationId, swapIdLength, 'reservationId');
    final arena = pkg_ffi.Arena();
    try {
      final reservationPtr = _bytesToNative(reservationId, arena);
      final outPtrPtr = arena.allocate<ffi.Pointer<ffi.Uint8>>(1);
      final outLenPtr = arena.allocate<ffi.Uint32>(1);
      _check(
        bindings.fetchMessages(reservationPtr, outPtrPtr, outLenPtr),
        'fetch_messages',
      );
      final bytes = _consumeOwnedBuffer(outPtrPtr.value, outLenPtr.value);
      return _decodeMailboxPayload(bytes);
    } finally {
      arena.releaseAll();
    }
  }

  /// Creates a new orchestrator handle over host-provided callback tables.
  ffi.Pointer<ffi.Void> orchestratorNew({
    required ffi.Pointer<ffi.Void> keyCallbacks,
    required ffi.Pointer<ffi.Void> evmCallbacks,
    required ffi.Pointer<ffi.Void> moneroCallbacks,
    required ffi.Pointer<ffi.Void> persistenceCallbacks,
    required ffi.Pointer<ffi.Void> timeCallbacks,
    required ffi.Pointer<ffi.Void> uxCallbacks,
    OrchestratorConfig? config,
  }) {
    _requirePointer(keyCallbacks, 'keyCallbacks');
    _requirePointer(evmCallbacks, 'evmCallbacks');
    _requirePointer(moneroCallbacks, 'moneroCallbacks');
    _requirePointer(persistenceCallbacks, 'persistenceCallbacks');
    _requirePointer(timeCallbacks, 'timeCallbacks');
    _requirePointer(uxCallbacks, 'uxCallbacks');
    final arena = pkg_ffi.Arena();
    try {
      final outHandle =
          arena.allocate<ffi.Pointer<NativeFfiOrchestratorHandle>>(1);
      final cfgPtr = config == null
          ? ffi.nullptr.cast<NativeOrchestratorConfig>()
          : arena.allocate<NativeOrchestratorConfig>(1);
      if (config != null) {
        cfgPtr.ref.checkpointVersion = config.checkpointVersion;
        cfgPtr.ref.makerTimeoutSecs = config.makerTimeoutSecs;
        cfgPtr.ref.takerTimeoutSecs = config.takerTimeoutSecs;
      }
      _check(
        bindings.orchestratorNew(
          keyCallbacks,
          evmCallbacks,
          moneroCallbacks,
          persistenceCallbacks,
          timeCallbacks,
          uxCallbacks,
          cfgPtr,
          outHandle,
        ),
        'orchestrator_new',
      );
      return outHandle.value.cast<ffi.Void>();
    } finally {
      arena.releaseAll();
    }
  }

  /// Releases an orchestrator handle previously returned by [orchestratorNew].
  void orchestratorFree(ffi.Pointer<ffi.Void> handle) {
    _requirePointer(handle, 'handle');
    bindings.orchestratorFree(handle.cast<NativeFfiOrchestratorHandle>());
  }

  /// Resumes orchestrator state for a reservation and returns its parsed state.
  SwapState orchestratorResume({
    required ffi.Pointer<ffi.Void> handle,
    required Uint8List reservationId,
  }) {
    _requirePointer(handle, 'handle');
    _requireLength(reservationId, swapIdLength, 'reservationId');
    final arena = pkg_ffi.Arena();
    try {
      final reservationPtr = _bytesToNative(reservationId, arena);
      final outStatePtr = arena.allocate<ffi.Pointer<ffi.Uint8>>(1);
      final outStateLen = arena.allocate<ffi.Uint32>(1);
      _check(
        bindings.orchestratorResume(
          handle.cast<NativeFfiOrchestratorHandle>(),
          reservationPtr,
          outStatePtr,
          outStateLen,
        ),
        'orchestrator_resume',
      );
      final rawBytes =
          _consumeOwnedBuffer(outStatePtr.value, outStateLen.value);
      final stateString = String.fromCharCodes(rawBytes);
      return SwapState.fromDebugString(stateString);
    } finally {
      arena.releaseAll();
    }
  }

  /// Executes one orchestrator command and returns the optional 32-byte result.
  Uint8List orchestratorStep({
    required ffi.Pointer<ffi.Void> handle,
    required Uint8List reservationId,
    required int commandId,
    Uint8List? payload,
  }) {
    _requirePointer(handle, 'handle');
    _requireLength(reservationId, swapIdLength, 'reservationId');
    if (commandId <= 0) {
      throw ArgumentError.value(commandId, 'commandId', 'must be > 0');
    }
    final payloadBytes = payload ?? Uint8List(0);
    _validateStepPayload(commandId, payloadBytes);
    final arena = pkg_ffi.Arena();
    try {
      final reservationPtr = _bytesToNative(reservationId, arena);
      final payloadPtr = _bytesToNative(payloadBytes, arena, allowEmpty: true);
      final outResult = arena.allocate<ffi.Uint8>(32);
      _check(
        bindings.orchestratorStep(
          handle.cast<NativeFfiOrchestratorHandle>(),
          reservationPtr,
          commandId,
          payloadPtr,
          payloadBytes.length,
          outResult,
        ),
        'orchestrator_step',
      );
      return Uint8List.fromList(outResult.asTypedList(32));
    } finally {
      arena.releaseAll();
    }
  }

  /// Checks orchestrator deadline expirations.
  List<SwapLifecycleEvent> orchestratorCheckDeadlines({
    required ffi.Pointer<ffi.Void> handle,
    int maxEvents = 16,
  }) {
    _requirePointer(handle, 'handle');
    if (maxEvents <= 0) {
      throw ArgumentError.value(maxEvents, 'maxEvents', 'must be > 0');
    }
    final arena = pkg_ffi.Arena();
    try {
      final outEvents = arena.allocate<NativeDeadlineEvent>(maxEvents);
      final outLen = arena.allocate<ffi.Uint32>(1);
      _check(
        bindings.orchestratorCheckDeadlines(
          handle.cast<NativeFfiOrchestratorHandle>(),
          outEvents,
          maxEvents,
          outLen,
        ),
        'orchestrator_check_deadlines',
      );
      final count = outLen.value;
      final events = <SwapLifecycleEvent>[];
      for (var i = 0; i < count; i++) {
        final event = (outEvents + i).ref;
        events.add(
          SwapLifecycleEvent.deadlineExceeded(
            reservationId:
                _arrayToBytes(event.reservationId, length: swapIdLength),
            deadline: event.deadline,
          ),
        );
      }
      return events;
    } finally {
      arena.releaseAll();
    }
  }

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
      outLenPtr.value = outputCapacity;
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
      if (outLen > outputCapacity) {
        throw StateError(
          'clsag_make_pre_sig returned length $outLen beyond capacity $outputCapacity',
        );
      }
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
      outLenPtr.value = outputCapacity;
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
      if (outLen > outputCapacity) {
        throw StateError(
          'clsag_complete returned length $outLen beyond capacity $outputCapacity',
        );
      }
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
          final dst = (logsPtr + i).ref;
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
        final src = (outPtr + i).ref;
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
    required Uint8List minReceivedBigEndian,
    int? gasLimit,
    int dataCapacity = 256,
  }) {
    _requireLength(escrowAddress, addressLength, 'escrowAddress');
    _requireLength(swapId, swapIdLength, 'swapId');
    _requireLength(adaptorSecret, scalarLength, 'adaptorSecret');
    _requireLength(minReceivedBigEndian, u256Length, 'minReceivedBigEndian');
    if (dataCapacity <= 0) {
      throw ArgumentError.value(dataCapacity, 'dataCapacity', 'must be > 0');
    }
    final arena = pkg_ffi.Arena();
    try {
      final escrowPtr = _bytesToNative(escrowAddress, arena);
      final swapPtr = _bytesToNative(swapId, arena);
      final secretPtr = _bytesToNative(adaptorSecret, arena);
      final minReceivedPtr = _bytesToNative(minReceivedBigEndian, arena);
      final outPtr = arena.allocate<ffi.Uint8>(dataCapacity);
      final outLenPtr = arena.allocate<ffi.Uint32>(1);
      final valuePtr = arena.allocate<ffi.Uint8>(u256Length);
      final gasPtr = arena.allocate<ffi.Uint64>(1);
      _check(
        bindings.escrowSettle(
          escrowPtr,
          swapPtr,
          secretPtr,
          minReceivedPtr,
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

  void _publishMailbox({
    required int Function(
      ffi.Pointer<ffi.Uint8>,
      ffi.Pointer<ffi.Uint8>,
      int,
    ) op,
    required String context,
    required Uint8List reservationId,
    required Uint8List envelope,
  }) {
    _requireLength(reservationId, swapIdLength, 'reservationId');
    if (envelope.isEmpty) {
      throw ArgumentError('envelope must not be empty');
    }
    final arena = pkg_ffi.Arena();
    try {
      final reservationPtr = _bytesToNative(reservationId, arena);
      final envelopePtr = _bytesToNative(envelope, arena);
      _check(op(reservationPtr, envelopePtr, envelope.length), context);
    } finally {
      arena.releaseAll();
    }
  }

  List<Uint8List> _decodeMailboxPayload(Uint8List encoded) {
    if (encoded.length < 4) {
      throw const FormatException('mailbox payload truncated: missing count');
    }
    final data = ByteData.sublistView(encoded);
    var offset = 0;
    final count = data.getUint32(offset, Endian.little);
    offset += 4;
    final messages = <Uint8List>[];
    for (var i = 0; i < count; i++) {
      if (offset + 4 > encoded.length) {
        throw FormatException('mailbox payload truncated at message length $i');
      }
      final messageLen = data.getUint32(offset, Endian.little);
      offset += 4;
      if (offset + messageLen > encoded.length) {
        throw FormatException('mailbox payload truncated at message body $i');
      }
      messages.add(
          Uint8List.fromList(encoded.sublist(offset, offset + messageLen)));
      offset += messageLen;
    }
    if (offset != encoded.length) {
      throw const FormatException('mailbox payload has trailing bytes');
    }
    return messages;
  }

  Uint8List _consumeOwnedBuffer(ffi.Pointer<ffi.Uint8> ptr, int len) {
    if (ptr == ffi.nullptr || len == 0) {
      return Uint8List(0);
    }
    try {
      return Uint8List.fromList(ptr.asTypedList(len));
    } finally {
      bindings.freeBuffer(ptr, len);
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
      final message = _lookupErrorMessage(rc);
      throw EqualXException(rc, '$context: $message');
    }
  }

  String _lookupErrorMessage(int rc) {
    final arena = pkg_ffi.Arena();
    try {
      final out = arena.allocate<ffi.Pointer<ffi.Char>>(1);
      final lookupRc = bindings.errorMessage(rc, out);
      if (lookupRc != 0 || out.value == ffi.nullptr) {
        return 'native error code $rc';
      }
      final message = out.value.cast<pkg_ffi.Utf8>().toDartString();
      bindings.freeString(out.value);
      return message;
    } catch (_) {
      return 'native error code $rc';
    } finally {
      arena.releaseAll();
    }
  }

  void _validateStepPayload(int commandId, Uint8List payload) {
    if (commandId == eswpCmdMakerCreateReservation) {
      if (payload.isNotEmpty && payload.length != 8) {
        throw ArgumentError.value(
          payload.length,
          'payload.length',
          'must be 0 or 8 for maker_create_reservation',
        );
      }
      return;
    }
    if (commandId == eswpCmdTakerPublishContext) {
      if (payload.length < 34) {
        throw ArgumentError.value(
          payload.length,
          'payload.length',
          'must be >= 34 for taker_publish_context',
        );
      }
      return;
    }
    if (commandId == eswpCmdTakerPublishFinalSig) {
      if (payload.length != 32) {
        throw ArgumentError.value(
          payload.length,
          'payload.length',
          'must be 32 for taker_publish_final_sig',
        );
      }
      return;
    }
    if (payload.isNotEmpty) {
      throw ArgumentError.value(
        payload.length,
        'payload.length',
        'must be empty for command $commandId',
      );
    }
  }

  void _requirePointer(ffi.Pointer ptr, String name) {
    if (ptr == ffi.nullptr || ptr.address == 0) {
      throw ArgumentError.value(ptr.address, name, 'must not be null');
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
