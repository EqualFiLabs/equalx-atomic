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

class CapabilityDescriptor {
  const CapabilityDescriptor({
    required this.versionMajor,
    required this.versionMinor,
    required this.versionPatch,
    required this.backends,
    required this.apiGroups,
    required this.wireVersion,
  });

  final int versionMajor;
  final int versionMinor;
  final int versionPatch;
  final int backends;
  final int apiGroups;
  final int wireVersion;

  bool supportsBackend(int mask) => (backends & mask) == mask;
  bool supportsApiGroup(int mask) => (apiGroups & mask) == mask;
}

enum SwapRole { maker, taker, unknown }

class SwapState {
  const SwapState({
    required this.raw,
    required this.role,
    required this.stage,
  });

  final String raw;
  final SwapRole role;
  final String stage;

  factory SwapState.fromDebugString(String debugString) {
    final trimmed = debugString.trim();
    final role = trimmed.startsWith('Maker(')
        ? SwapRole.maker
        : trimmed.startsWith('Taker(')
            ? SwapRole.taker
            : SwapRole.unknown;
    final stageMatch = RegExp(r'^(?:Maker|Taker)\(([^({]+)')
        .firstMatch(trimmed)
        ?.group(1)
        ?.trim();
    return SwapState(
      raw: debugString,
      role: role,
      stage: stageMatch ?? trimmed,
    );
  }
}

enum SwapLifecycleEventKind {
  deadlineExceeded,
  stateTransition,
  deadlineWarning,
  errorOccurred,
  userActionRequired,
  txSubmitted,
  txConfirmed,
  swapCompleted,
  unknown,
}

class SwapLifecycleEvent {
  const SwapLifecycleEvent({
    required this.kind,
    required this.reservationId,
    this.deadline,
    this.message,
    this.raw,
  });

  final SwapLifecycleEventKind kind;
  final Uint8List reservationId;
  final int? deadline;
  final String? message;
  final String? raw;

  factory SwapLifecycleEvent.deadlineExceeded({
    required Uint8List reservationId,
    required int deadline,
  }) {
    return SwapLifecycleEvent(
      kind: SwapLifecycleEventKind.deadlineExceeded,
      reservationId: reservationId,
      deadline: deadline,
    );
  }
}

class OrchestratorConfig {
  const OrchestratorConfig({
    this.checkpointVersion = 1,
    this.makerTimeoutSecs = 3600,
    this.takerTimeoutSecs = 3600,
  });

  final int checkpointVersion;
  final int makerTimeoutSecs;
  final int takerTimeoutSecs;
}

const int swapIdLength = 32;
const int addressLength = 20;
const int scalarLength = 32;
const int u256Length = 32;

const int backendMaskClsag = 1 << 0;

const int apiGroupKeyRegistry = 1 << 0;
const int apiGroupMailbox = 1 << 1;
const int apiGroupAtomicDesk = 1 << 2;
const int apiGroupEscrow = 1 << 3;
const int apiGroupEventDecode = 1 << 4;
const int apiGroupOrchestrator = 1 << 5;

const int eswpCmdMakerCreateReservation = 1;
const int eswpCmdMakerSetHashlock = 2;
const int eswpCmdMakerHandleContext = 3;
const int eswpCmdMakerPublishPresig = 4;
const int eswpCmdMakerHandleFinalSig = 5;
const int eswpCmdMakerSettle = 6;
const int eswpCmdTakerAcceptReservation = 11;
const int eswpCmdTakerPublishContext = 12;
const int eswpCmdTakerHandlePresig = 13;
const int eswpCmdTakerCompleteAndBroadcast = 14;
const int eswpCmdTakerPublishFinalSig = 15;
