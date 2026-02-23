// ignore_for_file: library_private_types_in_public_api

import 'dart:ffi' as ffi;

import 'equalx_library.dart';

final class NativeEscrowLog extends ffi.Struct {
  @ffi.Uint8()
  external int kind;

  @ffi.Uint8()
  external int backend;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> swapId;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> amountBe;
}

final class NativeEscrowEvent extends ffi.Struct {
  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> digest;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> swapId;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> amountBe;

  @ffi.Uint8()
  external int backend;

  @ffi.Uint8()
  external int kind;
}

final class NativeCapabilityDescriptor extends ffi.Struct {
  @ffi.Uint16()
  external int versionMajor;

  @ffi.Uint16()
  external int versionMinor;

  @ffi.Uint16()
  external int versionPatch;

  @ffi.Uint32()
  external int backends;

  @ffi.Uint32()
  external int apiGroups;

  @ffi.Uint32()
  external int wireVersion;
}

final class NativeAtomicReservationCreatedEvent extends ffi.Struct {
  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> reservationId;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> deskId;

  @ffi.Array<ffi.Uint8>(20)
  external ffi.Array<ffi.Uint8> taker;

  @ffi.Array<ffi.Uint8>(20)
  external ffi.Array<ffi.Uint8> asset;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> amountBe;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> settlementDigest;

  @ffi.Uint64()
  external int expiry;

  @ffi.Uint64()
  external int createdAt;
}

final class NativeReservationCreatedEvent extends ffi.Struct {
  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> reservationId;

  @ffi.Array<ffi.Uint8>(20)
  external ffi.Array<ffi.Uint8> taker;

  @ffi.Array<ffi.Uint8>(20)
  external ffi.Array<ffi.Uint8> desk;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> amountBe;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> counterBe;
}

final class NativeHashlockSetEvent extends ffi.Struct {
  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> reservationId;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> hashlock;
}

final class NativeTrancheOpenedEvent extends ffi.Struct {
  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> trancheId;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> deskId;

  @ffi.Array<ffi.Uint8>(20)
  external ffi.Array<ffi.Uint8> maker;

  @ffi.Array<ffi.Uint8>(20)
  external ffi.Array<ffi.Uint8> asset;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> priceNumeratorBe;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> priceDenominatorBe;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> totalLiquidityBe;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> minFillBe;

  @ffi.Uint16()
  external int feeBps;

  @ffi.Uint8()
  external int feePayer;

  @ffi.Uint64()
  external int expiry;
}

final class NativeTakerTrancheOpenedEvent extends ffi.Struct {
  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> trancheId;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> deskId;

  @ffi.Array<ffi.Uint8>(20)
  external ffi.Array<ffi.Uint8> taker;

  @ffi.Array<ffi.Uint8>(20)
  external ffi.Array<ffi.Uint8> asset;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> priceNumeratorBe;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> priceDenominatorBe;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> totalLiquidityBe;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> minFillBe;

  @ffi.Uint16()
  external int feeBps;

  @ffi.Uint8()
  external int feePayer;

  @ffi.Uint64()
  external int expiry;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> postingFeeBe;
}

final class NativeTrancheReservedEvent extends ffi.Struct {
  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> trancheId;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> reservationId;

  @ffi.Array<ffi.Uint8>(20)
  external ffi.Array<ffi.Uint8> actor;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> amountBe;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> remainingLiquidityBe;
}

final class NativeSettleEvent extends ffi.Struct {
  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> reservationId;

  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> value;
}

final class NativeOrchestratorConfig extends ffi.Struct {
  @ffi.Uint8()
  external int checkpointVersion;

  @ffi.Uint64()
  external int makerTimeoutSecs;

  @ffi.Uint64()
  external int takerTimeoutSecs;
}

final class NativeDeadlineEvent extends ffi.Struct {
  @ffi.Array<ffi.Uint8>(32)
  external ffi.Array<ffi.Uint8> reservationId;

  @ffi.Uint64()
  external int deadline;
}

final class NativeFfiOrchestratorHandle extends ffi.Opaque {}

typedef _WireVersionNative = ffi.Uint32 Function();
typedef _WireVersionDart = int Function();

typedef _BackendClsagNative = ffi.Uint8 Function();
typedef _BackendClsagDart = int Function();

typedef _GenerateMoneroKeypairNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
);
typedef _GenerateMoneroKeypairDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
);

typedef _MoneroDeriveSubaddressNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint32>,
  ffi.Pointer<ffi.Uint8>,
);
typedef _MoneroDeriveSubaddressDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint32>,
  ffi.Pointer<ffi.Uint8>,
);

typedef _MoneroComputeKeyImageNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
);
typedef _MoneroComputeKeyImageDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
);

typedef _GenerateEvmKeypairNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
);
typedef _GenerateEvmKeypairDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
);

typedef _SignEvmMessageNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
);
typedef _SignEvmMessageDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
);

typedef _ClsagMakePreSigNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint32>,
);
typedef _ClsagMakePreSigDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  int,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint32>,
);

typedef _ClsagCompleteNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint32>,
);
typedef _ClsagCompleteDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint32>,
);

typedef _ClsagVerifyNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
);
typedef _ClsagVerifyDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
);

typedef _ClsagExtractNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
);
typedef _ClsagExtractDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
);

typedef _PrepareRefundNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint64,
  ffi.Uint64,
  ffi.Uint64,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint32>,
  ffi.Pointer<ffi.Uint64>,
);
typedef _PrepareRefundDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  int,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint32>,
  ffi.Pointer<ffi.Uint64>,
);

typedef _LockEthNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint64,
  ffi.Uint8,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint64,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint32>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint64>,
);
typedef _LockEthDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  int,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint32>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint64>,
);

typedef _RefundCallNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint64,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint32>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint64>,
);
typedef _RefundCallDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint32>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint64>,
);

typedef _DecodeEventsNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<NativeEscrowLog>,
  ffi.Uint32,
  ffi.Pointer<NativeEscrowEvent>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint32>,
);
typedef _DecodeEventsDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<NativeEscrowLog>,
  int,
  ffi.Pointer<NativeEscrowEvent>,
  int,
  ffi.Pointer<ffi.Uint32>,
);

typedef _PostTxHashNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint64,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint32>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint64>,
);
typedef _PostTxHashDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint32>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint64>,
);

typedef _SettleCallNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint64,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint32>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint64>,
);
typedef _SettleCallDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint32>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint64>,
);

typedef _LockErc20Native = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint64,
  ffi.Uint8,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Uint64,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint32>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint64>,
);
typedef _LockErc20Dart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  int,
  int,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  int,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint32>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint64>,
);

typedef _CapabilityQueryNative = ffi.Int32 Function(
  ffi.Pointer<NativeCapabilityDescriptor>,
);
typedef _CapabilityQueryDart = int Function(
  ffi.Pointer<NativeCapabilityDescriptor>,
);

typedef _RegisterEncPubNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
);
typedef _RegisterEncPubDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  int,
);

typedef _GetEncPubNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Uint32>,
);
typedef _GetEncPubDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Uint32>,
);

typedef _IsRegisteredNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
);
typedef _IsRegisteredDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
);

typedef _MailboxPublishNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
);
typedef _MailboxPublishDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  int,
);

typedef _FetchMessagesNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Uint32>,
);
typedef _FetchMessagesDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Uint32>,
);

typedef _RegisterDeskNative = ffi.Int32 Function(ffi.Pointer<ffi.Uint8>);
typedef _RegisterDeskDart = int Function(ffi.Pointer<ffi.Uint8>);

typedef _ReserveAtomicSwapNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint64,
  ffi.Uint64,
);
typedef _ReserveAtomicSwapDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  int,
  int,
);

typedef _GetReservationNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<NativeAtomicReservationCreatedEvent>,
);
typedef _GetReservationDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<NativeAtomicReservationCreatedEvent>,
);

typedef _DecodeReservationCreatedNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<NativeReservationCreatedEvent>,
);
typedef _DecodeReservationCreatedDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<NativeReservationCreatedEvent>,
);

typedef _DecodeHashlockSetNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<NativeHashlockSetEvent>,
);
typedef _DecodeHashlockSetDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<NativeHashlockSetEvent>,
);

typedef _DecodeAtomicReservationCreatedNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<NativeAtomicReservationCreatedEvent>,
);
typedef _DecodeAtomicReservationCreatedDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<NativeAtomicReservationCreatedEvent>,
);

typedef _DecodeTrancheOpenedNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<NativeTrancheOpenedEvent>,
);
typedef _DecodeTrancheOpenedDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<NativeTrancheOpenedEvent>,
);

typedef _DecodeTakerTrancheOpenedNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<NativeTakerTrancheOpenedEvent>,
);
typedef _DecodeTakerTrancheOpenedDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<NativeTakerTrancheOpenedEvent>,
);

typedef _DecodeTrancheReservedNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<NativeTrancheReservedEvent>,
);
typedef _DecodeTrancheReservedDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<NativeTrancheReservedEvent>,
);

typedef _DecodeTakerTrancheReservedNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<NativeTrancheReservedEvent>,
);
typedef _DecodeTakerTrancheReservedDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<NativeTrancheReservedEvent>,
);

typedef _DecodeSettleNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<NativeSettleEvent>,
);
typedef _DecodeSettleDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<NativeSettleEvent>,
);

typedef _OrchestratorNewNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<NativeOrchestratorConfig>,
  ffi.Pointer<ffi.Pointer<NativeFfiOrchestratorHandle>>,
);
typedef _OrchestratorNewDart = int Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<NativeOrchestratorConfig>,
  ffi.Pointer<ffi.Pointer<NativeFfiOrchestratorHandle>>,
);

typedef _OrchestratorFreeNative = ffi.Void Function(
  ffi.Pointer<NativeFfiOrchestratorHandle>,
);
typedef _OrchestratorFreeDart = void Function(
  ffi.Pointer<NativeFfiOrchestratorHandle>,
);

typedef _OrchestratorResumeNative = ffi.Int32 Function(
  ffi.Pointer<NativeFfiOrchestratorHandle>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Uint32>,
);
typedef _OrchestratorResumeDart = int Function(
  ffi.Pointer<NativeFfiOrchestratorHandle>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Uint32>,
);

typedef _OrchestratorStepNative = ffi.Int32 Function(
  ffi.Pointer<NativeFfiOrchestratorHandle>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint8>,
);
typedef _OrchestratorStepDart = int Function(
  ffi.Pointer<NativeFfiOrchestratorHandle>,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
);

typedef _OrchestratorCheckDeadlinesNative = ffi.Int32 Function(
  ffi.Pointer<NativeFfiOrchestratorHandle>,
  ffi.Pointer<NativeDeadlineEvent>,
  ffi.Uint32,
  ffi.Pointer<ffi.Uint32>,
);
typedef _OrchestratorCheckDeadlinesDart = int Function(
  ffi.Pointer<NativeFfiOrchestratorHandle>,
  ffi.Pointer<NativeDeadlineEvent>,
  int,
  ffi.Pointer<ffi.Uint32>,
);

typedef _FreeBufferNative = ffi.Void Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
);
typedef _FreeBufferDart = void Function(
  ffi.Pointer<ffi.Uint8>,
  int,
);

typedef _FreeStringNative = ffi.Void Function(ffi.Pointer<ffi.Char>);
typedef _FreeStringDart = void Function(ffi.Pointer<ffi.Char>);

typedef _ErrorMessageNative = ffi.Int32 Function(
  ffi.Int32,
  ffi.Pointer<ffi.Pointer<ffi.Char>>,
);
typedef _ErrorMessageDart = int Function(
  int,
  ffi.Pointer<ffi.Pointer<ffi.Char>>,
);

class EqualXBindings {
  EqualXBindings([ffi.DynamicLibrary? dynamicLibrary])
      : _lib = dynamicLibrary ?? EqualXLibrary.instance() {
    wireVersion = _lib.lookupFunction<_WireVersionNative, _WireVersionDart>(
      'eswp_wire_version',
    );
    backendClsagId =
        _lib.lookupFunction<_BackendClsagNative, _BackendClsagDart>(
      'eswp_backend_clsag_id',
    );
    generateMoneroKeypair = _lib.lookupFunction<_GenerateMoneroKeypairNative,
        _GenerateMoneroKeypairDart>('eswp_generate_monero_keypair');
    moneroDeriveSubaddress = _lib.lookupFunction<_MoneroDeriveSubaddressNative,
        _MoneroDeriveSubaddressDart>('eswp_monero_derive_subaddress');
    moneroComputeKeyImage = _lib.lookupFunction<_MoneroComputeKeyImageNative,
        _MoneroComputeKeyImageDart>('eswp_monero_compute_key_image');
    generateEvmKeypair =
        _lib.lookupFunction<_GenerateEvmKeypairNative, _GenerateEvmKeypairDart>(
      'eswp_generate_evm_keypair',
    );
    signEvmMessage =
        _lib.lookupFunction<_SignEvmMessageNative, _SignEvmMessageDart>(
      'eswp_sign_evm_message',
    );
    clsagMakePreSig =
        _lib.lookupFunction<_ClsagMakePreSigNative, _ClsagMakePreSigDart>(
      'eswp_clsag_make_pre_sig',
    );
    clsagComplete =
        _lib.lookupFunction<_ClsagCompleteNative, _ClsagCompleteDart>(
      'eswp_clsag_complete',
    );
    clsagVerify = _lib.lookupFunction<_ClsagVerifyNative, _ClsagVerifyDart>(
      'eswp_clsag_verify',
    );
    clsagExtract = _lib.lookupFunction<_ClsagExtractNative, _ClsagExtractDart>(
      'eswp_clsag_extract_t',
    );
    prepareRefund =
        _lib.lookupFunction<_PrepareRefundNative, _PrepareRefundDart>(
      'eswp_prepare_refund',
    );
    lockEth = _lib.lookupFunction<_LockEthNative, _LockEthDart>(
      'eswp_escrow_lock_eth_call',
    );
    escrowRefund = _lib.lookupFunction<_RefundCallNative, _RefundCallDart>(
      'eswp_escrow_refund_call',
    );
    decodeEvents = _lib.lookupFunction<_DecodeEventsNative, _DecodeEventsDart>(
      'eswp_decode_escrow_events',
    );
    postTxHash = _lib.lookupFunction<_PostTxHashNative, _PostTxHashDart>(
      'eswp_post_tx_hash_call',
    );
    escrowSettle = _lib.lookupFunction<_SettleCallNative, _SettleCallDart>(
      'eswp_escrow_settle_call',
    );
    lockErc20 = _lib.lookupFunction<_LockErc20Native, _LockErc20Dart>(
      'eswp_escrow_lock_erc20_call',
    );

    capabilityQuery =
        _lib.lookupFunction<_CapabilityQueryNative, _CapabilityQueryDart>(
            'eswp_capability_query');
    registerEncPub =
        _lib.lookupFunction<_RegisterEncPubNative, _RegisterEncPubDart>(
            'eswp_register_enc_pub');
    getEncPub = _lib.lookupFunction<_GetEncPubNative, _GetEncPubDart>(
      'eswp_get_enc_pub',
    );
    isRegistered = _lib.lookupFunction<_IsRegisteredNative, _IsRegisteredDart>(
      'eswp_is_registered',
    );
    publishContext =
        _lib.lookupFunction<_MailboxPublishNative, _MailboxPublishDart>(
            'eswp_publish_context');
    publishPresig =
        _lib.lookupFunction<_MailboxPublishNative, _MailboxPublishDart>(
            'eswp_publish_presig');
    publishFinalSig =
        _lib.lookupFunction<_MailboxPublishNative, _MailboxPublishDart>(
            'eswp_publish_final_sig');
    fetchMessages =
        _lib.lookupFunction<_FetchMessagesNative, _FetchMessagesDart>(
            'eswp_fetch_messages');
    registerDesk = _lib.lookupFunction<_RegisterDeskNative, _RegisterDeskDart>(
      'eswp_register_desk',
    );
    reserveAtomicSwap =
        _lib.lookupFunction<_ReserveAtomicSwapNative, _ReserveAtomicSwapDart>(
            'eswp_reserve_atomic_swap');
    getReservation =
        _lib.lookupFunction<_GetReservationNative, _GetReservationDart>(
            'eswp_get_reservation');

    decodeReservationCreated = _lib.lookupFunction<
        _DecodeReservationCreatedNative,
        _DecodeReservationCreatedDart>('eswp_decode_reservation_created');
    decodeHashlockSet =
        _lib.lookupFunction<_DecodeHashlockSetNative, _DecodeHashlockSetDart>(
            'eswp_decode_hashlock_set');
    decodeAtomicReservationCreated = _lib.lookupFunction<
            _DecodeAtomicReservationCreatedNative,
            _DecodeAtomicReservationCreatedDart>(
        'eswp_decode_atomic_reservation_created');
    decodeTrancheOpened = _lib
        .lookupFunction<_DecodeTrancheOpenedNative, _DecodeTrancheOpenedDart>(
      'eswp_decode_tranche_opened',
    );
    decodeTakerTrancheOpened = _lib.lookupFunction<
        _DecodeTakerTrancheOpenedNative,
        _DecodeTakerTrancheOpenedDart>('eswp_decode_taker_tranche_opened');
    decodeTrancheReserved = _lib.lookupFunction<_DecodeTrancheReservedNative,
        _DecodeTrancheReservedDart>('eswp_decode_tranche_reserved');
    decodeTakerTrancheReserved = _lib.lookupFunction<
        _DecodeTakerTrancheReservedNative,
        _DecodeTakerTrancheReservedDart>('eswp_decode_taker_tranche_reserved');
    decodeSettled = _lib.lookupFunction<_DecodeSettleNative, _DecodeSettleDart>(
      'eswp_decode_settled',
    );
    decodeRefunded =
        _lib.lookupFunction<_DecodeSettleNative, _DecodeSettleDart>(
      'eswp_decode_refunded',
    );

    orchestratorNew =
        _lib.lookupFunction<_OrchestratorNewNative, _OrchestratorNewDart>(
            'eswp_orchestrator_new');
    orchestratorFree =
        _lib.lookupFunction<_OrchestratorFreeNative, _OrchestratorFreeDart>(
            'eswp_orchestrator_free');
    orchestratorResume =
        _lib.lookupFunction<_OrchestratorResumeNative, _OrchestratorResumeDart>(
            'eswp_orchestrator_resume');
    orchestratorStep =
        _lib.lookupFunction<_OrchestratorStepNative, _OrchestratorStepDart>(
            'eswp_orchestrator_step');
    orchestratorCheckDeadlines = _lib.lookupFunction<
        _OrchestratorCheckDeadlinesNative,
        _OrchestratorCheckDeadlinesDart>('eswp_orchestrator_check_deadlines');

    freeBuffer = _lib.lookupFunction<_FreeBufferNative, _FreeBufferDart>(
      'eswp_free_buffer',
    );
    freeString = _lib.lookupFunction<_FreeStringNative, _FreeStringDart>(
      'eswp_free_string',
    );
    errorMessage = _lib.lookupFunction<_ErrorMessageNative, _ErrorMessageDart>(
      'eswp_error_message',
    );
  }

  final ffi.DynamicLibrary _lib;

  late final _WireVersionDart wireVersion;
  late final _BackendClsagDart backendClsagId;
  late final _GenerateMoneroKeypairDart generateMoneroKeypair;
  late final _MoneroDeriveSubaddressDart moneroDeriveSubaddress;
  late final _MoneroComputeKeyImageDart moneroComputeKeyImage;
  late final _GenerateEvmKeypairDart generateEvmKeypair;
  late final _SignEvmMessageDart signEvmMessage;
  late final _ClsagMakePreSigDart clsagMakePreSig;
  late final _ClsagCompleteDart clsagComplete;
  late final _ClsagVerifyDart clsagVerify;
  late final _ClsagExtractDart clsagExtract;
  late final _PrepareRefundDart prepareRefund;
  late final _LockEthDart lockEth;
  late final _RefundCallDart escrowRefund;
  late final _DecodeEventsDart decodeEvents;
  late final _PostTxHashDart postTxHash;
  late final _SettleCallDart escrowSettle;
  late final _LockErc20Dart lockErc20;

  late final _CapabilityQueryDart capabilityQuery;
  late final _RegisterEncPubDart registerEncPub;
  late final _GetEncPubDart getEncPub;
  late final _IsRegisteredDart isRegistered;
  late final _MailboxPublishDart publishContext;
  late final _MailboxPublishDart publishPresig;
  late final _MailboxPublishDart publishFinalSig;
  late final _FetchMessagesDart fetchMessages;
  late final _RegisterDeskDart registerDesk;
  late final _ReserveAtomicSwapDart reserveAtomicSwap;
  late final _GetReservationDart getReservation;

  late final _DecodeReservationCreatedDart decodeReservationCreated;
  late final _DecodeHashlockSetDart decodeHashlockSet;
  late final _DecodeAtomicReservationCreatedDart decodeAtomicReservationCreated;
  late final _DecodeTrancheOpenedDart decodeTrancheOpened;
  late final _DecodeTakerTrancheOpenedDart decodeTakerTrancheOpened;
  late final _DecodeTrancheReservedDart decodeTrancheReserved;
  late final _DecodeTakerTrancheReservedDart decodeTakerTrancheReserved;
  late final _DecodeSettleDart decodeSettled;
  late final _DecodeSettleDart decodeRefunded;

  late final _OrchestratorNewDart orchestratorNew;
  late final _OrchestratorFreeDart orchestratorFree;
  late final _OrchestratorResumeDart orchestratorResume;
  late final _OrchestratorStepDart orchestratorStep;
  late final _OrchestratorCheckDeadlinesDart orchestratorCheckDeadlines;

  late final _FreeBufferDart freeBuffer;
  late final _FreeStringDart freeString;
  late final _ErrorMessageDart errorMessage;
}
