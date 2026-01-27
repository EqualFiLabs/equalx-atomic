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

typedef _WireVersionNative = ffi.Uint32 Function();
typedef _WireVersionDart = int Function();

typedef _BackendClsagNative = ffi.Uint8 Function();
typedef _BackendClsagDart = int Function();

typedef _GenerateMoneroKeypairNative = ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _GenerateMoneroKeypairDart = int Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);

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
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _GenerateEvmKeypairDart = int Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);

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
}
