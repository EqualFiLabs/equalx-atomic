import 'dart:ffi' as ffi;
import 'dart:math';
import 'dart:typed_data';

import 'package:equalx_ffi/equalx_ffi.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:glados/glados.dart' as glados;

Uint8List _randomBytes(Random random, int len) {
  return Uint8List.fromList(
      List<int>.generate(len, (_) => random.nextInt(256)));
}

void main() {
  group('EqualXLibrary', () {
    test('load failure is descriptive', () {
      EqualXLibrary.reset();
      const missing = '/tmp/equalx_missing_library.so';
      expect(
        () => EqualXLibrary.load(path: missing),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            allOf(contains('Unable to load EqualX FFI library'),
                contains(missing)),
          ),
        ),
      );
    });
  });

  group('EqualXApi', () {
    late EqualXApi api;

    setUp(() {
      EqualXLibrary.reset();
      api = EqualXApi.fromDefaultLibrary();
    });

    test('wire version is non-zero', () {
      expect(api.wireVersion(), greaterThan(0));
    });

    test('key generation yields expected lengths', () {
      final monero = api.generateMoneroKeypair();
      expect(monero.spendKey, hasLength(32));
      expect(monero.viewKey, hasLength(32));

      final evm = api.generateEvmKeypair();
      expect(evm.privateKey, hasLength(32));
      expect(evm.address, hasLength(20));
    });

    test('capability query is consistent with wire version', () {
      final cap = api.capabilityQuery();
      expect(cap.wireVersion, equals(api.wireVersion()));
      expect(cap.supportsBackend(backendMaskClsag), isTrue);
      expect(cap.supportsApiGroup(apiGroupOrchestrator), isTrue);
      expect(cap.supportsApiGroup(apiGroupMailbox), isTrue);
    });

    test('native errors include translated message', () {
      final owner = Uint8List.fromList(List<int>.filled(20, 0x7B));
      expect(
        () => api.getEncPub(ownerAddress: owner),
        throwsA(
          isA<EqualXException>().having(
            (e) => e.context,
            'context',
            contains('equalx ffi error'),
          ),
        ),
      );
    });

    test('orchestrator step payload validation runs before native call', () {
      final fakeHandle = ffi.Pointer<ffi.Void>.fromAddress(1);
      final reservation = Uint8List(32);
      expect(
        () => api.orchestratorStep(
          handle: fakeHandle,
          reservationId: reservation,
          commandId: eswpCmdMakerSetHashlock,
          payload: Uint8List.fromList([1]),
        ),
        throwsArgumentError,
      );
    });

    glados.Glados(glados.any.intInRange(0, 64)).test(
      'registerEncPub validates owner length',
      (ownerLen) {
        if (ownerLen == 20) {
          return;
        }
        final owner = Uint8List(ownerLen);
        final key = Uint8List(33);
        expect(
          () => api.registerEncPub(ownerAddress: owner, compressedPubkey: key),
          throwsArgumentError,
        );
      },
    );

    glados.Glados(glados.any.nonEmptyList(glados.any.uint8)).testWithRandom(
      'mailbox publish/fetch round-trip',
      (rawEnvelope, random) {
        final reservationId = _randomBytes(random, 32);
        final envelope = Uint8List.fromList(
          rawEnvelope.map((b) => b & 0xFF).toList(growable: false),
        );

        api.publishContext(reservationId: reservationId, envelope: envelope);
        final messages = api.fetchMessages(reservationId: reservationId);

        expect(messages, isNotEmpty);
        expect(messages.last, equals(envelope));
      },
    );
  });
}
