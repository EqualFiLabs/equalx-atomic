import 'package:equalx_ffi/equalx_ffi.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
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
  });
}
