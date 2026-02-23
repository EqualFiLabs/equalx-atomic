import 'dart:ffi' as ffi;
import 'dart:io';

/// Loads the EqualX native library used by the Dart/Flutter bindings.
class EqualXLibrary {
  static const _envVar = 'EQUALX_FFI_LIB';
  static const _processSentinel = '__equalx_process__';
  static ffi.DynamicLibrary? _cached;

  /// Returns the cached dynamic library handle, defaulting to [load] if needed.
  static ffi.DynamicLibrary instance() {
    return _cached ??= load();
  }

  /// Loads the native library with optional overrides.
  ///
  /// When [path] is null the loader inspects [Platform.environment], then
  /// searches common host-specific output locations.
  static ffi.DynamicLibrary load({String? path, bool useProcess = false}) {
    if (useProcess) {
      return _cached ??= ffi.DynamicLibrary.process();
    }

    final os = Platform.operatingSystem;
    final searched = <String>[];
    final candidate = path ?? _resolveCandidatePath(os, searched);

    if (candidate == _processSentinel) {
      try {
        return _cached ??= ffi.DynamicLibrary.process();
      } catch (e) {
        throw StateError(
          'Unable to load EqualX FFI library for platform "$os". '
          'Tried DynamicLibrary.process() after searching: ${searched.join(', ')}. '
          'Set $_envVar to a framework/binary path. Native error: $e',
        );
      }
    }

    try {
      return _cached ??= ffi.DynamicLibrary.open(candidate);
    } catch (e) {
      throw StateError(
        'Unable to load EqualX FFI library for platform "$os" at "$candidate". '
        'Searched: ${searched.join(', ')}. Set $_envVar to the compiled library path. '
        'Native error: $e',
      );
    }
  }

  /// Clears the cached handle to allow reloading a different library path.
  static void reset() {
    _cached = null;
  }

  static String _resolveCandidatePath(String os, List<String> searched) {
    final envPath = Platform.environment[_envVar];
    if (envPath != null && envPath.isNotEmpty) {
      searched.add(envPath);
      return envPath;
    }

    final defaultName = switch (os) {
      'linux' => 'libffi_c.so',
      'android' => 'libffi_c.so',
      'macos' => 'libffi_c.dylib',
      'windows' => 'ffi_c.dll',
      'ios' => 'EqualXFFI.framework/EqualXFFI',
      _ => (throw StateError('Unsupported platform: $os')),
    };

    final candidates = switch (os) {
      'ios' => <String>[
          defaultName,
          'Frameworks/EqualXFFI.framework/EqualXFFI',
          'App.framework/EqualXFFI',
          'EqualXFFI.xcframework/ios-arm64/EqualXFFI.framework/EqualXFFI',
          'EqualXFFI.xcframework/ios-arm64_x86_64-simulator/EqualXFFI.framework/EqualXFFI',
        ],
      'android' => <String>[
          defaultName,
          'android/src/main/jniLibs/arm64-v8a/$defaultName',
          'android/src/main/jniLibs/armeabi-v7a/$defaultName',
          'android/src/main/jniLibs/x86_64/$defaultName',
          'native/android/jniLibs/arm64-v8a/$defaultName',
          'native/android/jniLibs/armeabi-v7a/$defaultName',
          'native/android/jniLibs/x86_64/$defaultName',
        ],
      _ => <String>[
          defaultName,
          'target/debug/$defaultName',
          'target/release/$defaultName',
          '../target/debug/$defaultName',
          '../target/release/$defaultName',
          '../../target/debug/$defaultName',
          '../../target/release/$defaultName',
        ],
    };

    searched.addAll(candidates);

    for (final candidate in candidates) {
      final file = File(candidate);
      if (file.existsSync()) {
        return file.path;
      }
    }

    if (os == 'android') {
      return defaultName;
    }

    if (os == 'ios') {
      searched.add('DynamicLibrary.process()');
      return _processSentinel;
    }

    throw StateError(
      'Unable to locate the EqualX FFI library for platform "$os". '
      'Searched: ${searched.join(', ')}. Set $_envVar to the compiled library path.',
    );
  }
}
