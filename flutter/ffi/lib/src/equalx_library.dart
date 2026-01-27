import 'dart:ffi' as ffi;
import 'dart:io';

/// Loads the EqualX native library used by the Dart/Flutter bindings.
class EqualXLibrary {
  EqualXLibrary._(this._lib);

  final ffi.DynamicLibrary _lib;

  static const _envVar = 'EQUALX_FFI_LIB';
  static ffi.DynamicLibrary? _cached;

  /// Returns the cached dynamic library handle, defaulting to [load] if needed.
  static ffi.DynamicLibrary instance() {
    return _cached ??= load();
  }

  /// Loads the native library with optional overrides.
  ///
  /// When [path] is null the loader inspects the [Platform.environment],
  /// falling back to the default library name for the host OS and common
  /// build output directories (e.g. `target/debug`).
  ///
  /// Set [useProcess] to `true` when the bindings are statically linked into
  /// the running process (e.g. in unit tests).
  static ffi.DynamicLibrary load({String? path, bool useProcess = false}) {
    if (useProcess) {
      return _cached ??= ffi.DynamicLibrary.process();
    }
    final candidate = path ?? _resolveCandidatePath();
    return _cached ??= ffi.DynamicLibrary.open(candidate);
  }

  /// Clears the cached handle to allow reloading a different library path.
  static void reset() {
    _cached = null;
  }

  static String _resolveCandidatePath() {
    final envPath = Platform.environment[_envVar];
    if (envPath != null && envPath.isNotEmpty) {
      return envPath;
    }
    final os = Platform.operatingSystem;
    final defaultName = switch (os) {
      'linux' => 'libffi_c.so',
      'macos' => 'libffi_c.dylib',
      'windows' => 'ffi_c.dll',
      _ => (throw StateError('Unsupported platform: $os')),
    };

    final buildDirs = <String>[
      defaultName,
      'target/debug/$defaultName',
      'target/release/$defaultName',
      '../target/debug/$defaultName',
      '../target/release/$defaultName',
      '../../target/debug/$defaultName',
      '../../target/release/$defaultName',
    ];

    for (final candidate in buildDirs) {
      final file = File(candidate);
      if (file.existsSync()) {
        return file.path;
      }
    }

    throw StateError(
      'Unable to locate the EqualX FFI library. '
      'Set $_envVar to the compiled cdylib path (e.g. target/debug/$defaultName).',
    );
  }
}
