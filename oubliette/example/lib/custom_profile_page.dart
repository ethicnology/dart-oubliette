import 'dart:io';

import 'package:flutter/material.dart';
import 'package:oubliette/oubliette.dart';

import 'storage_test_page.dart';

class CustomProfilePage extends StatefulWidget {
  const CustomProfilePage({super.key});

  @override
  State<CustomProfilePage> createState() => _CustomProfilePageState();
}

class _CustomProfilePageState extends State<CustomProfilePage> {
  final _prefixController = TextEditingController(text: 'custom_');

  final _keyAliasController = TextEditingController(text: 'default_key');
  bool _strongBox = false;
  bool _unlockedDeviceRequired = true;
  bool _invalidatedByBiometricEnrollment = false;
  final _promptTitleController = TextEditingController();
  final _promptSubtitleController = TextEditingController();

  final _serviceController = TextEditingController();
  KeychainAccessibility _accessibility =
      KeychainAccessibility.whenUnlockedThisDeviceOnly;
  bool _useDataProtection = false;
  bool _authenticationRequired = false;
  bool _biometryCurrentSetOnly = false;
  bool _secureEnclave = false;
  final _authenticationPromptController = TextEditingController();

  @override
  void dispose() {
    _prefixController.dispose();
    _keyAliasController.dispose();
    _promptTitleController.dispose();
    _promptSubtitleController.dispose();
    _serviceController.dispose();
    _authenticationPromptController.dispose();
    super.dispose();
  }

  Oubliette _buildStorage() {
    if (Platform.isAndroid) {
      return Oubliette(
        android: AndroidSecretAccess.custom(
          prefix: _prefixController.text,
          keyAlias: _keyAliasController.text,
          strongBox: _strongBox,
          unlockedDeviceRequired: _unlockedDeviceRequired,
          invalidatedByBiometricEnrollment: _invalidatedByBiometricEnrollment,
          promptTitle: _promptTitleController.text.isEmpty
              ? null
              : _promptTitleController.text,
          promptSubtitle: _promptSubtitleController.text.isEmpty
              ? null
              : _promptSubtitleController.text,
        ),
        darwin: const DarwinSecretAccess.evenLocked(),
      );
    }
    return Oubliette(
      android: const AndroidSecretAccess.evenLocked(),
      darwin: DarwinSecretAccess.custom(
        prefix: _prefixController.text,
        service: _serviceController.text.isEmpty
            ? null
            : _serviceController.text,
        accessibility: _accessibility,
        useDataProtection: _useDataProtection,
        authenticationRequired: _authenticationRequired,
        biometryCurrentSetOnly: _biometryCurrentSetOnly,
        authenticationPrompt: _authenticationPromptController.text.isEmpty
            ? null
            : _authenticationPromptController.text,
        secureEnclave: _secureEnclave,
        accessGroup: null,
      ),
    );
  }

  void _launch() {
    if (Platform.isAndroid) {
      debugPrint(
        'CustomProfile [Android] '
        'prefix=${_prefixController.text}, '
        'keyAlias=${_keyAliasController.text}, '
        'strongBox=$_strongBox, '
        'unlockedDeviceRequired=$_unlockedDeviceRequired, '
        'invalidatedByBiometricEnrollment=$_invalidatedByBiometricEnrollment, '
        'promptTitle=${_promptTitleController.text.isEmpty ? 'null' : _promptTitleController.text}, '
        'promptSubtitle=${_promptSubtitleController.text.isEmpty ? 'null' : _promptSubtitleController.text}',
      );
    } else {
      debugPrint(
        'CustomProfile [Darwin] '
        'prefix=${_prefixController.text}, '
        'service=${_serviceController.text.isEmpty ? 'null' : _serviceController.text}, '
        'accessibility=${_accessibility.name}, '
        'useDataProtection=$_useDataProtection, '
        'authenticationRequired=$_authenticationRequired, '
        'biometryCurrentSetOnly=$_biometryCurrentSetOnly, '
        'secureEnclave=$_secureEnclave, '
        'authenticationPrompt=${_authenticationPromptController.text.isEmpty ? 'null' : _authenticationPromptController.text}',
      );
    }
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => StorageTestPage(
          storage: _buildStorage(),
          title: 'Custom',
          subtitle: 'prefix: ${_prefixController.text}',
          icon: Icons.tune,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Custom Profile'),
        backgroundColor: cs.inversePrimary,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            TextField(
              controller: _prefixController,
              decoration: const InputDecoration(
                labelText: 'prefix',
                helperText: 'Prepended to every storage key',
                border: OutlineInputBorder(),
              ),
            ),
            if (Platform.isAndroid) ..._buildAndroidFields(tt),
            if (Platform.isIOS || Platform.isMacOS) ..._buildDarwinFields(tt),
            const SizedBox(height: 24),
            FilledButton.icon(
              onPressed: _launch,
              icon: const Icon(Icons.play_arrow),
              label: const Text('Launch'),
            ),
          ],
        ),
      ),
    );
  }

  List<Widget> _buildAndroidFields(TextTheme tt) {
    return [
      const SizedBox(height: 16),
      _SectionHeader('Android Keystore'),
      const SizedBox(height: 8),
      TextField(
        controller: _keyAliasController,
        decoration: const InputDecoration(
          labelText: 'keyAlias',
          helperText: 'Keystore alias for AES-256-GCM key',
          border: OutlineInputBorder(),
        ),
      ),
      const SizedBox(height: 4),
      SwitchListTile(
        title: const Text('strongBox'),
        subtitle: const Text('Prefer hardware Secure Element'),
        value: _strongBox,
        onChanged: (v) => setState(() => _strongBox = v),
      ),
      SwitchListTile(
        title: const Text('unlockedDeviceRequired'),
        subtitle: const Text('Key usable only while device is unlocked'),
        value: _unlockedDeviceRequired,
        onChanged: (v) => setState(() => _unlockedDeviceRequired = v),
      ),
      SwitchListTile(
        title: const Text('invalidatedByBiometricEnrollment'),
        subtitle: const Text('Invalidate key if biometrics change'),
        value: _invalidatedByBiometricEnrollment,
        onChanged: (v) => setState(() => _invalidatedByBiometricEnrollment = v),
      ),
      const SizedBox(height: 8),
      TextField(
        controller: _promptTitleController,
        decoration: const InputDecoration(
          labelText: 'promptTitle (optional)',
          helperText: 'Non-empty enables biometric auth',
          border: OutlineInputBorder(),
        ),
      ),
      const SizedBox(height: 12),
      TextField(
        controller: _promptSubtitleController,
        decoration: const InputDecoration(
          labelText: 'promptSubtitle (optional)',
          border: OutlineInputBorder(),
        ),
      ),
    ];
  }

  List<Widget> _buildDarwinFields(TextTheme tt) {
    return [
      const SizedBox(height: 16),
      _SectionHeader(Platform.isIOS ? 'iOS Keychain' : 'macOS Keychain'),
      const SizedBox(height: 8),
      TextField(
        controller: _serviceController,
        decoration: const InputDecoration(
          labelText: 'service (optional)',
          helperText: 'kSecAttrService — namespaces keychain items',
          border: OutlineInputBorder(),
        ),
      ),
      const SizedBox(height: 12),
      DropdownButtonFormField<KeychainAccessibility>(
        initialValue: _accessibility,
        decoration: const InputDecoration(
          labelText: 'accessibility',
          border: OutlineInputBorder(),
        ),
        items: KeychainAccessibility.values
            .map(
              (a) => DropdownMenuItem(
                value: a,
                child: Text(a.name, style: const TextStyle(fontSize: 13)),
              ),
            )
            .toList(),
        onChanged: (v) {
          if (v != null) setState(() => _accessibility = v);
        },
      ),
      const SizedBox(height: 4),
      SwitchListTile(
        title: const Text('useDataProtection'),
        subtitle: const Text('kSecUseDataProtectionKeychain (macOS)'),
        value: _useDataProtection,
        onChanged: (v) => setState(() => _useDataProtection = v),
      ),
      SwitchListTile(
        title: const Text('authenticationRequired'),
        subtitle: const Text('Require biometric/passcode on read'),
        value: _authenticationRequired,
        onChanged: (v) => setState(() => _authenticationRequired = v),
      ),
      SwitchListTile(
        title: const Text('biometryCurrentSetOnly'),
        subtitle: const Text('Invalidate if biometrics change'),
        value: _biometryCurrentSetOnly,
        onChanged: (v) => setState(() => _biometryCurrentSetOnly = v),
      ),
      SwitchListTile(
        title: const Text('secureEnclave'),
        subtitle: const Text('Encrypt/decrypt via Secure Enclave P-256 key'),
        value: _secureEnclave,
        onChanged: (v) => setState(() => _secureEnclave = v),
      ),
      const SizedBox(height: 8),
      TextField(
        controller: _authenticationPromptController,
        decoration: const InputDecoration(
          labelText: 'authenticationPrompt (optional)',
          helperText: 'Reason shown in system auth dialog',
          border: OutlineInputBorder(),
        ),
      ),
    ];
  }
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.text);
  final String text;

  @override
  Widget build(BuildContext context) {
    return Text(
      text,
      style: Theme.of(context).textTheme.titleSmall?.copyWith(
        color: Theme.of(context).colorScheme.primary,
      ),
    );
  }
}
