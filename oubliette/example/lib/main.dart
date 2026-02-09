import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:oubliette/oubliette.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Oubliette',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.teal),
        useMaterial3: true,
      ),
      home: const _OublietteDemoPage(),
    );
  }
}

class _OublietteDemoPage extends StatefulWidget {
  const _OublietteDemoPage();

  @override
  State<_OublietteDemoPage> createState() => _OublietteDemoPageState();
}

class _OublietteDemoPageState extends State<_OublietteDemoPage> {
  final Oubliette _storage = createOubliette();
  final _keyController = TextEditingController(text: 'my_secret_key');
  final _valueController = TextEditingController();
  String? _fetchedValue;
  String? _message;
  bool _obscureFetched = true;
  bool _loading = false;

  @override
  void dispose() {
    _keyController.dispose();
    _valueController.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    final key = _keyController.text.trim();
    final value = _valueController.text;
    if (key.isEmpty) {
      _setMessage('Enter a key.', isError: true);
      return;
    }
    setState(() {
      _loading = true;
      _message = null;
      _fetchedValue = null;
    });
    try {
      await _storage.storeString(key, value);
      if (!mounted) return;
      _setMessage('Saved securely (${Platform.isIOS ? "Keychain" : "Keystore + encrypted prefs"}).');
    } on PlatformException catch (e) {
      _setMessage('${e.code}: ${e.message ?? "unknown"}', isError: true);
    } catch (e) {
      _setMessage('$e', isError: true);
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _load() async {
    final key = _keyController.text.trim();
    if (key.isEmpty) {
      _setMessage('Enter a key.', isError: true);
      return;
    }
    setState(() {
      _loading = true;
      _message = null;
      _fetchedValue = null;
    });
    try {
      final value = await _storage.fetchString(key);
      if (!mounted) return;
      setState(() {
        _fetchedValue = value;
        _message = value == null ? 'No value for this key.' : null;
      });
    } on PlatformException catch (e) {
      _setMessage('${e.code}: ${e.message ?? "unknown"}', isError: true);
    } catch (e) {
      _setMessage('$e', isError: true);
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _delete() async {
    final key = _keyController.text.trim();
    if (key.isEmpty) {
      _setMessage('Enter a key.', isError: true);
      return;
    }
    setState(() {
      _loading = true;
      _message = null;
      _fetchedValue = null;
    });
    try {
      await _storage.trash(key);
      if (!mounted) return;
      _setMessage('Key deleted.');
    } on PlatformException catch (e) {
      _setMessage('${e.code}: ${e.message ?? "unknown"}', isError: true);
    } catch (e) {
      _setMessage('$e', isError: true);
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  void _setMessage(String msg, {bool isError = false}) {
    if (!mounted) return;
    setState(() => _message = msg);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Oubliette'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Why this library?',
                      style: Theme.of(context).textTheme.titleMedium?.copyWith(
                            fontWeight: FontWeight.bold,
                          ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      Platform.isIOS
                          ? 'Data is stored in the iOS Keychain. It is not in plain SharedPreferences and benefits from system-level protection.'
                          : 'Data is encrypted with a key held in Android Keystore, then stored. The secret never lives in plain text in app storage.',
                      style: Theme.of(context).textTheme.bodyMedium,
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),
            Text(
              'Key',
              style: Theme.of(context).textTheme.labelLarge,
            ),
            const SizedBox(height: 4),
            TextField(
              controller: _keyController,
              decoration: const InputDecoration(
                hintText: 'e.g. api_token, refresh_token, pin',
                border: OutlineInputBorder(),
              ),
              textInputAction: TextInputAction.next,
            ),
            const SizedBox(height: 16),
            Text(
              'Value (secret to store)',
              style: Theme.of(context).textTheme.labelLarge,
            ),
            const SizedBox(height: 4),
            TextField(
              controller: _valueController,
              decoration: const InputDecoration(
                hintText: 'Enter a secret string',
                border: OutlineInputBorder(),
              ),
              obscureText: true,
              textInputAction: TextInputAction.done,
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: FilledButton.icon(
                    onPressed: _loading ? null : _save,
                    icon: _loading
                        ? const SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.save, size: 18),
                    label: const Text('Save'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton.tonalIcon(
                    onPressed: _loading ? null : _load,
                    icon: const Icon(Icons.download, size: 18),
                    label: const Text('Load'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: _loading ? null : _delete,
                    icon: const Icon(Icons.delete_outline, size: 18),
                    label: const Text('Delete'),
                  ),
                ),
              ],
            ),
            if (_message != null) ...[
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  _message!,
                  style: Theme.of(context).textTheme.bodySmall,
                ),
              ),
            ],
            if (_fetchedValue != null) ...[
              const SizedBox(height: 16),
              Card(
                color: Theme.of(context).colorScheme.surfaceContainerLow,
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Text(
                            'Stored value',
                            style: Theme.of(context).textTheme.labelLarge,
                          ),
                          IconButton(
                            icon: Icon(
                              _obscureFetched ? Icons.visibility : Icons.visibility_off,
                            ),
                            onPressed: () =>
                                setState(() => _obscureFetched = !_obscureFetched),
                          ),
                        ],
                      ),
                      const SizedBox(height: 4),
                      SelectableText(
                        _obscureFetched
                            ? '•' * _fetchedValue!.length
                            : _fetchedValue!,
                        style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                              fontFamily: 'monospace',
                            ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
