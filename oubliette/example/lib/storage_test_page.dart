import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:oubliette/oubliette.dart';

class StorageTestPage extends StatefulWidget {
  const StorageTestPage({
    super.key,
    required this.storage,
    required this.title,
    required this.subtitle,
    this.icon,
  });

  final Oubliette storage;
  final String title;
  final String subtitle;
  final IconData? icon;

  @override
  State<StorageTestPage> createState() => _StorageTestPageState();
}

class _StorageTestPageState extends State<StorageTestPage> {
  final _keyController = TextEditingController(text: 'my_secret');
  final _valueController = TextEditingController();
  String? _fetchedValue;
  String? _message;
  bool _isError = false;
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
    if (key.isEmpty) { _setMessage('Enter a key.', error: true); return; }
    setState(() { _loading = true; _message = null; _fetchedValue = null; });
    try {
      await widget.storage.storeString(key, value);
      if (!mounted) return;
      _setMessage('Saved.');
    } on PlatformException catch (e) {
      _setMessage('${e.code}: ${e.message ?? "unknown"}', error: true);
    } catch (e) {
      _setMessage('$e', error: true);
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _load() async {
    final key = _keyController.text.trim();
    if (key.isEmpty) { _setMessage('Enter a key.', error: true); return; }
    setState(() { _loading = true; _message = null; _fetchedValue = null; });
    try {
      await widget.storage.useStringAndForget<void>(key, (value) async {
        if (!mounted) return;
        setState(() {
          _fetchedValue = value;
          _message = null;
          _isError = false;
        });
      });
      if (_fetchedValue == null && mounted) {
        setState(() {
          _message = 'No value for this key.';
          _isError = true;
        });
      }
    } on PlatformException catch (e) {
      _setMessage('${e.code}: ${e.message ?? "unknown"}', error: true);
    } catch (e) {
      _setMessage('$e', error: true);
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _delete() async {
    final key = _keyController.text.trim();
    if (key.isEmpty) { _setMessage('Enter a key.', error: true); return; }
    setState(() { _loading = true; _message = null; _fetchedValue = null; });
    try {
      await widget.storage.trash(key);
      if (!mounted) return;
      _setMessage('Deleted.');
    } on PlatformException catch (e) {
      _setMessage('${e.code}: ${e.message ?? "unknown"}', error: true);
    } catch (e) {
      _setMessage('$e', error: true);
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _exists() async {
    final key = _keyController.text.trim();
    if (key.isEmpty) { _setMessage('Enter a key.', error: true); return; }
    setState(() { _loading = true; _message = null; _fetchedValue = null; });
    try {
      final found = await widget.storage.exists(key);
      if (!mounted) return;
      _setMessage(found ? 'Key exists.' : 'Key not found.');
    } on PlatformException catch (e) {
      _setMessage('${e.code}: ${e.message ?? "unknown"}', error: true);
    } catch (e) {
      _setMessage('$e', error: true);
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  void _setMessage(String msg, {bool error = false}) {
    if (!mounted) return;
    setState(() { _message = msg; _isError = error; });
  }

  String get _platformHint {
    if (Platform.isAndroid) return 'Android Keystore + encrypted file';
    if (Platform.isIOS) return 'iOS Keychain';
    if (Platform.isMacOS) return 'macOS Keychain';
    return 'Platform storage';
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
        backgroundColor: cs.inversePrimary,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Row(
                  children: [
                    if (widget.icon != null) ...[
                      Icon(widget.icon, size: 28, color: cs.primary),
                      const SizedBox(width: 12),
                    ],
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(widget.subtitle, style: tt.bodyMedium),
                          const SizedBox(height: 4),
                          Text(_platformHint, style: tt.bodySmall?.copyWith(color: cs.outline)),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),
            Text('Key', style: tt.labelLarge),
            const SizedBox(height: 4),
            TextField(
              controller: _keyController,
              decoration: const InputDecoration(
                hintText: 'e.g. seed_phrase, api_token',
                border: OutlineInputBorder(),
              ),
              textInputAction: TextInputAction.next,
            ),
            const SizedBox(height: 16),
            Text('Value', style: tt.labelLarge),
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
                        ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
                        : const Icon(Icons.save, size: 18),
                    label: const Text('Save'),
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: FilledButton.tonalIcon(
                    onPressed: _loading ? null : _load,
                    icon: const Icon(Icons.download, size: 18),
                    label: const Text('Load'),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: _loading ? null : _exists,
                    icon: const Icon(Icons.search, size: 18),
                    label: const Text('Exists?'),
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: _loading ? null : _delete,
                    icon: Icon(Icons.delete_outline, size: 18, color: cs.error),
                    label: Text('Delete', style: TextStyle(color: cs.error)),
                  ),
                ),
              ],
            ),
            if (_message != null) ...[
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: _isError ? cs.errorContainer : cs.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  _message!,
                  style: tt.bodySmall?.copyWith(
                    color: _isError ? cs.onErrorContainer : cs.onSurface,
                  ),
                ),
              ),
            ],
            if (_fetchedValue != null) ...[
              const SizedBox(height: 16),
              Card(
                color: cs.surfaceContainerLow,
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Text('Stored value', style: tt.labelLarge),
                          IconButton(
                            icon: Icon(_obscureFetched ? Icons.visibility : Icons.visibility_off),
                            onPressed: () => setState(() => _obscureFetched = !_obscureFetched),
                          ),
                        ],
                      ),
                      const SizedBox(height: 4),
                      SelectableText(
                        _obscureFetched ? '•' * _fetchedValue!.length : _fetchedValue!,
                        style: tt.bodyMedium?.copyWith(fontFamily: 'monospace'),
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
