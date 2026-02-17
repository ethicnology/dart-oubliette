import 'package:flutter/material.dart';
import 'package:oubliette/oubliette.dart';

import 'custom_profile_page.dart';
import 'storage_test_page.dart';

enum SecurityProfile {
  evenLocked(
    label: 'Even Locked',
    subtitle: 'Accessible even when the device is locked',
    icon: Icons.lock_open,
  ),
  onlyUnlocked(
    label: 'Only Unlocked',
    subtitle: 'Accessible only while the device is unlocked',
    icon: Icons.lock_outline,
  ),
  biometric(
    label: 'Biometric',
    subtitle: 'Requires biometric/passcode — survives enrollment changes',
    icon: Icons.fingerprint,
  ),
  biometricFatal(
    label: 'Biometric Fatal',
    subtitle:
        'Requires biometric — invalidated on enrollment change, destroyed if passcode removed',
    icon: Icons.front_hand,
  );

  const SecurityProfile({
    required this.label,
    required this.subtitle,
    required this.icon,
  });

  final String label;
  final String subtitle;
  final IconData icon;

  Oubliette createStorage() {
    switch (this) {
      case SecurityProfile.evenLocked:
        return Oubliette(
          android: const AndroidSecretAccess.evenLocked(prefix: 'demo_el_'),
          darwin: const DarwinSecretAccess.evenLocked(prefix: 'demo_el_'),
        );
      case SecurityProfile.onlyUnlocked:
        return Oubliette(
          android: const AndroidSecretAccess.onlyUnlocked(
            prefix: 'demo_ou_',
            strongBox: false,
          ),
          darwin: const DarwinSecretAccess.onlyUnlocked(
            prefix: 'demo_ou_',
            secureEnclave: false,
          ),
        );
      case SecurityProfile.biometric:
        return Oubliette(
          android: const AndroidSecretAccess.biometric(
            prefix: 'demo_bio_',
            strongBox: false,
            promptTitle: 'Oubliette',
            promptSubtitle: 'Authenticate to access your secret',
          ),
          darwin: const DarwinSecretAccess.biometric(
            prefix: 'demo_bio_',
            promptReason: 'Authenticate to access your secret',
            secureEnclave: true,
          ),
        );
      case SecurityProfile.biometricFatal:
        return Oubliette(
          android: const AndroidSecretAccess.biometricFatal(
            prefix: 'demo_bs_',
            strongBox: false,
            promptTitle: 'Oubliette',
            promptSubtitle: 'Authenticate to access your secret',
          ),
          darwin: const DarwinSecretAccess.biometricFatal(
            prefix: 'demo_bs_',
            promptReason: 'Authenticate to access your secret',
            secureEnclave: true,
          ),
        );
    }
  }
}

class ProfileListPage extends StatelessWidget {
  const ProfileListPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Oubliette'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: ListView(
        padding: const EdgeInsets.symmetric(vertical: 16),
        children: [
          ...SecurityProfile.values.map(
            (profile) => ListTile(
              leading: Icon(profile.icon),
              title: Text(profile.label),
              subtitle: Text(profile.subtitle),
              trailing: const Icon(Icons.chevron_right),
              onTap: () => Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => StorageTestPage(
                    storage: profile.createStorage(),
                    title: profile.label,
                    subtitle: profile.subtitle,
                    icon: profile.icon,
                  ),
                ),
              ),
            ),
          ),
          const Divider(),
          ListTile(
            leading: const Icon(Icons.tune),
            title: const Text('Custom Profile'),
            subtitle: const Text('Build your own parameter combination'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const CustomProfilePage()),
            ),
          ),
        ],
      ),
    );
  }
}
