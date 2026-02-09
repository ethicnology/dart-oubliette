// coverage:ignore-file
// GENERATED CODE - DO NOT MODIFY BY HAND
// dart format off
// ignore_for_file: type=lint
// ignore_for_file: invalid_use_of_protected_member
// ignore_for_file: unused_element, unnecessary_cast, override_on_non_overriding_member
// ignore_for_file: strict_raw_type, inference_failure_on_untyped_parameter

part of 'encrypted_payload.dart';

class EncryptedPayloadMapper extends ClassMapperBase<EncryptedPayload> {
  EncryptedPayloadMapper._();

  static EncryptedPayloadMapper? _instance;
  static EncryptedPayloadMapper ensureInitialized() {
    if (_instance == null) {
      MapperContainer.globals.use(_instance = EncryptedPayloadMapper._());
    }
    return _instance!;
  }

  @override
  final String id = 'EncryptedPayload';

  static int _$version(EncryptedPayload v) => v.version;
  static const Field<EncryptedPayload, int> _f$version = Field('version', _$version);
  static Uint8List _$nonce(EncryptedPayload v) => v.nonce;
  static const Field<EncryptedPayload, Uint8List> _f$nonce = Field(
    'nonce',
    _$nonce,
    hook: Uint8ListBase64Hook(),
  );
  static Uint8List _$ciphertext(EncryptedPayload v) => v.ciphertext;
  static const Field<EncryptedPayload, Uint8List> _f$ciphertext = Field(
    'ciphertext',
    _$ciphertext,
    hook: Uint8ListBase64Hook(),
  );
  static String _$aad(EncryptedPayload v) => v.aad;
  static const Field<EncryptedPayload, String> _f$aad = Field('aad', _$aad);
  static String _$alias(EncryptedPayload v) => v.alias;
  static const Field<EncryptedPayload, String> _f$alias = Field('alias', _$alias);

  @override
  final MappableFields<EncryptedPayload> fields = const {
    #version: _f$version,
    #nonce: _f$nonce,
    #ciphertext: _f$ciphertext,
    #aad: _f$aad,
    #alias: _f$alias,
  };

  static EncryptedPayload _instantiate(DecodingData data) {
    return EncryptedPayload(
      version: data.dec(_f$version),
      nonce: data.dec(_f$nonce),
      ciphertext: data.dec(_f$ciphertext),
      aad: data.dec(_f$aad),
      alias: data.dec(_f$alias),
    );
  }

  @override
  final Function instantiate = _instantiate;

  static EncryptedPayload fromMap(Map<String, dynamic> map) {
    return ensureInitialized().decodeMap<EncryptedPayload>(map);
  }

  static EncryptedPayload fromJson(String json) {
    return ensureInitialized().decodeJson<EncryptedPayload>(json);
  }
}

mixin EncryptedPayloadMappable {
  String toJson() {
    return EncryptedPayloadMapper.ensureInitialized()
        .encodeJson<EncryptedPayload>(this as EncryptedPayload);
  }

  Map<String, dynamic> toMap() {
    return EncryptedPayloadMapper.ensureInitialized()
        .encodeMap<EncryptedPayload>(this as EncryptedPayload);
  }

  EncryptedPayloadCopyWith<EncryptedPayload, EncryptedPayload, EncryptedPayload>
  get copyWith =>
      _EncryptedPayloadCopyWithImpl<EncryptedPayload, EncryptedPayload>(
        this as EncryptedPayload,
        $identity,
        $identity,
      );
  @override
  String toString() {
    return EncryptedPayloadMapper.ensureInitialized().stringifyValue(
      this as EncryptedPayload,
    );
  }

  @override
  bool operator ==(Object other) {
    return EncryptedPayloadMapper.ensureInitialized().equalsValue(
      this as EncryptedPayload,
      other,
    );
  }

  @override
  int get hashCode {
    return EncryptedPayloadMapper.ensureInitialized().hashValue(
      this as EncryptedPayload,
    );
  }
}

extension EncryptedPayloadValueCopy<$R, $Out>
    on ObjectCopyWith<$R, EncryptedPayload, $Out> {
  EncryptedPayloadCopyWith<$R, EncryptedPayload, $Out>
  get $asEncryptedPayload =>
      $base.as((v, t, t2) => _EncryptedPayloadCopyWithImpl<$R, $Out>(v, t, t2));
}

abstract class EncryptedPayloadCopyWith<$R, $In extends EncryptedPayload, $Out>
    implements ClassCopyWith<$R, $In, $Out> {
  $R call({int? version, Uint8List? nonce, Uint8List? ciphertext, String? aad, String? alias});
  EncryptedPayloadCopyWith<$R2, $In, $Out2> $chain<$R2, $Out2>(
    Then<$Out2, $R2> t,
  );
}

class _EncryptedPayloadCopyWithImpl<$R, $Out>
    extends ClassCopyWithBase<$R, EncryptedPayload, $Out>
    implements EncryptedPayloadCopyWith<$R, EncryptedPayload, $Out> {
  _EncryptedPayloadCopyWithImpl(super.value, super.then, super.then2);

  @override
  late final ClassMapperBase<EncryptedPayload> $mapper =
      EncryptedPayloadMapper.ensureInitialized();
  @override
  $R call({int? version, Uint8List? nonce, Uint8List? ciphertext, String? aad, String? alias}) => $apply(
    FieldCopyWithData({
      if (version != null) #version: version,
      if (nonce != null) #nonce: nonce,
      if (ciphertext != null) #ciphertext: ciphertext,
      if (aad != null) #aad: aad,
      if (alias != null) #alias: alias,
    }),
  );
  @override
  EncryptedPayload $make(CopyWithData data) => EncryptedPayload(
    version: data.get(#version, or: $value.version),
    nonce: data.get(#nonce, or: $value.nonce),
    ciphertext: data.get(#ciphertext, or: $value.ciphertext),
    aad: data.get(#aad, or: $value.aad),
    alias: data.get(#alias, or: $value.alias),
  );

  @override
  EncryptedPayloadCopyWith<$R2, EncryptedPayload, $Out2> $chain<$R2, $Out2>(
    Then<$Out2, $R2> t,
  ) => _EncryptedPayloadCopyWithImpl<$R2, $Out2>($value, $cast, t);
}
