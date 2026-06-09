#include "include/secretservice/secretservice_plugin.h"

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>
#include <libsecret/secret.h>

#include <cstring>

// ---------------------------------------------------------------------------
// Frozen storage schema. UPGRADE CONTRACT: the schema name and attribute names
// below are an on-disk contract — once shipped they are NEVER changed, or every
// stored item orphans (the upgrade-data-loss this library exists to prevent).
//
// - `slot`: the full storage slot, `prefix + U+001D + key` (built in Dart).
//   Stored UNENCRYPTED (Secret Service keeps attributes in the clear for
//   lookup), so slot names are not secret — only the value is encrypted.
// - `fmt` : a constant scoping attribute ("v1") that tags every oubliette item,
//   used to enumerate this app's items during a prefixed purge. It is NOT the
//   payload version — the payload carries its own 1-byte header inside the
//   encrypted value (mirroring the Darwin format header).
//
// SECRET_SCHEMA_NONE matches the schema *name*, scoping lookups/searches to
// this app's items.
// ---------------------------------------------------------------------------
static const SecretSchema kSchema = {
    "com.oubliette.secretservice",
    SECRET_SCHEMA_NONE,
    {
        {"slot", SECRET_SCHEMA_ATTRIBUTE_STRING},
        {"fmt", SECRET_SCHEMA_ATTRIBUTE_STRING},
        {nullptr, static_cast<SecretSchemaAttributeType>(0)},
    },
    // Reserved fields zero-initialised.
    0, 0, 0, 0, 0, 0, 0, 0};

static const char* kFmt = "v1";

#define SECRETSERVICE_PLUGIN(obj)                                     \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), secretservice_plugin_get_type(), \
                              SecretServicePlugin))

struct _SecretServicePlugin {
  GObject parent_instance;
};

G_DEFINE_TYPE(SecretServicePlugin, secretservice_plugin, g_object_get_type())

// Frees a gchar* secret in place (best effort).
#define secret_autofree _GLIB_CLEANUP(secret_cleanup_free)
static inline void secret_cleanup_free(gchar** p) {
  if (*p) secret_password_free(*p);
}

// ---------------------------------------------------------------------------
// Backend readiness. Returns the SecretService (transfer full — caller unrefs)
// or nullptr with *err_code set to a stable, distinct code so the Dart layer
// can pick the right typed exception:
//   - "backend_unavailable": no session D-Bus / no Secret Service provider, or
//     the default collection cannot be resolved (NON-recoverable env problem).
//   - "keyring_locked": the default collection is present but locked and the
//     unlock did not complete (RECOVERABLE — retry once unlocked).
// We never silently treat "no backend" and "locked" as the same thing.
// ---------------------------------------------------------------------------
static SecretService* warmup(const char** err_code) {
  *err_code = nullptr;
  g_autoptr(GError) error = nullptr;

  SecretService* service = secret_service_get_sync(
      static_cast<SecretServiceFlags>(SECRET_SERVICE_OPEN_SESSION |
                                      SECRET_SERVICE_LOAD_COLLECTIONS),
      nullptr, &error);
  if (!service) {
    *err_code = "backend_unavailable";
    return nullptr;
  }

  SecretCollection* collection = secret_collection_for_alias_sync(
      service, SECRET_COLLECTION_DEFAULT, SECRET_COLLECTION_NONE, nullptr,
      &error);
  if (!collection) {
    g_object_unref(service);
    *err_code = "backend_unavailable";
    return nullptr;
  }

  if (secret_collection_get_locked(collection)) {
    GList* to_unlock = g_list_append(nullptr, collection);
    GList* unlocked = nullptr;
    gint n = secret_service_unlock_sync(service, to_unlock, nullptr, &unlocked,
                                        &error);
    g_list_free(to_unlock);
    if (unlocked) g_list_free_full(unlocked, g_object_unref);
    if (n == 0) {
      g_object_unref(collection);
      g_object_unref(service);
      *err_code = "keyring_locked";
      return nullptr;
    }
  }

  g_object_unref(collection);
  return service;
}

// Helper: build a FlMethodResponse error from a stable code + message.
static FlMethodResponse* error_response(const char* code, const char* message) {
  return FL_METHOD_RESPONSE(
      fl_method_error_response_new(code, message, nullptr));
}

// contains(slot) -> bool
static FlMethodResponse* handle_contains(const gchar* slot) {
  const char* code = nullptr;
  SecretService* service = warmup(&code);
  if (!service) return error_response(code, "Secret Service is not ready.");
  g_object_unref(service);

  g_autoptr(GError) error = nullptr;
  secret_autofree gchar* value = secret_password_lookup_sync(
      &kSchema, nullptr, &error, "slot", slot, nullptr);
  if (error) {
    return error_response("secret_service_error", error->message);
  }
  return FL_METHOD_RESPONSE(
      fl_method_success_response_new(fl_value_new_bool(value != nullptr)));
}

// write(slot, value) -> null. Fail-closed if the slot already exists.
static FlMethodResponse* handle_write(const gchar* slot, const gchar* value) {
  const char* code = nullptr;
  SecretService* service = warmup(&code);
  if (!service) return error_response(code, "Secret Service is not ready.");
  g_object_unref(service);

  g_autoptr(GError) lookup_error = nullptr;
  secret_autofree gchar* existing = secret_password_lookup_sync(
      &kSchema, nullptr, &lookup_error, "slot", slot, nullptr);
  if (lookup_error) {
    return error_response("secret_service_error", lookup_error->message);
  }
  if (existing != nullptr) {
    return error_response("already_exists",
                          "A value already exists for this slot.");
  }

  g_autoptr(GError) store_error = nullptr;
  gboolean ok = secret_password_store_sync(
      &kSchema, SECRET_COLLECTION_DEFAULT, "Oubliette", value, nullptr,
      &store_error, "slot", slot, "fmt", kFmt, nullptr);
  if (store_error) {
    return error_response("secret_service_error", store_error->message);
  }
  if (!ok) {
    return error_response("secret_service_error", "Store returned false.");
  }
  return FL_METHOD_RESPONSE(fl_method_success_response_new(nullptr));
}

// read(slot) -> string | null
static FlMethodResponse* handle_read(const gchar* slot) {
  const char* code = nullptr;
  SecretService* service = warmup(&code);
  if (!service) return error_response(code, "Secret Service is not ready.");
  g_object_unref(service);

  g_autoptr(GError) error = nullptr;
  secret_autofree gchar* value = secret_password_lookup_sync(
      &kSchema, nullptr, &error, "slot", slot, nullptr);
  if (error) {
    return error_response("secret_service_error", error->message);
  }
  if (value == nullptr) {
    return FL_METHOD_RESPONSE(fl_method_success_response_new(nullptr));
  }
  return FL_METHOD_RESPONSE(
      fl_method_success_response_new(fl_value_new_string(value)));
}

// delete(slot) -> null. A locked/unavailable keyring throws (never a silent
// no-op): warmup runs first and surfaces backend_unavailable / keyring_locked.
static FlMethodResponse* handle_delete(const gchar* slot) {
  const char* code = nullptr;
  SecretService* service = warmup(&code);
  if (!service) return error_response(code, "Secret Service is not ready.");
  g_object_unref(service);

  g_autoptr(GError) error = nullptr;
  secret_password_clear_sync(&kSchema, nullptr, &error, "slot", slot, nullptr);
  if (error) {
    return error_response("secret_service_error", error->message);
  }
  return FL_METHOD_RESPONSE(fl_method_success_response_new(nullptr));
}

// deleteByPrefix(prefix) -> null. Enumerates this app's items and deletes those
// whose `slot` attribute begins with [prefix]. Ownership is exact because the
// caller passes `profilePrefix + U+001D`.
static FlMethodResponse* handle_delete_by_prefix(const gchar* prefix) {
  const char* code = nullptr;
  SecretService* service = warmup(&code);
  if (!service) return error_response(code, "Secret Service is not ready.");

  GHashTable* attrs = g_hash_table_new(g_str_hash, g_str_equal);
  g_hash_table_insert(attrs, const_cast<char*>("fmt"), const_cast<char*>(kFmt));

  g_autoptr(GError) search_error = nullptr;
  GList* items = secret_service_search_sync(
      service, &kSchema, attrs,
      static_cast<SecretSearchFlags>(SECRET_SEARCH_ALL | SECRET_SEARCH_UNLOCK),
      nullptr, &search_error);
  g_hash_table_unref(attrs);

  if (search_error) {
    g_object_unref(service);
    return error_response("secret_service_error", search_error->message);
  }

  const char* delete_error_message = nullptr;
  for (GList* l = items; l != nullptr; l = l->next) {
    SecretItem* item = SECRET_ITEM(l->data);
    GHashTable* item_attrs = secret_item_get_attributes(item);
    const char* slot =
        static_cast<const char*>(g_hash_table_lookup(item_attrs, "slot"));
    if (slot != nullptr && g_str_has_prefix(slot, prefix)) {
      g_autoptr(GError) del_error = nullptr;
      secret_item_delete_sync(item, nullptr, &del_error);
      if (del_error && delete_error_message == nullptr) {
        delete_error_message = g_strdup(del_error->message);
      }
    }
    g_hash_table_unref(item_attrs);
  }
  if (items) g_list_free_full(items, g_object_unref);
  g_object_unref(service);

  if (delete_error_message != nullptr) {
    return error_response("secret_service_error", delete_error_message);
  }
  return FL_METHOD_RESPONSE(fl_method_success_response_new(nullptr));
}

static void secretservice_plugin_handle_method_call(
    SecretServicePlugin* self, FlMethodCall* method_call) {
  g_autoptr(FlMethodResponse) response = nullptr;

  const gchar* method = fl_method_call_get_name(method_call);
  FlValue* args = fl_method_call_get_args(method_call);

  if (fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
    response = error_response("bad_args", "Arguments are not a map.");
    fl_method_call_respond(method_call, response, nullptr);
    return;
  }

  FlValue* slot_value = fl_value_lookup_string(args, "slot");
  FlValue* value_value = fl_value_lookup_string(args, "value");
  FlValue* prefix_value = fl_value_lookup_string(args, "prefix");
  const gchar* slot =
      slot_value == nullptr ? nullptr : fl_value_get_string(slot_value);
  const gchar* value =
      value_value == nullptr ? nullptr : fl_value_get_string(value_value);
  const gchar* prefix =
      prefix_value == nullptr ? nullptr : fl_value_get_string(prefix_value);

  if (strcmp(method, "contains") == 0) {
    if (!slot)
      response = error_response("bad_args", "Missing slot.");
    else
      response = handle_contains(slot);
  } else if (strcmp(method, "write") == 0) {
    if (!slot || !value)
      response = error_response("bad_args", "Missing slot or value.");
    else
      response = handle_write(slot, value);
  } else if (strcmp(method, "read") == 0) {
    if (!slot)
      response = error_response("bad_args", "Missing slot.");
    else
      response = handle_read(slot);
  } else if (strcmp(method, "delete") == 0) {
    if (!slot)
      response = error_response("bad_args", "Missing slot.");
    else
      response = handle_delete(slot);
  } else if (strcmp(method, "deleteByPrefix") == 0) {
    if (!prefix)
      response = error_response("bad_args", "Missing prefix.");
    else
      response = handle_delete_by_prefix(prefix);
  } else {
    response = FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
  }

  fl_method_call_respond(method_call, response, nullptr);
}

static void secretservice_plugin_dispose(GObject* object) {
  G_OBJECT_CLASS(secretservice_plugin_parent_class)->dispose(object);
}

static void secretservice_plugin_class_init(SecretServicePluginClass* klass) {
  G_OBJECT_CLASS(klass)->dispose = secretservice_plugin_dispose;
}

static void secretservice_plugin_init(SecretServicePlugin* self) {}

static void method_call_cb(FlMethodChannel* channel, FlMethodCall* method_call,
                           gpointer user_data) {
  SecretServicePlugin* plugin = SECRETSERVICE_PLUGIN(user_data);
  secretservice_plugin_handle_method_call(plugin, method_call);
}

void secretservice_plugin_register_with_registrar(
    FlPluginRegistrar* registrar) {
  SecretServicePlugin* plugin = SECRETSERVICE_PLUGIN(
      g_object_new(secretservice_plugin_get_type(), nullptr));

  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
  g_autoptr(FlMethodChannel) channel = fl_method_channel_new(
      fl_plugin_registrar_get_messenger(registrar), "secretservice",
      FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(
      channel, method_call_cb, g_object_ref(plugin), g_object_unref);

  g_object_unref(plugin);
}
