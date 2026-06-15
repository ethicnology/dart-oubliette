#include "include/secret_service/secret_service_plugin.h"

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
// SECRET_SCHEMA_NONE means libsecret does NOT add or match the implicit
// `xdg:schema` name attribute — items are matched purely on the attributes we
// pass. So the schema name is documentation only; it does NOT scope lookups.
// App-scoping is therefore carried entirely by the `fmt` attribute, which every
// store writes and every lookup/search below matches on (alongside `slot`), so
// a foreign item that merely reuses an attribute named `slot` cannot collide.
// ---------------------------------------------------------------------------
static const SecretSchema kSchema = {
    "com.oubliette.secret_service",
    SECRET_SCHEMA_NONE,
    {
        {"slot", SECRET_SCHEMA_ATTRIBUTE_STRING},
        {"fmt", SECRET_SCHEMA_ATTRIBUTE_STRING},
        {nullptr, static_cast<SecretSchemaAttributeType>(0)},
    },
    // Reserved fields zero-initialised.
    0, 0, 0, 0, 0, 0, 0, 0};

static const char* kFmt = "v1";

#define SECRET_SERVICE_PLUGIN(obj)                                     \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), secret_service_plugin_get_type(), \
                              SecretServicePlugin))

struct _SecretServicePlugin {
  GObject parent_instance;
};

G_DEFINE_TYPE(SecretServicePlugin, secret_service_plugin, g_object_get_type())

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
// Bound for the interactive keyring unlock. A headless / no-prompter session
// has no agent to satisfy the prompt, so the sync unlock could otherwise block
// forever; cap it and surface the recoverable "keyring_locked" instead.
static const guint kUnlockTimeoutSeconds = 20;

// Watchdog shared between the bounded caller and its detached timer thread.
// Refcounted so neither side frees it out from under the other: the caller holds
// one ref for the lifetime of the bounded call, the timer holds one for the
// lifetime of the thread, and whichever drops last frees it. The GCond/GMutex
// pair lets the caller WAKE the timer the instant the operation finishes, so the
// thread does not linger sleeping for the full timeout after every (fast, common)
// unlocked call — LINUX-2 arms this on EVERY per-operation call, so a burst of
// operations would otherwise pile up one ~20 s-sleeping thread per call.
struct OpWatchdog {
  gint refcount;        // g_atomic
  GMutex mutex;         // guards `done`
  GCond cond;           // signalled when `done` flips
  gboolean done;        // set by the caller when the bounded call returns
  GCancellable* cancellable;
};

static void op_watchdog_unref(OpWatchdog* w) {
  if (!g_atomic_int_dec_and_test(&w->refcount)) return;
  g_object_unref(w->cancellable);
  g_cond_clear(&w->cond);
  g_mutex_clear(&w->mutex);
  g_free(w);
}

// Timer thread: waits until either the deadline elapses or the caller signals
// completion, then cancels the GCancellable (a no-op if the call already
// finished — g_cancellable_cancel on an unused or done cancellable is harmless).
// The bounded g_cond_wait_until is one-shot and deadline-capped, so it cannot
// deadlock even if the signal is missed. Drops the timer's watchdog ref on exit.
static gpointer op_timeout_thread(gpointer data) {
  OpWatchdog* w = static_cast<OpWatchdog*>(data);
  gint64 deadline =
      g_get_monotonic_time() +
      static_cast<gint64>(kUnlockTimeoutSeconds) * G_TIME_SPAN_SECOND;
  g_mutex_lock(&w->mutex);
  while (!w->done) {
    if (!g_cond_wait_until(&w->cond, &w->mutex, deadline)) break;  // timed out
  }
  gboolean timed_out = !w->done;
  g_mutex_unlock(&w->mutex);
  if (timed_out) g_cancellable_cancel(w->cancellable);
  op_watchdog_unref(w);
  return nullptr;
}

// LINUX-2: returns a fresh OpWatchdog whose `cancellable` is armed with the
// detached timeout above, so ANY sync call that can trigger an interactive
// unlock prompt (not just the warmup) is bounded — e.g. a keyring that re-locks
// (daemon restart) between the warmup and the operation, or an externally
// created item in another locked collection reached via SECRET_SEARCH_UNLOCK,
// would otherwise re-prompt with no cancellable and hang the platform thread
// forever. The caller owns one ref and MUST release it via op_watchdog_finish()
// after the bounded call (which both wakes the timer and drops the ref). Thread-
// creation failure degrades to an un-timed (but still correct) call rather than
// aborting the host app — identical to the warmup path. A cancelled-by-timeout
// call returns a G_IO_ERROR_CANCELLED GError that every handler already surfaces
// as an error (never as "absent" / success).
static OpWatchdog* op_watchdog_arm() {
  OpWatchdog* w = g_new0(OpWatchdog, 1);
  w->refcount = 1;  // the caller's ref
  g_mutex_init(&w->mutex);
  g_cond_init(&w->cond);
  w->done = FALSE;
  w->cancellable = g_cancellable_new();

  g_atomic_int_inc(&w->refcount);  // the timer's ref
  GThread* timer =
      g_thread_try_new("oubliette-op-timeout", op_timeout_thread, w, nullptr);
  if (timer != nullptr) {
    g_thread_unref(timer);  // detached; it owns and releases its own ref
  } else {
    // No timer: the call runs un-timed (correct, just unbounded). Drop the ref
    // minted for the absent thread; mark done so no stale wake is expected.
    g_mutex_lock(&w->mutex);
    w->done = TRUE;
    g_mutex_unlock(&w->mutex);
    op_watchdog_unref(w);
  }
  return w;
}

// Signals the timer that the bounded call has returned (waking it so it exits
// immediately instead of sleeping out the timeout) and drops the caller's ref.
static void op_watchdog_finish(OpWatchdog* w) {
  g_mutex_lock(&w->mutex);
  w->done = TRUE;
  g_cond_signal(&w->cond);
  g_mutex_unlock(&w->mutex);
  op_watchdog_unref(w);
}

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
    // LINUX-1: bound the interactive unlock so a headless/no-prompter session
    // cannot hang here forever — a detached timer cancels it after a timeout.
    OpWatchdog* watchdog = op_watchdog_arm();

    GList* to_unlock = g_list_append(nullptr, collection);
    GList* unlocked = nullptr;
    // Returns the count unlocked (>= 1 on success), 0 if the prompt was
    // dismissed (no item unlocked, no GError), or -1 on error / cancellation
    // (timeout, which sets a G_IO_ERROR_CANCELLED GError). Anything but a
    // positive count is fail-closed (SS-1: -1 must NOT read as success).
    gint n = secret_service_unlock_sync(service, to_unlock,
                                        watchdog->cancellable, &unlocked,
                                        &error);
    g_list_free(to_unlock);
    if (unlocked) g_list_free_full(unlocked, g_object_unref);
    op_watchdog_finish(watchdog);  // wake the timer; drop our ref

    if (n < 1) {
      g_object_unref(collection);
      g_object_unref(service);
      // Distinguish the two recoverable cases so the Dart layer can raise the
      // right typed exception (linux_oubliette._mapError):
      //   - prompt dismissed by the user (n == 0, no GError) -> auth_cancelled
      //     (AuthenticationFailedException, cancelled: true).
      //   - any other failure: a timeout (our watchdog cancelled the prompt) or
      //     a real unlock error -> keyring_locked (KeyringLockedException).
      // Both keep data intact; neither is treated as "empty".
      *err_code = (n == 0 && error == nullptr) ? "auth_cancelled"
                                               : "keyring_locked";
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
  // Match BOTH attributes: `slot` identifies the item, `fmt` scopes it to this
  // app (SECRET_SCHEMA_NONE means the schema name is not matched, so without
  // `fmt` a foreign item reusing a `slot` attribute could match). Bound the call
  // (LINUX-2): a keyring that re-locked since warmup re-prompts here, outside the
  // warmup watchdog.
  OpWatchdog* watchdog = op_watchdog_arm();
  secret_autofree gchar* value = secret_password_lookup_sync(
      &kSchema, watchdog->cancellable, &error, "slot", slot, "fmt", kFmt,
      nullptr);
  op_watchdog_finish(watchdog);
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
  // Scope the duplicate check to this app's items (slot + fmt) — see
  // handle_contains for why `fmt` is required alongside `slot`. Bound both the
  // lookup and the store (LINUX-2): either can re-prompt if the keyring relocked.
  OpWatchdog* lookup_watchdog = op_watchdog_arm();
  secret_autofree gchar* existing = secret_password_lookup_sync(
      &kSchema, lookup_watchdog->cancellable, &lookup_error, "slot", slot,
      "fmt", kFmt, nullptr);
  op_watchdog_finish(lookup_watchdog);
  if (lookup_error) {
    return error_response("secret_service_error", lookup_error->message);
  }
  if (existing != nullptr) {
    return error_response("already_exists",
                          "A value already exists for this slot.");
  }

  g_autoptr(GError) store_error = nullptr;
  OpWatchdog* store_watchdog = op_watchdog_arm();
  gboolean ok = secret_password_store_sync(
      &kSchema, SECRET_COLLECTION_DEFAULT, "Oubliette", value,
      store_watchdog->cancellable, &store_error, "slot", slot, "fmt", kFmt,
      nullptr);
  op_watchdog_finish(store_watchdog);
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
  // Match slot + fmt so a foreign item reusing a `slot` attribute is not read
  // back as ours (see handle_contains). Bound the call (LINUX-2): a relocked
  // keyring re-prompts here, outside the warmup watchdog.
  OpWatchdog* watchdog = op_watchdog_arm();
  secret_autofree gchar* value = secret_password_lookup_sync(
      &kSchema, watchdog->cancellable, &error, "slot", slot, "fmt", kFmt,
      nullptr);
  op_watchdog_finish(watchdog);
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
  // Scope the clear to this app's items (slot + fmt): without `fmt` a foreign
  // item that reused a `slot` attribute could be deleted out from under another
  // application (see handle_contains). Bound the call (LINUX-2): a relocked
  // keyring re-prompts here, outside the warmup watchdog.
  OpWatchdog* watchdog = op_watchdog_arm();
  secret_password_clear_sync(&kSchema, watchdog->cancellable, &error, "slot",
                             slot, "fmt", kFmt, nullptr);
  op_watchdog_finish(watchdog);
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
  // Bound the search (LINUX-2): SECRET_SEARCH_UNLOCK actively unlocks any matching
  // collection, so an externally created item in another locked collection — or a
  // keyring relocked since warmup — would re-prompt here with no timeout. The
  // detached watchdog cancels it; a cancellation surfaces as secret_service_error
  // (never a silent empty purge).
  OpWatchdog* search_watchdog = op_watchdog_arm();
  GList* items = secret_service_search_sync(
      service, &kSchema, attrs,
      static_cast<SecretSearchFlags>(SECRET_SEARCH_ALL | SECRET_SEARCH_UNLOCK),
      search_watchdog->cancellable, &search_error);
  op_watchdog_finish(search_watchdog);
  g_hash_table_unref(attrs);

  if (search_error) {
    g_object_unref(service);
    return error_response("secret_service_error", search_error->message);
  }

  // Best-effort: attempt EVERY matching item, then report. Purge is non-atomic
  // and idempotent — on a partial failure the caller should retry, which deletes
  // whatever remained. g_autofree frees the captured message on every path.
  g_autofree gchar* first_error = nullptr;
  int delete_failures = 0;
  for (GList* l = items; l != nullptr; l = l->next) {
    SecretItem* item = SECRET_ITEM(l->data);
    GHashTable* item_attrs = secret_item_get_attributes(item);
    // A malformed/hostile provider can expose an item whose Attributes D-Bus
    // property is missing, in which case libsecret returns nullptr here (the
    // unguarded g_hash_table_lookup/unref below would emit GLib criticals —
    // an abort under G_DEBUG=fatal-criticals). The item matched the fmt
    // search server-side, so it IS an oubliette item, but its slot — and so
    // its owning profile — cannot be verified client-side; deleting it could
    // cross-profile-wipe. Fail closed: leave it and COUNT it, so the purge
    // reports partial rather than silently leaving an item behind.
    if (item_attrs == nullptr) {
      delete_failures++;
      if (first_error == nullptr) {
        first_error =
            g_strdup("item attributes unreadable; item left in place");
      }
      continue;
    }
    const char* slot =
        static_cast<const char*>(g_hash_table_lookup(item_attrs, "slot"));
    if (slot != nullptr && g_str_has_prefix(slot, prefix)) {
      g_autoptr(GError) del_error = nullptr;
      // Bound each delete (LINUX-2): a relocked collection re-prompts per item.
      OpWatchdog* del_watchdog = op_watchdog_arm();
      secret_item_delete_sync(item, del_watchdog->cancellable, &del_error);
      op_watchdog_finish(del_watchdog);
      if (del_error) {
        delete_failures++;
        if (first_error == nullptr) first_error = g_strdup(del_error->message);
      }
    }
    g_hash_table_unref(item_attrs);
  }
  if (items) g_list_free_full(items, g_object_unref);
  g_object_unref(service);

  if (delete_failures > 0) {
    // Report the count so the caller knows the purge was partial (readable
    // ciphertext may remain) and that a retry is needed.
    g_autofree gchar* msg = g_strdup_printf(
        "%d item(s) failed to delete during purge (first: %s); purge is "
        "best-effort and idempotent — retry to remove the rest",
        delete_failures, first_error);
    return error_response("secret_service_error", msg);
  }
  return FL_METHOD_RESPONSE(fl_method_success_response_new(nullptr));
}

static void secret_service_plugin_handle_method_call(
    SecretServicePlugin* self, FlMethodCall* method_call) {
  g_autoptr(FlMethodResponse) response = nullptr;

  const gchar* method = fl_method_call_get_name(method_call);
  FlValue* args = fl_method_call_get_args(method_call);

  // A call with no arguments yields a NULL FlValue (not an FL_VALUE_TYPE_NULL
  // value); fl_value_get_type asserts (g_return_val_if_fail) on NULL, which
  // would abort the host process. Reject it as bad_args before touching it.
  if (args == nullptr || fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
    response = error_response("bad_args", "Arguments are not a map.");
    fl_method_call_respond(method_call, response, nullptr);
    return;
  }

  // Extract only when the entry is actually a string: fl_value_get_string
  // asserts (g_return_val_if_fail) on a non-string FlValue, which would abort
  // the host process on a malformed call. A wrong-typed arg reads as nullptr
  // and is rejected below as a bad_args error.
  FlValue* slot_value = fl_value_lookup_string(args, "slot");
  FlValue* value_value = fl_value_lookup_string(args, "value");
  FlValue* prefix_value = fl_value_lookup_string(args, "prefix");
  const gchar* slot =
      (slot_value != nullptr &&
       fl_value_get_type(slot_value) == FL_VALUE_TYPE_STRING)
          ? fl_value_get_string(slot_value)
          : nullptr;
  const gchar* value =
      (value_value != nullptr &&
       fl_value_get_type(value_value) == FL_VALUE_TYPE_STRING)
          ? fl_value_get_string(value_value)
          : nullptr;
  const gchar* prefix =
      (prefix_value != nullptr &&
       fl_value_get_type(prefix_value) == FL_VALUE_TYPE_STRING)
          ? fl_value_get_string(prefix_value)
          : nullptr;

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
    // Reject an empty prefix: g_str_has_prefix(slot, "") is always true, so an
    // empty prefix would purge EVERY oubliette item across all profiles. The
    // Dart layer always passes `profilePrefix + U+001D` (never empty); this is
    // a defensive backstop so a malformed call cannot cross-profile-wipe.
    if (!prefix || prefix[0] == '\0')
      response = error_response("bad_args", "Missing or empty prefix.");
    else
      response = handle_delete_by_prefix(prefix);
  } else {
    response = FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
  }

  fl_method_call_respond(method_call, response, nullptr);
}

static void secret_service_plugin_dispose(GObject* object) {
  G_OBJECT_CLASS(secret_service_plugin_parent_class)->dispose(object);
}

static void secret_service_plugin_class_init(SecretServicePluginClass* klass) {
  G_OBJECT_CLASS(klass)->dispose = secret_service_plugin_dispose;
}

static void secret_service_plugin_init(SecretServicePlugin* self) {}

static void method_call_cb(FlMethodChannel* channel, FlMethodCall* method_call,
                           gpointer user_data) {
  SecretServicePlugin* plugin = SECRET_SERVICE_PLUGIN(user_data);
  secret_service_plugin_handle_method_call(plugin, method_call);
}

void secret_service_plugin_register_with_registrar(
    FlPluginRegistrar* registrar) {
  SecretServicePlugin* plugin = SECRET_SERVICE_PLUGIN(
      g_object_new(secret_service_plugin_get_type(), nullptr));

  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
  g_autoptr(FlMethodChannel) channel = fl_method_channel_new(
      fl_plugin_registrar_get_messenger(registrar), "secret_service",
      FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(
      channel, method_call_cb, g_object_ref(plugin), g_object_unref);

  g_object_unref(plugin);
}
