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
// SECRET_SCHEMA_NONE (0) does NOT include SECRET_SCHEMA_DONT_MATCH_NAME, so the
// *simple* password API (secret_password_store/lookup/clear_sync) DOES inject
// and match the implicit `xdg:schema` name attribute (our schema name) — that
// is what scopes store/read/delete to this app. The *search* API
// (secret_service_search_sync), however, matches ONLY the attributes hash table
// we pass — it does NOT add the schema name. So the search-based paths
// (contains, the write dup-check, deleteByPrefix) must insert `xdg:schema`
// themselves to scope identically; otherwise a foreign item merely carrying a
// matching `fmt`/`slot` could be matched (and, for purge, deleted). `fmt` and
// `slot` remain as defence-in-depth alongside the schema-name scope.
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

// Frees a gchar* secret in place, zeroing it first (best effort).
// secret_password_free() (= egg_secure_strfree, verified against libsecret
// 0.21.7) ZEROES the bytes and then FREES the allocation — returning a pointer
// from libsecret's mlocked secure-memory pool to the pool, or plain-freeing an
// ordinary heap pointer. secret_password_wipe() (= egg_secure_strclear) only
// zeroes and NEVER frees: used as a cleanup it would leak one secure-pool
// allocation per read, eventually exhausting RLIMIT_MEMLOCK — after which
// libsecret silently falls back to ordinary *pageable* memory for every future
// secret transfer, degrading the non-pageable property process-wide (plus an
// unbounded RSS leak). This is the only place the plugin holds raw plaintext
// (the read path), so it is the one place worth wiping — and it must free too.
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
  // One GError per GLib call, never a shared/reused one. GLib's contract is that
  // a GError** must point at NULL on entry (g_return_if_fail(*error == NULL)) —
  // threading a single variable through several sequential calls is fragile: a
  // provider that (against contract) left `error` set while returning success
  // would trip a fatal g_critical on the next call. Separate autoptrs keep each
  // call's precondition trivially satisfied and each error independently owned.
  g_autoptr(GError) get_error = nullptr;
  SecretService* service = secret_service_get_sync(
      static_cast<SecretServiceFlags>(SECRET_SERVICE_OPEN_SESSION |
                                      SECRET_SERVICE_LOAD_COLLECTIONS),
      nullptr, &get_error);
  if (!service) {
    *err_code = "backend_unavailable";
    return nullptr;
  }

  g_autoptr(GError) alias_error = nullptr;
  SecretCollection* collection = secret_collection_for_alias_sync(
      service, SECRET_COLLECTION_DEFAULT, SECRET_COLLECTION_NONE, nullptr,
      &alias_error);
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
    g_autoptr(GError) unlock_error = nullptr;
    // Returns the count unlocked (>= 1 on success), 0 if the prompt was
    // dismissed (no item unlocked, no GError), or -1 on error / cancellation
    // (timeout, which sets a G_IO_ERROR_CANCELLED GError). Anything but a
    // positive count is fail-closed (SS-1: -1 must NOT read as success).
    gint n = secret_service_unlock_sync(service, to_unlock,
                                        watchdog->cancellable, &unlocked,
                                        &unlock_error);
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
      *err_code = (n == 0 && unlock_error == nullptr) ? "auth_cancelled"
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

// Maps a libsecret/D-Bus GError to a stable error code. A call cancelled by the
// per-op watchdog (the timeout fired) comes back as G_IO_ERROR_CANCELLED — that
// is operationally distinct from a hard bus/provider fault, so surface it as the
// recoverable `keyring_timeout` (the keyring did not respond in the bounded
// window, typically a pending unlock prompt with no agent). Every other GError
// is a generic `secret_service_error`. Both are recoverable on the Dart side
// (never purge); the split lets a caller back off / message differently.
static const char* error_code_for(GError* error) {
  if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
    return "keyring_timeout";
  }
  // A collection that relocked between warmup and the operation fails the call
  // with SECRET_ERROR_IS_LOCKED. Surface the distinct, recoverable
  // `keyring_locked` (→ KeyringLockedException) rather than collapsing it into
  // the generic `secret_service_error`, so a caller can prompt for unlock and
  // retry instead of treating it as an opaque backend fault. Both are
  // recoverable on the Dart side (never purge) — the split is for precision.
  if (g_error_matches(error, SECRET_ERROR, SECRET_ERROR_IS_LOCKED)) {
    return "keyring_locked";
  }
  return "secret_service_error";
}

// contains(slot) -> bool
static FlMethodResponse* handle_contains(const gchar* slot) {
  const char* code = nullptr;
  SecretService* service = warmup(&code);
  if (!service) return error_response(code, "Secret Service is not ready.");

  // Existence is an ATTRIBUTE-only question — never load (decrypt + bus-transfer)
  // the secret value just to test for a matching item. `secret_service_search_sync`
  // without SECRET_SEARCH_LOAD_SECRETS returns the matching SecretItem(s) with no
  // secret payload, so the plaintext never enters this process. (The old
  // `secret_password_lookup_sync` loaded the full secret merely to check non-NULL.)
  // Match BOTH attributes: `slot` identifies the item, `fmt` scopes it to this
  // app (SECRET_SCHEMA_NONE means the schema name is not matched, so without
  // `fmt` a foreign item reusing a `slot` attribute could match).
  GHashTable* attrs = g_hash_table_new(g_str_hash, g_str_equal);
  g_hash_table_insert(attrs, const_cast<char*>("slot"),
                      const_cast<char*>(slot));
  g_hash_table_insert(attrs, const_cast<char*>("fmt"), const_cast<char*>(kFmt));
  // Scope the search to THIS app's schema name. Unlike the simple password API,
  // secret_service_search_sync does not match xdg:schema implicitly, so add it
  // explicitly — otherwise a foreign item reusing fmt/slot could match (and, in
  // deleteByPrefix, be deleted out from under another app).
  g_hash_table_insert(attrs, const_cast<char*>("xdg:schema"),
                      const_cast<char*>(kSchema.name));

  g_autoptr(GError) error = nullptr;
  // SECRET_SEARCH_ALL only — deliberately NOT SECRET_SEARCH_UNLOCK (same
  // rationale as handle_delete_by_prefix): existence is decided entirely by
  // the ATTRIBUTES, and libsecret's search matches and returns LOCKED items
  // too — the flag only controls whether matched items are actively unlocked,
  // which matters solely for reading their secret VALUE (the read path, which
  // keeps unlock-on-access). UNLOCK here would actively unlock EVERY
  // collection holding a fmt-matching item — including one an attacker/other
  // app planted an oubliette-tagged item in — an unlock-prompt storm for a
  // question the attributes already answer. Still bounded (LINUX-2): a
  // slow/hung provider surfaces as keyring_timeout, never as "absent".
  OpWatchdog* watchdog = op_watchdog_arm();
  GList* items = secret_service_search_sync(
      service, &kSchema, attrs,
      static_cast<SecretSearchFlags>(SECRET_SEARCH_ALL),
      watchdog->cancellable, &error);
  op_watchdog_finish(watchdog);
  g_hash_table_unref(attrs);
  g_object_unref(service);

  if (error) {
    return error_response(error_code_for(error), error->message);
  }
  gboolean found = (items != nullptr);
  if (items) g_list_free_full(items, g_object_unref);
  return FL_METHOD_RESPONSE(
      fl_method_success_response_new(fl_value_new_bool(found)));
}

// write(slot, value) -> null. Fail-closed if the slot already exists.
static FlMethodResponse* handle_write(const gchar* slot, const gchar* value) {
  const char* code = nullptr;
  SecretService* service = warmup(&code);
  if (!service) return error_response(code, "Secret Service is not ready.");

  // Duplicate check is an ATTRIBUTE-only question: search (no LOAD_SECRETS) so
  // the existing item's secret value is never decrypted/transferred just to test
  // for its presence — see handle_contains. Scope to this app's items (slot +
  // fmt). Bound both the search and the store (LINUX-2): the store can re-prompt
  // if the keyring relocked, and the search can stall on a slow/hung provider.
  GHashTable* attrs = g_hash_table_new(g_str_hash, g_str_equal);
  g_hash_table_insert(attrs, const_cast<char*>("slot"),
                      const_cast<char*>(slot));
  g_hash_table_insert(attrs, const_cast<char*>("fmt"), const_cast<char*>(kFmt));
  // Scope the search to THIS app's schema name. Unlike the simple password API,
  // secret_service_search_sync does not match xdg:schema implicitly, so add it
  // explicitly — otherwise a foreign item reusing fmt/slot could match (and, in
  // deleteByPrefix, be deleted out from under another app).
  g_hash_table_insert(attrs, const_cast<char*>("xdg:schema"),
                      const_cast<char*>(kSchema.name));

  g_autoptr(GError) lookup_error = nullptr;
  // SECRET_SEARCH_ALL only — deliberately NOT SECRET_SEARCH_UNLOCK: the
  // dup-check is an existence question, and locked items match and are
  // returned without the flag (see handle_contains for the full rationale —
  // UNLOCK would let a planted item trigger an unlock-prompt storm across
  // unrelated keyrings). A duplicate in a re-locked collection is still found
  // and still fails closed as already_exists; the store below fails with the
  // recoverable keyring_locked if the default collection re-locked.
  OpWatchdog* lookup_watchdog = op_watchdog_arm();
  GList* existing = secret_service_search_sync(
      service, &kSchema, attrs,
      static_cast<SecretSearchFlags>(SECRET_SEARCH_ALL),
      lookup_watchdog->cancellable, &lookup_error);
  op_watchdog_finish(lookup_watchdog);
  g_hash_table_unref(attrs);
  if (lookup_error) {
    g_object_unref(service);
    return error_response(error_code_for(lookup_error), lookup_error->message);
  }
  if (existing != nullptr) {
    g_list_free_full(existing, g_object_unref);
    g_object_unref(service);
    return error_response("already_exists",
                          "A value already exists for this slot.");
  }
  g_object_unref(service);

  g_autoptr(GError) store_error = nullptr;
  OpWatchdog* store_watchdog = op_watchdog_arm();
  gboolean ok = secret_password_store_sync(
      &kSchema, SECRET_COLLECTION_DEFAULT, "Oubliette", value,
      store_watchdog->cancellable, &store_error, "slot", slot, "fmt", kFmt,
      nullptr);
  op_watchdog_finish(store_watchdog);
  if (store_error) {
    return error_response(error_code_for(store_error), store_error->message);
  }
  if (!ok) {
    return error_response("secret_service_error", "Store returned false.");
  }
  return FL_METHOD_RESPONSE(fl_method_success_response_new(nullptr));
}

// read(slot) -> string | null
//
// INTERNAL ONLY. Despite the name, this is not a public plain-read API: the
// oubliette layer exposes the stored value solely through `useAndForget`
// (a fetch that zeroes the plaintext after the caller's callback). There is no
// public read() — see the AGENTS.md "No read() API" invariant. Do not promote
// this method into a directly-callable public surface.
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
    return error_response(error_code_for(error), error->message);
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
    return error_response(error_code_for(error), error->message);
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
  // Scope the search to THIS app's schema name. Unlike the simple password API,
  // secret_service_search_sync does not match xdg:schema implicitly, so add it
  // explicitly — otherwise a foreign item reusing fmt/slot could match (and, in
  // deleteByPrefix, be deleted out from under another app).
  g_hash_table_insert(attrs, const_cast<char*>("xdg:schema"),
                      const_cast<char*>(kSchema.name));

  g_autoptr(GError) search_error = nullptr;
  // Enumerate with SECRET_SEARCH_ALL only — deliberately NOT SECRET_SEARCH_UNLOCK.
  // The plugin only ever stores into the default collection (warmup already
  // unlocked it), and item *attributes* (including `slot`, which decides what to
  // delete) are readable while a collection is locked. SECRET_SEARCH_UNLOCK would
  // actively unlock EVERY collection holding a fmt-matching item — including one
  // an attacker/other app planted an oubliette-tagged item in — turning a purge
  // into an unlock-prompt storm across unrelated keyrings. Dropping it confines
  // any unlock to the per-item secret_item_delete_sync below, which touches only
  // the (default) collection we own. The search is still bounded by the watchdog;
  // a cancellation surfaces as keyring_timeout (never a silent empty purge).
  OpWatchdog* search_watchdog = op_watchdog_arm();
  GList* items = secret_service_search_sync(
      service, &kSchema, attrs,
      static_cast<SecretSearchFlags>(SECRET_SEARCH_ALL),
      search_watchdog->cancellable, &search_error);
  op_watchdog_finish(search_watchdog);
  g_hash_table_unref(attrs);

  if (search_error) {
    g_object_unref(service);
    return error_response(error_code_for(search_error), search_error->message);
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

// listByPrefix(prefix) -> List<String>. The non-destructive twin of
// deleteByPrefix: enumerates this app's items and returns the `slot` attribute
// of those whose slot begins with [prefix], instead of deleting them. Ownership
// is exact because the caller passes `profilePrefix + U+001D`. Slot attributes
// are stored unencrypted (not secret); NO item value is loaded (no
// SECRET_SEARCH_LOAD_SECRETS) — this is enumeration, not the forbidden read().
static FlMethodResponse* handle_list_by_prefix(const gchar* prefix) {
  const char* code = nullptr;
  SecretService* service = warmup(&code);
  if (!service) return error_response(code, "Secret Service is not ready.");

  GHashTable* attrs = g_hash_table_new(g_str_hash, g_str_equal);
  g_hash_table_insert(attrs, const_cast<char*>("fmt"), const_cast<char*>(kFmt));
  // Scope to THIS app's schema name so a foreign item reusing fmt/slot can't be
  // listed back as ours (same rationale as handle_delete_by_prefix).
  g_hash_table_insert(attrs, const_cast<char*>("xdg:schema"),
                      const_cast<char*>(kSchema.name));

  g_autoptr(GError) search_error = nullptr;
  // SECRET_SEARCH_ALL only — deliberately NOT SECRET_SEARCH_UNLOCK (same as
  // handle_delete_by_prefix): item *attributes* (incl. `slot`) are readable
  // while a collection is locked, and UNLOCK would prompt across unrelated
  // keyrings. No SECRET_SEARCH_LOAD_SECRETS — values are never fetched. Bounded
  // by the watchdog; a cancellation surfaces as keyring_timeout.
  OpWatchdog* search_watchdog = op_watchdog_arm();
  GList* items = secret_service_search_sync(
      service, &kSchema, attrs,
      static_cast<SecretSearchFlags>(SECRET_SEARCH_ALL),
      search_watchdog->cancellable, &search_error);
  op_watchdog_finish(search_watchdog);
  g_hash_table_unref(attrs);

  if (search_error) {
    g_object_unref(service);
    return error_response(error_code_for(search_error), search_error->message);
  }

  FlValue* list = fl_value_new_list();
  for (GList* l = items; l != nullptr; l = l->next) {
    SecretItem* item = SECRET_ITEM(l->data);
    GHashTable* item_attrs = secret_item_get_attributes(item);
    // An item whose attributes are unreadable cannot have its slot verified
    // client-side; skip it (read-only enumeration — nothing to fail closed on,
    // unlike deleteByPrefix where a missing slot risks a cross-profile wipe).
    if (item_attrs == nullptr) continue;
    const char* slot =
        static_cast<const char*>(g_hash_table_lookup(item_attrs, "slot"));
    if (slot != nullptr && g_str_has_prefix(slot, prefix)) {
      fl_value_append_take(list, fl_value_new_string(slot));
    }
    g_hash_table_unref(item_attrs);
  }
  if (items) g_list_free_full(items, g_object_unref);
  g_object_unref(service);

  return FL_METHOD_RESPONSE(fl_method_success_response_new(list));
}

// ---------------------------------------------------------------------------
// Off-platform-thread execution (M-9). Every handler above runs blocking
// *_sync libsecret calls; run inline on the GTK platform thread, each
// watchdog-bounded call could freeze the whole window (no input, no redraw)
// for up to kUnlockTimeoutSeconds — and handle_write chains THREE bounded
// calls — precisely while the user is expected to interact with the unlock
// dialog the freeze hides. So the libsecret work runs on a worker thread and
// only the response is delivered back on the platform thread.
//
// Threading contract:
// - Argument parsing/validation stays on the platform thread
//   (secret_service_plugin_handle_method_call): bad_args / not_implemented
//   never touch libsecret, cannot block, and respond inline.
// - Valid operations are pushed to a single-threaded, process-global, FIFO
//   GThreadPool. ONE worker thread means operations are serialized exactly as
//   the platform thread implicitly serialized them before this refactor — the
//   Dart layer's locks are per-isolate only, so without native serialization
//   two isolates could interleave libsecret state.
// - The worker owns plain g_strdup'ed copies of the string arguments, NOT the
//   FlValue objects (FlValue refcounting is not atomic; copies remove every
//   cross-thread aliasing question). The `value` copy is secret material and
//   is wiped before free.
// - The FlMethodCall is kept alive by a g_object_ref held by the work item
//   (GObject refcounts ARE atomic). The plugin instance is deliberately NOT
//   captured: no handler reads plugin state, so plugin disposal while an
//   operation is in flight cannot use-after-free anything.
// - Responses are delivered via g_idle_add at G_PRIORITY_DEFAULT on the
//   default GMainContext — the GTK platform thread's context — because the
//   FlBinaryMessenger API is not thread-safe (DEFAULT, not DEFAULT_IDLE, so a
//   continuously-redrawing app cannot starve the reply).
//   fl_method_call_respond runs exactly once per call on every path: inline
//   for parse failures and the no-worker fallback, in the idle callback
//   otherwise — the branches are mutually exclusive by construction.
// - The OpWatchdog machinery is thread-agnostic (its own detached timer thread
//   plus a thread-safe GCancellable; no main-loop or platform-thread
//   dependency), so the handlers' timeout semantics are unchanged on the
//   worker thread. Likewise libsecret's *_sync API is documented safe to call
//   from any thread (it iterates a private GMainContext internally).
// ---------------------------------------------------------------------------

enum class SecretOp {
  kContains,
  kWrite,
  kRead,
  kDelete,
  kDeleteByPrefix,
  kListByPrefix,
};

// One queued method call. Owns copies of the string arguments and a ref on the
// FlMethodCall; `response` is produced by the worker and consumed (responded +
// unreffed) on the platform thread.
struct WorkItem {
  SecretOp op;
  gchar* slot;    // owned; nullptr when the op takes no slot
  gchar* value;   // owned; nullptr except for write; wiped before free
  gchar* prefix;  // owned; nullptr when the op takes no prefix
  FlMethodCall* call;          // owned ref
  FlMethodResponse* response;  // owned once set
};

static void work_item_free(WorkItem* item) {
  g_free(item->slot);
  if (item->value != nullptr) {
    // The write value is the caller's secret payload (base64 of the stored
    // bytes); this copy exists only to cross threads, so zero it before
    // releasing. secret_password_wipe is documented for any NUL-terminated
    // string (a plain memset) and, as an external call, cannot be elided by
    // the compiler the way a local memset-before-free can.
    secret_password_wipe(item->value);
    g_free(item->value);
  }
  g_free(item->prefix);
  g_clear_object(&item->response);
  g_object_unref(item->call);
  g_free(item);
}

// Runs the (blocking) libsecret handler for [item]. Called on the worker
// thread — or, in the degraded no-worker fallback, on the platform thread.
// Always returns a response: even an impossible op value produces an error
// rather than a dropped (never-answered) call.
static FlMethodResponse* run_secret_op(const WorkItem* item) {
  switch (item->op) {
    case SecretOp::kContains:
      return handle_contains(item->slot);
    case SecretOp::kWrite:
      return handle_write(item->slot, item->value);
    case SecretOp::kRead:
      return handle_read(item->slot);
    case SecretOp::kDelete:
      return handle_delete(item->slot);
    case SecretOp::kDeleteByPrefix:
      return handle_delete_by_prefix(item->prefix);
    case SecretOp::kListByPrefix:
      return handle_list_by_prefix(item->prefix);
  }
  return error_response("secret_service_error", "Unknown internal operation.");
}

// Platform thread (idle callback): deliver the worker's response. This is the
// only thread allowed to touch the messenger, and the FlMethodCall ref held by
// the item keeps the call (and its channel) alive until here even if the
// plugin instance was disposed while the worker ran.
static gboolean respond_on_platform_thread(gpointer data) {
  WorkItem* item = static_cast<WorkItem*>(data);
  fl_method_call_respond(item->call, item->response, nullptr);
  work_item_free(item);  // releases the response and the call ref
  return G_SOURCE_REMOVE;
}

// Worker thread: run the blocking handler, then hand the response back to the
// platform thread. The item's ownership transfers to the idle callback.
static void secret_op_worker(gpointer data, gpointer user_data) {
  WorkItem* item = static_cast<WorkItem*>(data);
  item->response = run_secret_op(item);
  g_idle_add_full(G_PRIORITY_DEFAULT, respond_on_platform_thread, item,
                  nullptr);
}

// Lazily creates the single worker. Process-global and never freed: method
// calls can arrive for as long as the process lives, and a plugin
// re-registration (engine restart) reuses the same queue, keeping the
// serialization property global rather than per-instance. Exclusive with
// max_threads = 1: the one thread is spawned HERE, so a later
// g_thread_pool_push can never need (and never fail to spawn) a thread — a
// pushed item is guaranteed to run and respond. Only ever called from the
// platform thread (the method-call callback), so the lazy init needs no lock.
// On thread-spawn failure returns nullptr (retried on the next call) and the
// caller degrades to inline execution.
static GThreadPool* secret_worker_pool() {
  static GThreadPool* pool = nullptr;
  if (pool == nullptr) {
    pool = g_thread_pool_new(secret_op_worker, nullptr, 1 /* max_threads */,
                             TRUE /* exclusive */, nullptr);
  }
  return pool;
}

// Queues [op] for the worker (copying the string arguments; nullptrs pass
// through g_strdup unchanged). Fallback: if no worker thread could be created,
// run the operation inline on the platform thread — the pre-M-9 behavior
// (frozen UI for the bounded call, but correct, fail-closed results) — rather
// than dropping the call or aborting the host app; the same degrade-not-abort
// posture as op_watchdog_arm's timer fallback.
static void dispatch_secret_op(FlMethodCall* method_call, SecretOp op,
                               const gchar* slot, const gchar* value,
                               const gchar* prefix) {
  WorkItem* item = g_new0(WorkItem, 1);
  item->op = op;
  item->slot = g_strdup(slot);
  item->value = g_strdup(value);
  item->prefix = g_strdup(prefix);
  item->call = FL_METHOD_CALL(g_object_ref(method_call));
  item->response = nullptr;

  GThreadPool* pool = secret_worker_pool();
  if (pool != nullptr) {
    g_thread_pool_push(pool, item, nullptr);
    return;
  }

  item->response = run_secret_op(item);
  fl_method_call_respond(item->call, item->response, nullptr);
  work_item_free(item);
}

// Platform thread entry point: validate, then either respond inline (argument
// errors — they never touch libsecret) or queue the operation for the worker.
// Exactly one of the two happens per call.
static void secret_service_plugin_handle_method_call(
    FlMethodCall* method_call) {
  const gchar* method = fl_method_call_get_name(method_call);
  FlValue* args = fl_method_call_get_args(method_call);

  // A call with no arguments yields a NULL FlValue (not an FL_VALUE_TYPE_NULL
  // value); fl_value_get_type asserts (g_return_val_if_fail) on NULL, which
  // would abort the host process. Reject it as bad_args before touching it.
  if (args == nullptr || fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
    g_autoptr(FlMethodResponse) response =
        error_response("bad_args", "Arguments are not a map.");
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

  // Embedded-NUL rejection is enforced in Dart (`SecretService._rejectNul`)
  // BEFORE the value crosses the channel. It cannot be re-checked here: a NUL in
  // a Dart String would make every downstream use (g_hash_table attribute,
  // secret_password_store_sync, strlen / g_str_has_prefix) silently truncate at
  // the first NUL, and the Flutter embedder exposes NO byte-length getter for a
  // string FlValue — `fl_value_get_string` already returns a NUL-terminated C
  // string (so it has truncated by the time we see it), and `fl_value_get_length`
  // is for list/map types only. So a native length-compare is impossible; the
  // Dart guard is the authoritative enforcement. As defense-in-depth, the
  // deleteByPrefix/listByPrefix paths additionally require the prefix to END in
  // the U+001D slot separator (checked via strlen below), so a NUL-truncated
  // prefix that loses its trailing separator is rejected on those paths anyway.

  // Validation failures respond inline below; a still-nullptr `response` at
  // the end of the chain means the operation was handed to the worker, which
  // responds later (never both — see the M-9 threading contract above).
  g_autoptr(FlMethodResponse) response = nullptr;

  if (strcmp(method, "contains") == 0) {
    if (!slot)
      response = error_response("bad_args", "Missing slot.");
    else
      dispatch_secret_op(method_call, SecretOp::kContains, slot, nullptr,
                         nullptr);
  } else if (strcmp(method, "write") == 0) {
    if (!slot || !value)
      response = error_response("bad_args", "Missing slot or value.");
    else
      dispatch_secret_op(method_call, SecretOp::kWrite, slot, value, nullptr);
  } else if (strcmp(method, "read") == 0) {
    if (!slot)
      response = error_response("bad_args", "Missing slot.");
    else
      dispatch_secret_op(method_call, SecretOp::kRead, slot, nullptr, nullptr);
  } else if (strcmp(method, "delete") == 0) {
    if (!slot)
      response = error_response("bad_args", "Missing slot.");
    else
      dispatch_secret_op(method_call, SecretOp::kDelete, slot, nullptr,
                         nullptr);
  } else if (strcmp(method, "deleteByPrefix") == 0) {
    // Reject an empty prefix: g_str_has_prefix(slot, "") is always true, so an
    // empty prefix would purge EVERY oubliette item across all profiles. The
    // Dart layer always passes `profilePrefix + U+001D` (never empty); this is
    // a defensive backstop so a malformed call cannot cross-profile-wipe.
    //
    // Also require the reserved slot separator (U+001D, one byte 0x1D in UTF-8)
    // as the final byte: ownership is exact ONLY because the separator's position
    // encodes the prefix length, so a prefix lacking it (e.g. "app_" instead of
    // "app_\x1d") could byte-prefix-match and cross-wipe a nested sibling
    // ("app_admin_\x1d…"). The Dart layer always appends the separator; this
    // makes the nested-prefix guard defense-in-depth rather than single-layer.
    if (!prefix || prefix[0] == '\0') {
      response = error_response("bad_args", "Missing or empty prefix.");
    } else {
      size_t prefix_len = strlen(prefix);
      if (prefix[prefix_len - 1] != '\x1d')
        response = error_response(
            "bad_args", "Prefix must end at the reserved slot separator.");
      else
        dispatch_secret_op(method_call, SecretOp::kDeleteByPrefix, nullptr,
                           nullptr, prefix);
    }
  } else if (strcmp(method, "listByPrefix") == 0) {
    // Same guards as deleteByPrefix: a non-empty, separator-terminated prefix.
    // An empty or non-separator prefix could enumerate across nested sibling
    // profiles, so reject it (the Dart layer always passes `prefix + U+001D`).
    if (!prefix || prefix[0] == '\0') {
      response = error_response("bad_args", "Missing or empty prefix.");
    } else {
      size_t prefix_len = strlen(prefix);
      if (prefix[prefix_len - 1] != '\x1d')
        response = error_response(
            "bad_args", "Prefix must end at the reserved slot separator.");
      else
        dispatch_secret_op(method_call, SecretOp::kListByPrefix, nullptr,
                           nullptr, prefix);
    }
  } else {
    response = FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
  }

  if (response != nullptr) {
    fl_method_call_respond(method_call, response, nullptr);
  }
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
  // `user_data` (the plugin ref held by the channel) is deliberately unused:
  // the handlers are stateless, and NOT threading the plugin instance into the
  // worker means plugin disposal while an operation is in flight cannot
  // use-after-free — the work item's g_object_ref on the FlMethodCall is what
  // keeps the response path alive (see the M-9 threading contract).
  secret_service_plugin_handle_method_call(method_call);
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
