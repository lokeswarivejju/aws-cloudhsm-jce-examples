/*
 * Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.amazonaws.cloudhsm.examples;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;

/**
 * KeyCacheExampleRunner demonstrates how to look keys up once and reuse the key objects, instead
 * of calling KeyStore.getKey() on every request. This sample is for token keys, which persist in the
 * cluster and can be looked up by label.
 *
 * <p>Why cache: a key lookup queries every HSM in the cluster, which is expensive. Looking a key up
 * once and reusing the key object avoids that cost on every request. See
 * https://docs.aws.amazon.com/cloudhsm/latest/userguide/bp-application-integration.html#bp-manage-application
 *
 * <p>It also helps with the key availability check (on by default): a key object looked up while all
 * HSMs are reachable can keep being used if an HSM is temporarily unavailable, for example during an
 * HSM replacement, while a new lookup at that time may fail the check. See
 * https://docs.aws.amazon.com/cloudhsm/latest/userguide/troubleshoot-key-availability-check.html
 *
 * <p>A cached key object refers to one key in the cluster, not to a label. If that key is deleted,
 * using the cached object throws an exception, even if a new key is later created with the same label,
 * so evict it and look it up again. If the key is relabelled, the cached object keeps working but the
 * old label no longer finds it. If a new key is then created under the old label, the cache still
 * returns the old key until it is evicted, so evict a label whenever you relabel or replace its key.
 */
public class KeyCacheExampleRunner {

    // Number of HMAC operations the example runs with the cached key.
    private static final int OPERATIONS = 100;

    /**
     * A thread-safe cache of key objects. Each key is looked up once, even if many threads ask for it
     * at the same time, and failed lookups are not cached. There is no expiry, so call evict() when
     * a cached key is no longer valid, for example after its key was deleted.
     */
    public static class KeyCache {
        private final KeyStore keyStore;
        private final Map<String, Key> keys = new ConcurrentHashMap<>();
        private final AtomicInteger getKeyCalls = new AtomicInteger();

        public KeyCache(final KeyStore keyStore) {
            this.keyStore = keyStore;
        }

        /**
         * Returns the cached key, or null if no key has the label (null is not cached). KeyStore.getKey()
         * is only called the first time a label is used. Throws IllegalStateException if the lookup fails,
         * for example UnrecoverableKeyException when two keys share the label (see getCause()). Unchecked
         * CloudHSM exceptions, such as KeyUsageException, are not wrapped.
         */
        public Key get(final String label) {
            return keys.computeIfAbsent(
                    label,
                    l -> {
                        try {
                            getKeyCalls.incrementAndGet();
                            // CloudHSM does not use the key password, so null is passed.
                            return keyStore.getKey(l, null);
                        } catch (final GeneralSecurityException e) {
                            // The lambda cannot throw checked exceptions, and nothing is cached on failure.
                            throw new IllegalStateException("Key lookup failed: " + l, e);
                        }
                    });
        }

        /** Removes a key from the cache, so the next get() looks it up again. */
        public void evict(final String label) {
            keys.remove(label);
        }

        /**
         * Number of times KeyStore.getKey() was called. Each call queries every HSM. Using a cached key
         * can still start background availability checks after an HSM is added or replaced, which are
         * not counted here.
         */
        public int getKeyCallCount() {
            return getKeyCalls.get();
        }
    }

    public static void main(final String[] args) throws Exception {
        try {
            if (Security.getProvider(CloudHsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new CloudHsmProvider());
            }
        } catch (final IOException ex) {
            System.out.println(ex);
            return;
        }

        // Create persistent key to look up. In your application, the key already exists.
        final String label = "KeyCacheExample-" + UUID.randomUUID();
        final KeyAttributesMap keySpec = new KeyAttributesMap();
        keySpec.put(KeyAttribute.LABEL, label);
        keySpec.put(KeyAttribute.SIZE, 256);
        keySpec.put(KeyAttribute.TOKEN, true);
        final KeyGenerator keyGenerator =
                KeyGenerator.getInstance("HmacSHA256", CloudHsmProvider.PROVIDER_NAME);
        keyGenerator.init(keySpec);
        final SecretKey generatedKey = keyGenerator.generateKey();

        boolean keyDeleted = false;
        try {
            final KeyStore keyStore = KeyStore.getInstance(CloudHsmProvider.PROVIDER_NAME);
            keyStore.load(null, null);
            final KeyCache cache = new KeyCache(keyStore);

            // Start-up: look the key up once. get() returns null if no key has the label.
            if (cache.get(label) == null) {
                throw new IllegalStateException("Key not found: " + label);
            }

            // Requests: reuse the cached key object. No more getKey() calls.
            final String message = "This is a sample message";
            for (int i = 0; i < OPERATIONS; i++) {
                HmacUtil.hmacDigest(cache.get(label), "HmacSHA256", message);
            }

            System.out.println("HMAC operations: " + OPERATIONS);
            System.out.println("KeyStore.getKey calls: " + cache.getKeyCallCount());
            if (cache.getKeyCallCount() != 1) {
                throw new AssertionError("Expected exactly one getKey call, got " + cache.getKeyCallCount());
            }

            // Delete the key, as another process or a key rotation could. How fast a delete reaches every
            // HSM can vary, so this example prints what happens and does not assert on it.
            ((Destroyable) generatedKey).destroy();
            keyDeleted = true;
            try {
                HmacUtil.hmacDigest(cache.get(label), "HmacSHA256", message);
                System.out.println("Cached key still worked right after the key was deleted");
            } catch (final Exception e) {
                // CloudHSM throws an unchecked exception (KeyUsageException, key not found).
                System.out.println("Cached key failed after the key was deleted: " + e.getClass().getSimpleName());
            }

            // Here we know the key was deleted, so evict it and the next get() looks the label up again.
            // In an application, evict only when using the cached key fails because the key is gone (a
            // KeyUsageException with the message "Key not found"), not on every error: during an HSM outage
            // a new lookup fails the key availability check with the same exception class.
            cache.evict(label);
            try {
                System.out.println(
                        "After evict, lookup: " + (cache.get(label) == null ? "no key with this label" : "a key was found"));
            } catch (final RuntimeException e) {
                System.out.println("After evict, lookup failed: " + e.getClass().getSimpleName());
            }
        } finally {
            // Clean up the key created for this example, if it was not already deleted above.
            if (!keyDeleted && generatedKey instanceof Destroyable) {
                ((Destroyable) generatedKey).destroy();
            }
        }
    }
}
