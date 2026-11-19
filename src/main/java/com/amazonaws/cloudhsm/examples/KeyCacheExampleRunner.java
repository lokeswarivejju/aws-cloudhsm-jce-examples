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
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;

/**
 * KeyCacheExampleRunner demonstrates how to look keys up once and reuse the key objects, instead
 * of calling KeyStore.getKey() on every request.
 *
 * <p>Why cache: a key lookup queries every HSM in the cluster, which is expensive. Looking a key up
 * once and reusing the key object avoids that cost on every request. See
 * https://docs.aws.amazon.com/cloudhsm/latest/userguide/bp-application-integration.html#bp-manage-application
 *
 * <p>It also helps with the key availability check (on by default): a key object looked up while all
 * HSMs are reachable can keep being used if an HSM is temporarily unavailable, for example during an
 * HSM replacement, while a new lookup at that time may fail the check. See
 * https://docs.aws.amazon.com/cloudhsm/latest/userguide/troubleshoot-key-availability-check.html
 */
public class KeyCacheExampleRunner {

    // Number of HMAC operations the example runs with the cached key.
    private static final int OPERATIONS = 100;

    /**
     * A thread-safe cache of key objects. Each key is looked up once, even if many threads ask for it
     * at the same time, and failed lookups are not cached. There is no expiry, because an expired
     * entry only forces another lookup.
     */
    public static class KeyCache {
        private final KeyStore keyStore;
        private final Map<String, Key> keys = new ConcurrentHashMap<>();
        private final AtomicInteger lookups = new AtomicInteger();

        public KeyCache(final KeyStore keyStore) {
            this.keyStore = keyStore;
        }

        /** Returns the cached key. The HSM is only queried the first time a label is used. */
        public Key get(final String label) {
            return keys.computeIfAbsent(
                    label,
                    l -> {
                        try {
                            lookups.incrementAndGet();
                            // CloudHSM does not use a key password, so it is always null.
                            final Key key = keyStore.getKey(l, null);
                            if (key == null) {
                                throw new IllegalStateException("Key not found: " + l);
                            }
                            return key;
                        } catch (final GeneralSecurityException e) {
                            throw new IllegalStateException("Key lookup failed: " + l, e);
                        }
                    });
        }

        /** Number of lookups that were sent to the HSM. */
        public int getLookupCount() {
            return lookups.get();
        }
    }

    /** Signs a message with an HMAC key. */
    public static byte[] hmac(final Key key, final byte[] message) throws Exception {
        final Mac mac = Mac.getInstance("HmacSHA256", CloudHsmProvider.PROVIDER_NAME);
        mac.init(key);
        mac.update(message);
        return mac.doFinal();
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

        try {
            final KeyStore keyStore = KeyStore.getInstance(CloudHsmProvider.PROVIDER_NAME);
            keyStore.load(null, null);
            final KeyCache cache = new KeyCache(keyStore);

            // Start-up: look the key up once.
            cache.get(label);

            // Requests: reuse the cached key object. No lookup reaches the HSM.
            final byte[] message = "This is a sample message".getBytes("UTF-8");
            for (int i = 0; i < OPERATIONS; i++) {
                hmac(cache.get(label), message);
            }

            System.out.println("HMAC operations: " + OPERATIONS);
            System.out.println("Key lookups sent to the HSM: " + cache.getLookupCount());
            if (cache.getLookupCount() != 1) {
                throw new AssertionError("Expected exactly one lookup, got " + cache.getLookupCount());
            }
        } finally {
            // Clean up the key created for this example.
            if (generatedKey instanceof Destroyable) {
                ((Destroyable) generatedKey).destroy();
            }
        }
    }
}
