/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.nifi.properties.sensitive;

import org.apache.commons.lang3.StringUtils;
import org.apache.nifi.properties.NiFiPropertiesLoader;
import org.apache.nifi.properties.StandardNiFiProperties;
import org.apache.nifi.util.NiFiProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;



/**
 * Decorator class for intermediate phase when {@link NiFiPropertiesLoader} loads the
 * raw properties file and performs unprotection activities before returning a clean
 * implementation of {@link NiFiProperties}, likely {@link StandardNiFiProperties}.
 * This encapsulates the sensitive property access logic from external consumers
 * of {@code NiFiProperties}.
 */
public class ProtectedNiFiProperties extends StandardNiFiProperties {
    private static final Logger logger = LoggerFactory.getLogger(ProtectedNiFiProperties.class);

    private NiFiProperties niFiProperties;

    // Additional "sensitive" property key
    public static final String ADDITIONAL_SENSITIVE_PROPERTIES_KEY = "nifi.sensitive.props.additional.keys";

    // Default list of "sensitive" property keys
    public static final List<String> DEFAULT_SENSITIVE_PROPERTIES = new ArrayList<>(asList(SECURITY_KEY_PASSWD,
            SECURITY_KEYSTORE_PASSWD, SECURITY_TRUSTSTORE_PASSWD, SENSITIVE_PROPS_KEY, PROVENANCE_REPO_ENCRYPTION_KEY));

    // Default sensitive property provider
    private SensitivePropertyProvider sensitivePropertyProvider;

    /**
     * Creates an instance containing the provided {@link NiFiProperties}.
     *
     * @param props the NiFiProperties to contain
     * @param sensitivePropertyProvider default sensitive property provider for the instance
     */
    public ProtectedNiFiProperties(NiFiProperties props, SensitivePropertyProvider sensitivePropertyProvider) {
        this.niFiProperties = props;
        this.sensitivePropertyProvider = sensitivePropertyProvider;
        logger.debug("Loaded {} properties (including {} protection schemes) into ProtectedNiFiProperties", getPropertyKeysIncludingProtectionSchemes().size(), getProtectedPropertyKeys().size());
    }

    /**
     * Creates an instance containing the provided raw {@link Properties}.
     *
     * @param rawProps the Properties to contain
     */
    public ProtectedNiFiProperties(Properties rawProps, SensitivePropertyProvider sensitivePropertyProvider) {
        this(new StandardNiFiProperties(rawProps), sensitivePropertyProvider);
    }

    /**
     * Creates an instance containing the provided {@link NiFiProperties} and key or key id.
     *
     * @param props the NiFiProperties to contain
     * @param keyOrKeyId key material or key id as needed by the specific {@link SensitivePropertyProvider} implementation
     */
    public ProtectedNiFiProperties(NiFiProperties props, String keyOrKeyId) {
        this(props, StandardSensitivePropertyProvider.fromKey(keyOrKeyId));
    }

    /**
     * Creates an instance containing the provided {@link Properties} and key or key id.
     *
     * @param rawProps the Properties to contain
     * @param keyOrKeyId key material or key id needed by the specific {@link SensitivePropertyProvider} implementation
     */
    public ProtectedNiFiProperties(Properties rawProps, String keyOrKeyId) {
        this(new StandardNiFiProperties(rawProps), keyOrKeyId);
    }

    /**
     * Retrieves the property value for the given property key.
     *
     * @param key the key of property value to lookup
     * @return value of property at given key or null if not found
     */
    @Override
    public String getProperty(String key) {
        return getInternalNiFiProperties().getProperty(key);
    }

    /**
     * Retrieves all known property keys.
     *
     * @return all known property keys
     */
    @Override
    public Set<String> getPropertyKeys() {
        Set<String> filteredKeys = getPropertyKeysIncludingProtectionSchemes();
        filteredKeys.removeIf(p -> p.endsWith(".protected"));
        return filteredKeys;
    }

    /**
     * Returns the internal representation of the {@link NiFiProperties} -- protected
     * or not as determined by the current state. No guarantee is made to the
     * protection state of these properties. If the internal reference is null, a new
     * {@link StandardNiFiProperties} instance is created.
     *
     * @return the internal properties
     */
    NiFiProperties getInternalNiFiProperties() {
        if (this.niFiProperties == null) {
            this.niFiProperties = new StandardNiFiProperties();
        }

        return this.niFiProperties;
    }

    /**
     * Returns the number of properties, excluding protection scheme properties.
     * <p>
     * Example:
     * <p>
     * key: E(value, key)
     * key.protected: aes/gcm/256
     * key2: value2
     * <p>
     * would return size 2
     *
     * @return the count of real properties
     */
    @Override
    public int size() {
        return getPropertyKeys().size();
    }

    /**
     * Returns the complete set of property keys, including any protection keys (i.e. 'x.y.z.protected').
     *
     * @return the set of property keys
     */
    Set<String> getPropertyKeysIncludingProtectionSchemes() {
        return getInternalNiFiProperties().getPropertyKeys();
    }

    /**
     * Splits a single string containing multiple property keys into a List. Delimited by ',' or ';' and ignores leading and trailing whitespace around delimiter.
     *
     * @param multipleProperties a single String containing multiple properties, i.e. "nifi.property.1; nifi.property.2, nifi.property.3"
     * @return a List containing the split and trimmed properties
     */
    private static List<String> splitMultipleProperties(String multipleProperties) {
        if (multipleProperties == null || multipleProperties.trim().isEmpty()) {
            return new ArrayList<>(0);
        } else {
            List<String> properties = new ArrayList<>(asList(multipleProperties.split("\\s*[,;]\\s*")));
            for (int i = 0; i < properties.size(); i++) {
                properties.set(i, properties.get(i).trim());
            }
            return properties;
        }
    }

    /**
     * Returns a list of the keys identifying "sensitive" properties. There is a default list,
     * and additional keys can be provided in the {@code nifi.sensitive.props.additional.keys} property in {@code nifi.properties}.
     *
     * @return the list of sensitive property keys
     */
    public List<String> getSensitivePropertyKeys() {
        String additionalPropertiesString = getProperty(ADDITIONAL_SENSITIVE_PROPERTIES_KEY);
        if (additionalPropertiesString == null || additionalPropertiesString.trim().isEmpty()) {
            return DEFAULT_SENSITIVE_PROPERTIES;
        } else {
            List<String> additionalProperties = splitMultipleProperties(additionalPropertiesString);
            /* Remove this key if it was accidentally provided as a sensitive key
             * because we cannot protect it and read from it
            */
            if (additionalProperties.contains(ADDITIONAL_SENSITIVE_PROPERTIES_KEY)) {
                logger.warn("The key '{}' contains itself. This is poor practice and should be removed", ADDITIONAL_SENSITIVE_PROPERTIES_KEY);
                additionalProperties.remove(ADDITIONAL_SENSITIVE_PROPERTIES_KEY);
            }
            additionalProperties.addAll(DEFAULT_SENSITIVE_PROPERTIES);
            return additionalProperties;
        }
    }

    /**
     * Returns a list of the keys identifying "sensitive" properties. There is a default list,
     * and additional keys can be provided in the {@code nifi.sensitive.props.additional.keys} property in {@code nifi.properties}.
     *
     * @return the list of sensitive property keys
     */
    public List<String> getPopulatedSensitivePropertyKeys() {
        List<String> allSensitiveKeys = getSensitivePropertyKeys();
        return allSensitiveKeys.stream().filter(k -> StringUtils.isNotBlank(getProperty(k))).collect(Collectors.toList());
    }

    /**
     * Returns true if any sensitive keys are protected.
     *
     * @return true if any key is protected; false otherwise
     */
    public boolean hasProtectedKeys() {
        List<String> sensitiveKeys = getSensitivePropertyKeys();
        for (String k : sensitiveKeys) {
            if (isPropertyProtected(k)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns a Map of the keys identifying "sensitive" properties that are currently protected and the "protection" key for each. This may or may not include all properties marked as sensitive.
     *
     * @return the Map of protected property keys and the protection identifier for each
     */
    public Map<String, String> getProtectedPropertyKeys() {
        List<String> sensitiveKeys = getSensitivePropertyKeys();

        // This is the Java 8 way, but can likely be optimized (and not sure of correctness)
        // Map<String, String> protectedProperties = sensitiveKeys.stream().filter(key ->
        // getProperty(getProtectionKey(key)) != null).collect(Collectors.toMap(Function.identity(), key ->
        // getProperty(getProtectionKey(key))));

        // Groovy
        // Map<String, String> groovyProtectedProperties = sensitiveKeys.collectEntries { key ->
        // [(key): getProperty(getProtectionKey(key))] }.findAll { k, v -> v }

        // Traditional way
        Map<String, String> traditionalProtectedProperties = new HashMap<>();
        for (String key : sensitiveKeys) {
            String protection = getProperty(getProtectionKey(key));
            if (StringUtils.isNotBlank(protection) && StringUtils.isNotBlank(getProperty(key))) {
                traditionalProtectedProperties.put(key, protection);
            }
        }

        return traditionalProtectedProperties;
    }

    /**
     * Returns a percentage of the total number of populated properties marked as sensitive that are currently protected.
     *
     * @return the percent of sensitive properties marked as protected
     */
    public int getPercentOfSensitivePropertiesProtected() {
        return (int) Math.round(getProtectedPropertyKeys().size() / ((double) getPopulatedSensitivePropertyKeys().size()) * 100);
    }

    /**
     * Returns true if the property identified by this key is considered sensitive in this instance of {@code NiFiProperties}.
     * Some properties are sensitive by default, while others can be specified by
     * {@link ProtectedNiFiProperties#ADDITIONAL_SENSITIVE_PROPERTIES_KEY}.
     *
     * @param key the key
     * @return true if it is sensitive
     * @see ProtectedNiFiProperties#getSensitivePropertyKeys()
     */
    public boolean isPropertySensitive(String key) {
        // If the explicit check for ADDITIONAL_SENSITIVE_PROPERTIES_KEY is not here, this will loop infinitely
        return key != null && !key.equals(ADDITIONAL_SENSITIVE_PROPERTIES_KEY) && getSensitivePropertyKeys().contains(key.trim());
    }

    /**
     * Returns true if the property identified by this key is considered protected in this instance of {@code NiFiProperties}.
     * The property value is protected if the key is sensitive and the sibling key of key.protected is present.
     *
     * @param key the key
     * @return true if it is currently marked as protected
     * @see ProtectedNiFiProperties#getSensitivePropertyKeys()
     */
    public boolean isPropertyProtected(String key) {
        return key != null && isPropertySensitive(key) && !StringUtils.isBlank(getProperty(getProtectionKey(key)));
    }

    /**
     * Returns the sibling property key which specifies the protection scheme for this key.
     * <p>
     * Example:
     * <p>
     * nifi.sensitive.key=ABCXYZ
     * nifi.sensitive.key.protected=aes/gcm/256
     * <p>
     * nifi.sensitive.key -> nifi.sensitive.key.protected
     *
     * @param key the key identifying the sensitive property
     * @return the key identifying the protection scheme for the sensitive property
     */
    public static String getProtectionKey(String key) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Cannot find protection key for null key");
        }

        return key + ".protected";
    }

    /**
     * Returns the unprotected {@link NiFiProperties} instance. If none of the properties
     * loaded are marked as protected, it will simply pass through the internal instance.
     * If any are protected, it will drop the protection scheme keys and translate each
     * protected value (encrypted, HSM-retrieved, etc.) into the raw value and store it
     * under the original key.
     * <p>
     * If any property fails to unprotect, it will save that key and continue. After
     * attempting all properties, it will throw an exception containing all failed
     * properties. This is necessary because the order is not enforced, so all failed
     * properties should be gathered together.
     *
     * @return the NiFiProperties instance with all raw values
     * @throws SensitivePropertyProtectionException if there is a problem unprotecting one or more keys
     */
    public NiFiProperties getUnprotectedProperties() throws SensitivePropertyException {
        if (hasProtectedKeys()) {
            logger.info("There are {} protected properties of {} sensitive properties ({}%)",
                    getProtectedPropertyKeys().size(),
                    getSensitivePropertyKeys().size(),
                    getPercentOfSensitivePropertiesProtected());

            Properties rawProperties = new Properties();

            Set<String> failedKeys = new HashSet<>();

            for (String key : getPropertyKeys()) {
                /* Three kinds of keys
                 * 1. protection schemes -- skip
                 * 2. protected keys -- unprotect and copy
                 * 3. normal keys -- copy over
                 */
                if (key.endsWith(".protected")) {
                    // Do nothing
                } else if (isPropertyProtected(key)) {
                    String value = getProperty(key);
                    String protectionScheme = getProperty(getProtectionKey(key));
                    SensitivePropertyProvider propertyProvider = sensitivePropertyProvider;
                    String defaultScheme = sensitivePropertyProvider.getIdentifierKey();
                    boolean sameScheme = defaultScheme.equals(protectionScheme);

                    if (!sameScheme && StandardSensitivePropertyProvider.hasProviderFor(protectionScheme)) {
                        propertyProvider = StandardSensitivePropertyProvider.fromKey(protectionScheme);
                        logger.info("Selected specific sensitive property provider: " + propertyProvider.getName() + " for property: " + key);
                    } else if (!sameScheme) {
                        throw new SensitivePropertyProtectionException("Unknown sensitive property protection scheme:" + protectionScheme);
                    }

                    try {
                        rawProperties.setProperty(key, unprotectValue(key, value, propertyProvider));
                    } catch (SensitivePropertyException e) {
                        logger.warn("Failed to unprotect '{}'", key, e);
                        failedKeys.add(key);
                    }
                } else {
                    rawProperties.setProperty(key, getProperty(key));
                }
            }

            if (!failedKeys.isEmpty()) {
                if (failedKeys.size() > 1) {
                    logger.warn("Combining {} failed keys [{}] into single exception", failedKeys.size(), StringUtils.join(failedKeys, ", "));
                    throw new MultipleSensitivePropertyProtectionException("Failed to unprotect keys", failedKeys);
                } else {
                    throw new SensitivePropertyException("Failed to unprotect key " + failedKeys.iterator().next());
                }
            }

            return new StandardNiFiProperties(rawProperties);
        } else {
            logger.debug("No protected properties");
            return getInternalNiFiProperties();
        }
    }

    @Override
    public String toString() {
        return new StringBuilder("ProtectedNiFiProperties instance with ")
                .append(size()).append(" properties (")
                .append(getProtectedPropertyKeys().size())
                .append(" protected and ")
                .append(getSensitivePropertyKeys().size())
                .append(" sensitive)")
                .toString();
    }

    /**
     * Returns a new instance of {@link NiFiProperties} with all populated sensitive values protected by the default protection scheme. Plain non-sensitive values are copied directly.
     *
     * @return the protected properties in a {@link StandardNiFiProperties} object
     * @throws IllegalStateException if no protection schemes are registered
     */
    public NiFiProperties protectPlainProperties() {
        try {
            return protectPlainProperties(StandardSensitivePropertyProvider.getDefaultProtectionScheme());
        } catch (IllegalStateException e) {
            final String msg = "Cannot protect properties with default scheme if no protection schemes are registered";
            logger.warn(msg);
            throw new IllegalStateException(msg, e);
        }
    }

    /**
     * Returns a new instance of {@link NiFiProperties} with all populated sensitive values protected by the provided protection scheme. Plain non-sensitive values are copied directly.
     *
     * @param protectionScheme the identifier key of the {@link SensitivePropertyProvider} to use
     * @return the protected properties in a {@link StandardNiFiProperties} object
     */
    NiFiProperties protectPlainProperties(String protectionScheme) {
        // Make a new holder (settable)
        Properties protectedProperties = new Properties();

        // Copy over the plain keys
        Set<String> plainKeys = getPropertyKeys();
        plainKeys.removeAll(getSensitivePropertyKeys());
        for (String key : plainKeys) {
            protectedProperties.setProperty(key, getInternalNiFiProperties().getProperty(key));
        }

        if (sensitivePropertyProvider == null) {
            return new StandardNiFiProperties(protectedProperties);
        }

        // Add the protected keys and the protection schemes
        for (String key : getSensitivePropertyKeys()) {
            final String plainValue = getInternalNiFiProperties().getProperty(key);
            if (plainValue != null && !plainValue.trim().isEmpty()) {
                final String protectedValue = sensitivePropertyProvider.protect(plainValue);
                protectedProperties.setProperty(key, protectedValue);
                protectedProperties.setProperty(getProtectionKey(key), protectionScheme);
            }
        }

        return new StandardNiFiProperties(protectedProperties);
    }

    /**
     * Returns the number of properties that are marked as protected in the provided {@link NiFiProperties} instance without requiring external creation of a {@link ProtectedNiFiProperties} instance.
     *
     * @param plainProperties the instance to count protected properties
     * @return the number of protected properties
     */
    public static int countProtectedProperties(NiFiProperties plainProperties) {
        return new ProtectedNiFiProperties(plainProperties, "").getProtectedPropertyKeys().size();
    }

    /**
     * Returns the number of properties that are marked as sensitive in the provided {@link NiFiProperties} instance without requiring external creation of a {@link ProtectedNiFiProperties} instance.
     *
     * @param plainProperties the instance to count sensitive properties
     * @return the number of sensitive properties
     */
    public static int countSensitiveProperties(NiFiProperties plainProperties, String keyOrKeyId) {
        return new ProtectedNiFiProperties(plainProperties, keyOrKeyId).getSensitivePropertyKeys().size();
    }

    /**
     * If the value is protected, unprotects it and returns it. If not, returns the original value.
     *
     * @param key            the retrieved property key
     * @param retrievedValue the retrieved property value
     * @param propertyProvider the property provider used to unprotect the value
     * @return the unprotected value
     */
    private String unprotectValue(String key, String retrievedValue, SensitivePropertyProvider propertyProvider) {
        // Checks if the key is sensitive and marked as protected
        if (!isPropertyProtected(key)) {
            return retrievedValue;
        }

        final String protectionScheme = getProperty(getProtectionKey(key));

        if (protectionScheme.equals("unknown")) {
            return retrievedValue;
        }

        // try and make one to unprotect, and if that fails...
        try {
            return propertyProvider.unprotect(retrievedValue);
        } catch (final SensitivePropertyException e) {
            throw new SensitivePropertyException("Error unprotecting value for " + key, e.getCause());
        }
    }
}
