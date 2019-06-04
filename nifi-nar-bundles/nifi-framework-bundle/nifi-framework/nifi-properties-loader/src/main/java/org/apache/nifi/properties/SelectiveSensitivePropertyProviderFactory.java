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
package org.apache.nifi.properties;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import org.apache.nifi.properties.sensitive.SensitivePropertyProtectionException;
import org.apache.nifi.properties.sensitive.SensitivePropertyProvider;
import org.apache.nifi.properties.sensitive.SensitivePropertyProviderFactory;
import org.apache.nifi.properties.sensitive.aes.AESSensitivePropertyProvider;
import org.apache.nifi.properties.sensitive.aws.kms.AWSKMSSensitivePropertyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class SelectiveSensitivePropertyProviderFactory implements SensitivePropertyProviderFactory {
    private static final Logger logger = LoggerFactory.getLogger(SelectiveSensitivePropertyProviderFactory.class);

    private enum ProviderType {
        AWS(AWSKMSSensitivePropertyProvider.class),
        AES(AESSensitivePropertyProvider.class);

        Class<?> type;
    
        Class<?> getType() {
            return type;
        }
        
        void setType(Class<?> type) {
            this.type = type;
        }
        
        ProviderType(Class<?> type) {
            setType(type);
        }
    }
    
    // The selector is typically the property value, which may or may
    // not contain both a scheme and a key:
    private String selector;
    
    public SelectiveSensitivePropertyProviderFactory(String selector) {
        this.selector = selector;
    }

    public SensitivePropertyProvider getProvider() throws SensitivePropertyProtectionException {
        for (ProviderType providerType : ProviderType.values()) {
            Class <?> type = providerType.getType();
            try {
                if ((boolean) type.getMethod("canHandleScheme", String.class).invoke(null, selector)) {
                    Constructor <?> ctor = type.getConstructor(String.class);
                    return (SensitivePropertyProvider) ctor.newInstance(selector);
                }
            } catch (final NoSuchMethodException exc) {
                logger.error("Exception selecting provider: " + exc);
            } catch (final IllegalAccessException | InstantiationException | InvocationTargetException exc) {
                logger.error("Exception creating provider: " + exc);                
            }
        }
        throw new SensitivePropertyProtectionException("Could not create any provider");
    }
    
    @Override
    public String toString() {
        return "SelectiveSensitivePropertyProviderFactory for selectivly creating SensitivePropertyProviders";
    }
}
