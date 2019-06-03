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

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import com.amazonaws.services.kms.AWSKMSClientBuilder;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Constructor;



public class SelectiveSensitivePropertyProviderFactory implements SensitivePropertyProviderFactory {
    private static final Logger logger = LoggerFactory.getLogger(SelectiveSensitivePropertyProviderFactory.class);

    private enum ProviderType {
        AWS(AWSSensitivePropertyProvider.class),   
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
