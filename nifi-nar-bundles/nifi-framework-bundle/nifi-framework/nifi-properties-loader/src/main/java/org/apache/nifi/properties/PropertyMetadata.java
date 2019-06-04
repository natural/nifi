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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class PropertyMetadata {
    private static final Logger logger = LoggerFactory.getLogger(PropertyMetadata.class);

    private String propertyName;
    private String propertyValue;
    private String protectionScheme;

    public PropertyMetadata() {
        propertyName = propertyValue = protectionScheme = "";
    }

    public PropertyMetadata withPropertyName(String name) {
        propertyName = name;
        return this;
    }

    public PropertyMetadata withPropertyValue(String value) {
        propertyValue = value;
        return this;
    }

    public PropertyMetadata withProtectionScheme(String scheme) {
        protectionScheme = scheme;
        return this;
    }

    public String getPropertyName() {
        return propertyName;
    }

    public String getPropertyValue() {
        return propertyValue;
    }

    public String getProtectionScheme() {
        return protectionScheme;
    }
}

