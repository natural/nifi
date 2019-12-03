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
package org.apache.nifi.processors.standard.pgp;

import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.processor.ProcessSession;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;


public class SerialStreamCallback implements ExtendedStreamCallback {
    private final ExtendedStreamCallback[] streams;

    public SerialStreamCallback(ExtendedStreamCallback... streams) {
        this.streams = streams;
    }

    @Override
    public void postProcess(ProcessSession session, FlowFile flowFile) {
        for (ExtendedStreamCallback stream : streams) {
            stream.postProcess(session, flowFile);
        }
    }

    /**
     * Provides a managed output stream for use. The input stream is
     * automatically opened and closed though it is ok to close the stream
     * manually - and quite important if any streams wrapping these streams open
     * resources which should be cleared.
     *
     * @param in  the stream to read bytes from
     * @param out the stream to write bytes to
     * @throws IOException if issues occur reading or writing the underlying streams
     */
    @Override
    public void process(InputStream in, OutputStream out) throws IOException {
        int count = streams.length;
        for (int i = 0; i<count; i++) {
            boolean last = i == count - 1;
            OutputStream next = last ? out : new ByteArrayOutputStream();
            ExtendedStreamCallback stream = streams[i];
            stream.process(in, next);
            if (!last) {
                in = new ByteArrayInputStream(((ByteArrayOutputStream) next).toByteArray());
            }
        }
    }
}
