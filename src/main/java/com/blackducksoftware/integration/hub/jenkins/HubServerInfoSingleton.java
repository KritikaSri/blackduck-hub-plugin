/**
 * blackduck-hub
 *
 * Copyright (C) 2018 Black Duck Software, Inc.
 * http://www.blackducksoftware.com/
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.blackducksoftware.integration.hub.jenkins;

public class HubServerInfoSingleton {

    private final static HubServerInfoSingleton _instance;

    static // static constructor
    {
        // instantiate the singleton at class loading time.
        _instance = new HubServerInfoSingleton();
    }

    private HubServerInfo _info;

    /**
     * Default constructor.
     */
    private HubServerInfoSingleton() {
        _info = null;
    }

    /**
     * Retrieve the singleton instance.
     *
     * @return The object instance that encapsulates the object with the server
     *         information.
     */
    public static HubServerInfoSingleton getInstance() {
        return _instance;
    }

    /**
     * Retrieve the Hub server information object.
     *
     * @return The object containing the server information.
     */
    public HubServerInfo getServerInfo() {
        if (_info == null) {
            _info = new HubServerInfo();
        }
        return _info;
    }

    /**
     * Replace the Hub server information object.
     *
     */
    public void setServerInfo(final HubServerInfo info) {
        _info = info;
    }

    @Override
    protected Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

}
