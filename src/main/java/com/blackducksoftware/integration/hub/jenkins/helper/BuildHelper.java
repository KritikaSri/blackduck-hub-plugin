/*******************************************************************************
 * Copyright (C) 2016 Black Duck Software, Inc.
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
 *******************************************************************************/
package com.blackducksoftware.integration.hub.jenkins.helper;

import java.net.MalformedURLException;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import com.blackducksoftware.integration.exception.EncryptionException;
import com.blackducksoftware.integration.hub.configuration.HubServerConfig;
import com.blackducksoftware.integration.hub.configuration.HubServerConfigBuilder;
import com.blackducksoftware.integration.hub.jenkins.exceptions.BDJenkinsHubPluginException;
import com.blackducksoftware.integration.hub.rest.RestConnection;
import com.blackducksoftware.integration.hub.service.HubServicesFactory;
import com.blackducksoftware.integration.log.IntLogger;
import com.blackducksoftware.integration.log.LogLevel;
import com.blackducksoftware.integration.log.PrintStreamIntLogger;

import hudson.ProxyConfiguration;
import hudson.Util;
import hudson.model.AbstractBuild;
import hudson.model.Result;
import jenkins.model.Jenkins;

public class BuildHelper {
    public static boolean isSuccess(final AbstractBuild<?, ?> build) {
        return build.getResult() == Result.SUCCESS;
    }

    public static boolean isOngoing(final AbstractBuild<?, ?> build) {
        return build.getResult() == null;
    }

    public static HubServicesFactory getHubServicesFactory(final String serverUrl, final String username, final String password, final int hubTimeout) throws EncryptionException, MalformedURLException {

        return getHubServicesFactory(null, serverUrl, username, password, hubTimeout);
    }

    public static HubServicesFactory getHubServicesFactory(final IntLogger logger, final String serverUrl, final String username, final String password, final int hubTimeout) throws EncryptionException, MalformedURLException {
        return getHubServicesFactory(logger, serverUrl, username, password, hubTimeout, false);
    }

    public static HubServicesFactory getHubServicesFactory(IntLogger logger, final String serverUrl, final String username, final String password, final int hubTimeout, final boolean shouldTrustSSLCertificates)
            throws EncryptionException, MalformedURLException {
        if (logger == null) {
            logger = new PrintStreamIntLogger(System.out, LogLevel.INFO);
        }
        final HubServicesFactory service = new HubServicesFactory(getRestConnection(logger, serverUrl, username, password, Integer.toString(hubTimeout), shouldTrustSSLCertificates));
        return service;
    }

    public static HubServicesFactory getHubServicesFactory(final IntLogger logger, final HubServerConfig hubServerConfig) throws EncryptionException, IllegalArgumentException {
        final HubServicesFactory service = new HubServicesFactory(getRestConnection(logger, hubServerConfig));
        return service;
    }

    public static RestConnection getRestConnection(final IntLogger logger, final HubServerConfig hubServerConfig) throws EncryptionException, IllegalArgumentException {
        return hubServerConfig.createCredentialsRestConnection(logger);
    }

    public static RestConnection getRestConnection(final IntLogger logger, final String serverUrl, final String username, final String password, final String hubTimeout, final boolean autoImportHttpsCertificates)
            throws EncryptionException, MalformedURLException {
        final HubServerConfigBuilder hubServerConfigBuilder = new HubServerConfigBuilder();
        hubServerConfigBuilder.setHubUrl(serverUrl);
        hubServerConfigBuilder.setUsername(username);
        hubServerConfigBuilder.setPassword(password);
        hubServerConfigBuilder.setTimeout(hubTimeout);
        hubServerConfigBuilder.setAlwaysTrustServerCertificate(autoImportHttpsCertificates);

        return getRestConnection(logger, serverUrl, hubServerConfigBuilder);
    }

    public static RestConnection getRestConnection(final IntLogger logger, final String serverUrl, final String username, final String password, final int hubTimeout) throws EncryptionException, MalformedURLException {
        final HubServerConfigBuilder hubServerConfigBuilder = new HubServerConfigBuilder();
        hubServerConfigBuilder.setHubUrl(serverUrl);
        hubServerConfigBuilder.setUsername(username);
        hubServerConfigBuilder.setPassword(password);
        hubServerConfigBuilder.setTimeout(hubTimeout);

        return getRestConnection(logger, serverUrl, hubServerConfigBuilder);
    }

    private static RestConnection getRestConnection(final IntLogger logger, final String serverUrl, final HubServerConfigBuilder hubServerConfigBuilder) throws EncryptionException, MalformedURLException {
        final Jenkins jenkins = Jenkins.getInstance();
        String proxyHost = null;
        Integer proxyPort = null;
        String proxyUser = null;
        String proxyPassword = null;
        if (jenkins != null) {
            final ProxyConfiguration proxyConfig = jenkins.proxy;
            if (proxyConfig != null) {
                if (JenkinsProxyHelper.shouldUseProxy(serverUrl, proxyConfig.noProxyHost)) {
                    proxyHost = proxyConfig.name;
                    proxyPort = proxyConfig.port;
                    proxyUser = jenkins.proxy.getUserName();
                    proxyPassword = jenkins.proxy.getPassword();
                }
            }
        }

        return getRestConnection(logger, hubServerConfigBuilder, proxyHost, proxyPort, proxyUser, proxyPassword);
    }

    public static RestConnection getRestConnection(final IntLogger logger, final HubServerConfigBuilder hubServerConfigBuilder, final String proxyHost, final Integer proxyPort, final String proxyUser, final String proxyPassword)
            throws EncryptionException {
        if (StringUtils.isNotBlank(proxyHost) && proxyPort != null) {
            hubServerConfigBuilder.setProxyHost(proxyHost);
            hubServerConfigBuilder.setProxyPort(proxyPort);

            if (StringUtils.isNotBlank(proxyUser) && StringUtils.isNotBlank(proxyPassword)) {
                hubServerConfigBuilder.setProxyUsername(proxyUser);
                hubServerConfigBuilder.setProxyPassword(proxyPassword);
            }
        }

        final HubServerConfig hubServerConfig = hubServerConfigBuilder.build();
        return hubServerConfig.createCredentialsRestConnection(logger);
    }

    public static String handleVariableReplacement(final Map<String, String> variables, final String value) throws BDJenkinsHubPluginException {
        if (value != null) {

            final String newValue = Util.replaceMacro(value, variables);

            if (newValue.contains("$")) {
                throw new BDJenkinsHubPluginException("Variable was not properly replaced. Value : " + value + ", Result : " + newValue + ". Make sure the variable has been properly defined.");
            }
            return newValue;
        } else {
            return null;
        }
    }

}
