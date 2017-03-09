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

import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;

import com.blackducksoftware.integration.exception.EncryptionException;
import com.blackducksoftware.integration.hub.builder.HubServerConfigBuilder;
import com.blackducksoftware.integration.hub.global.HubServerConfig;
import com.blackducksoftware.integration.hub.jenkins.exceptions.BDJenkinsHubPluginException;
import com.blackducksoftware.integration.hub.rest.CredentialsRestConnection;
import com.blackducksoftware.integration.hub.rest.RestConnection;
import com.blackducksoftware.integration.hub.service.HubServicesFactory;
import com.blackducksoftware.integration.log.IntLogger;

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

    public static HubServicesFactory getHubServicesFactory(final String serverUrl, final String username, final String password,
            final int hubTimeout) throws EncryptionException, MalformedURLException {

        return getHubServicesFactory(null, serverUrl, username, password, hubTimeout);
    }

    public static HubServicesFactory getHubServicesFactory(final IntLogger logger, final String serverUrl,
            final String username, final String password, final int hubTimeout) throws EncryptionException, MalformedURLException {

        final HubServicesFactory service = new HubServicesFactory(
                getRestConnection(logger, serverUrl, username, password, hubTimeout));

        return service;
    }

    public static HubServicesFactory getHubServicesFactory(final IntLogger logger, final HubServerConfig hubServerConfig)
            throws EncryptionException, IllegalArgumentException {
        final HubServicesFactory service = new HubServicesFactory(
                getRestConnection(logger, hubServerConfig));
        return service;
    }

    public static RestConnection getRestConnection(final IntLogger logger, final HubServerConfig hubServerConfig)
            throws EncryptionException, IllegalArgumentException {
        return getRestConnection(logger, hubServerConfig.getHubUrl().toString(), hubServerConfig.getGlobalCredentials().getUsername(),
                hubServerConfig.getGlobalCredentials().getDecryptedPassword(), hubServerConfig.getTimeout(), hubServerConfig.getProxyInfo().getHost(),
                hubServerConfig.getProxyInfo().getPort(), hubServerConfig.getProxyInfo().getUsername(),
                hubServerConfig.getProxyInfo().getDecryptedPassword());
    }

    public static RestConnection getRestConnection(final IntLogger logger, final String serverUrl,
            final String username, final String password, final String hubTimeout) throws EncryptionException, MalformedURLException {
        final HubServerConfigBuilder hubServerConfigBuilder = new HubServerConfigBuilder();
        hubServerConfigBuilder.setHubUrl(serverUrl);
        hubServerConfigBuilder.setUsername(username);
        hubServerConfigBuilder.setPassword(password);
        hubServerConfigBuilder.setTimeout(hubTimeout);

        return getRestConnection(logger, hubServerConfigBuilder);
    }

    public static RestConnection getRestConnection(final IntLogger logger, final String serverUrl,
            final String username, final String password, final int hubTimeout) throws EncryptionException, MalformedURLException {
        final HubServerConfigBuilder hubServerConfigBuilder = new HubServerConfigBuilder();
        hubServerConfigBuilder.setHubUrl(serverUrl);
        hubServerConfigBuilder.setUsername(username);
        hubServerConfigBuilder.setPassword(password);
        hubServerConfigBuilder.setTimeout(hubTimeout);

        return getRestConnection(logger, hubServerConfigBuilder);
    }

    private static RestConnection getRestConnection(final IntLogger logger, final HubServerConfigBuilder hubServerConfigBuilder)
            throws EncryptionException, MalformedURLException {
        final Jenkins jenkins = Jenkins.getInstance();
        String proxyHost = null;
        Integer proxyPort = null;
        String proxyUser = null;
        String proxyPassword = null;
        if (jenkins != null) {
            final ProxyConfiguration proxyConfig = jenkins.proxy;
            if (proxyConfig != null) {
                final URL actualUrl = new URL(hubServerConfigBuilder.getHubUrl());
                final Proxy proxy = ProxyConfiguration.createProxy(actualUrl.getHost(), proxyConfig.name,
                        proxyConfig.port, proxyConfig.noProxyHost);

                if (proxy.address() != null) {
                    final InetSocketAddress proxyAddress = (InetSocketAddress) proxy.address();
                    proxyHost = proxyAddress.getHostName();
                    proxyPort = proxyAddress.getPort();
                    proxyUser = jenkins.proxy.getUserName();
                    proxyPassword = jenkins.proxy.getPassword();
                }
            }
        }

        return getRestConnection(logger, hubServerConfigBuilder.getHubUrl(), hubServerConfigBuilder.getUsername(),
                hubServerConfigBuilder.getPassword(),
                NumberUtils.toInt(hubServerConfigBuilder.getTimeout()), proxyHost, proxyPort, proxyUser, proxyPassword);
    }

    public static RestConnection getRestConnection(final IntLogger logger, final String serverUrl,
            final String username, final String password, final int hubTimeout, final String proxyHost, final Integer proxyPort, final String proxyUser,
            final String proxyPassword) throws EncryptionException {
        final HubServerConfigBuilder hubServerConfigBuilder = new HubServerConfigBuilder();
        hubServerConfigBuilder.setHubUrl(serverUrl);
        hubServerConfigBuilder.setUsername(username);
        hubServerConfigBuilder.setPassword(password);
        hubServerConfigBuilder.setTimeout(hubTimeout);

        if (StringUtils.isNotBlank(proxyHost) && proxyPort != null) {
            hubServerConfigBuilder.setProxyHost(proxyHost);
            hubServerConfigBuilder.setProxyPort(proxyPort);

            if (StringUtils.isNotBlank(proxyUser) && StringUtils.isNotBlank(proxyPassword)) {
                hubServerConfigBuilder.setProxyUsername(proxyUser);
                hubServerConfigBuilder.setProxyPassword(proxyPassword);
            }
        }

        final HubServerConfig hubServerConfig = hubServerConfigBuilder.build();
        final RestConnection restConnection = new CredentialsRestConnection(logger, hubServerConfig.getHubUrl(),
                hubServerConfig.getGlobalCredentials().getUsername(), hubServerConfig.getGlobalCredentials().getDecryptedPassword(),
                hubServerConfig.getTimeout());
        restConnection.proxyHost = hubServerConfig.getProxyInfo().getHost();
        restConnection.proxyPort = hubServerConfig.getProxyInfo().getPort();
        restConnection.proxyNoHosts = hubServerConfig.getProxyInfo().getIgnoredProxyHosts();
        restConnection.proxyUsername = hubServerConfig.getProxyInfo().getUsername();
        restConnection.proxyPassword = hubServerConfig.getProxyInfo().getDecryptedPassword();
        return restConnection;
    }

    public static String handleVariableReplacement(final Map<String, String> variables, final String value)
            throws BDJenkinsHubPluginException {
        if (value != null) {

            final String newValue = Util.replaceMacro(value, variables);

            if (newValue.contains("$")) {
                throw new BDJenkinsHubPluginException("Variable was not properly replaced. Value : " + value
                        + ", Result : " + newValue + ". Make sure the variable has been properly defined.");
            }
            return newValue;
        } else {
            return null;
        }
    }

}
