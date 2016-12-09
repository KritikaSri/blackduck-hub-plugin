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
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import com.blackducksoftware.integration.exception.EncryptionException;
import com.blackducksoftware.integration.hub.builder.HubServerConfigBuilder;
import com.blackducksoftware.integration.hub.exception.HubIntegrationException;
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
            final int hubTimeout) throws BDJenkinsHubPluginException, HubIntegrationException, URISyntaxException,
            MalformedURLException, IllegalArgumentException, EncryptionException {

        return getHubServicesFactory(null, serverUrl, username, password, hubTimeout);
    }

    public static HubServicesFactory getHubServicesFactory(final IntLogger logger, final String serverUrl,
            final String username, final String password, final int hubTimeout)
            throws BDJenkinsHubPluginException, HubIntegrationException, URISyntaxException, MalformedURLException,
            IllegalArgumentException, EncryptionException {

        final HubServicesFactory service = new HubServicesFactory(
                getRestConnection(logger, serverUrl, username, password, hubTimeout));

        return service;
    }

    public static RestConnection getRestConnection(final IntLogger logger, final String serverUrl,
            final String username, final String password, final int hubTimeout)
            throws BDJenkinsHubPluginException, HubIntegrationException, URISyntaxException, MalformedURLException,
            IllegalArgumentException, EncryptionException {
        final HubServerConfigBuilder hubServerConfigBuilder = new HubServerConfigBuilder();
        hubServerConfigBuilder.setHubUrl(serverUrl);
        hubServerConfigBuilder.setUsername(username);
        hubServerConfigBuilder.setPassword(password);
        hubServerConfigBuilder.setTimeout(hubTimeout);

        final Jenkins jenkins = Jenkins.getInstance();
        if (jenkins != null) {
            final ProxyConfiguration proxyConfig = jenkins.proxy;
            if (proxyConfig != null) {
                final URL actualUrl = new URL(serverUrl);
                final Proxy proxy = ProxyConfiguration.createProxy(actualUrl.getHost(), proxyConfig.name,
                        proxyConfig.port, proxyConfig.noProxyHost);

                if (proxy.address() != null) {
                    final InetSocketAddress proxyAddress = (InetSocketAddress) proxy.address();
                    hubServerConfigBuilder.setProxyHost(proxyAddress.getHostName());
                    hubServerConfigBuilder.setProxyPort(proxyAddress.getPort());
                    hubServerConfigBuilder.setProxyUsername(jenkins.proxy.getUserName());
                    hubServerConfigBuilder.setProxyPassword(jenkins.proxy.getPassword());
                }
            }
        }

        HubServerConfig hubServerConfig = hubServerConfigBuilder.build();
        RestConnection restConnection = new CredentialsRestConnection(hubServerConfig);
        restConnection.setLogger(logger);
        return restConnection;
    }

    public static RestConnection getRestConnection(final IntLogger logger, final String serverUrl,
            final String username, final String password, final int hubTimeout, String proxyHost, Integer proxyPort, String proxyUser, String proxyPassword)
            throws BDJenkinsHubPluginException, HubIntegrationException, URISyntaxException, MalformedURLException,
            IllegalArgumentException, EncryptionException {
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

        HubServerConfig hubServerConfig = hubServerConfigBuilder.build();
        RestConnection restConnection = new CredentialsRestConnection(hubServerConfig);
        restConnection.setLogger(logger);
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
