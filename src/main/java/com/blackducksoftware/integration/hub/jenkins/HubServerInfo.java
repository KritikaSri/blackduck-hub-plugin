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
package com.blackducksoftware.integration.hub.jenkins;

import java.util.Collections;
import java.util.List;

import org.apache.commons.lang.StringUtils;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import com.cloudbees.plugins.credentials.matchers.IdMatcher;

import hudson.model.AbstractProject;
import hudson.security.ACL;

public class HubServerInfo {

    private String serverUrl;

    private String hubCredentialsId;

    private UsernamePasswordCredentialsImpl credential;

    private int timeout;

    private boolean performWorkspaceCheck;

    public HubServerInfo() {
    }

    public HubServerInfo(final String serverUrl, final String hubCredentialsId, final int timeout, final boolean performWorkspaceCheck) {
        this.serverUrl = serverUrl;
        this.hubCredentialsId = hubCredentialsId;
        this.timeout = timeout;
        this.performWorkspaceCheck = performWorkspaceCheck;
    }

    public static int getDefaultTimeout() {
        return 120;
    }

    public int getTimeout() {
        if (timeout == 0) {
            return getDefaultTimeout();
        }
        return timeout;
    }

    public void setTimeout(final int timeout) {
        this.timeout = timeout;
    }

    public String getServerUrl() {
        return serverUrl;
    }

    public void setServerUrl(final String serverUrl) {
        this.serverUrl = serverUrl;
    }

    public String getCredentialsId() {
        return hubCredentialsId;
    }

    public void setCredentialsId(final String hubCredentialsId) {
        this.hubCredentialsId = hubCredentialsId;
    }

    public boolean isPluginConfigured() {
        return StringUtils.isNotBlank(getServerUrl()) && StringUtils.isNotBlank(getCredentialsId());
    }

    public String getUsername() {
        final UsernamePasswordCredentialsImpl creds = getCredential();
        if (creds == null) {
            return null;
        } else {
            return creds.getUsername();
        }
    }

    public String getPassword() {
        final UsernamePasswordCredentialsImpl creds = getCredential();
        if (creds == null) {
            return null;
        } else {
            return creds.getPassword().getPlainText();
        }

    }

    public UsernamePasswordCredentialsImpl getCredential() {
        // Only need to look up the credential when you first run a build or if the credential that the user wants to
        // use has changed.
        if (credential == null || !credential.getId().equals(hubCredentialsId)) {
            final AbstractProject<?, ?> project = null;
            final List<StandardUsernamePasswordCredentials> credentials = CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class,
                    project, ACL.SYSTEM,
                    Collections.<DomainRequirement> emptyList());
            final IdMatcher matcher = new IdMatcher(hubCredentialsId);
            for (final StandardCredentials c : credentials) {
                if (matcher.matches(c) && c instanceof UsernamePasswordCredentialsImpl) {
                    credential = (UsernamePasswordCredentialsImpl) c;
                }
            }
        }
        return credential;
    }

    public boolean isPerformWorkspaceCheck() {
        return performWorkspaceCheck;
    }

    public void setPerformWorkspaceCheck(boolean performWorkspaceCheck) {
        this.performWorkspaceCheck = performWorkspaceCheck;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("HubServerInfo [serverUrl=");
        builder.append(serverUrl);
        builder.append(", hubCredentialsId=");
        builder.append(hubCredentialsId);
        builder.append(", credential=");
        builder.append(credential);
        builder.append(", timeout=");
        builder.append(timeout);
        builder.append(", performWorkspaceCheck=");
        builder.append(performWorkspaceCheck);
        builder.append("]");
        return builder.toString();
    }

}
