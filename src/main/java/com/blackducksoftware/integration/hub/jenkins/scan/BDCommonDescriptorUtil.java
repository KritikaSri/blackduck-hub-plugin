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
package com.blackducksoftware.integration.hub.jenkins.scan;

import com.blackducksoftware.integration.hub.api.item.HubViewFilter;
import com.blackducksoftware.integration.hub.api.item.MetaService;
import com.blackducksoftware.integration.hub.api.project.ProjectRequestService;
import com.blackducksoftware.integration.hub.api.project.version.ProjectVersionRequestService;
import com.blackducksoftware.integration.hub.exception.DoesNotExistException;
import com.blackducksoftware.integration.hub.exception.HubIntegrationException;
import com.blackducksoftware.integration.hub.jenkins.HubServerInfo;
import com.blackducksoftware.integration.hub.jenkins.Messages;
import com.blackducksoftware.integration.hub.jenkins.PostBuildScanDescriptor;
import com.blackducksoftware.integration.hub.jenkins.failure.FailureConditionBuildStateEnum;
import com.blackducksoftware.integration.hub.jenkins.helper.BuildHelper;
import com.blackducksoftware.integration.hub.model.enumeration.ProjectVersionDistributionEnum;
import com.blackducksoftware.integration.hub.model.enumeration.ProjectVersionPhaseEnum;
import com.blackducksoftware.integration.hub.model.view.ProjectVersionView;
import com.blackducksoftware.integration.hub.model.view.ProjectView;
import com.blackducksoftware.integration.hub.scan.HubScanConfigFieldEnum;
import com.blackducksoftware.integration.hub.service.HubServicesFactory;
import com.blackducksoftware.integration.hub.validator.HubScanConfigValidator;
import com.blackducksoftware.integration.validator.ValidationResults;
import com.cloudbees.plugins.credentials.CredentialsMatcher;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import hudson.model.AbstractProject;
import hudson.model.AutoCompletionCandidates;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import org.apache.commons.lang.StringUtils;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class BDCommonDescriptorUtil {

    public static ListBoxModel doFillBuildStateOnFailureItems() {
        final ListBoxModel items = new ListBoxModel();
        for (final FailureConditionBuildStateEnum buildState : FailureConditionBuildStateEnum.values()) {
            items.add(buildState.getDisplayValue(), buildState.name());
        }
        return items;
    }

    /**
     * Fills the Credential drop down list in the global config
     */
    public static ListBoxModel doFillCredentialsIdItems() {

        ListBoxModel boxModel = null;
        final ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
        boolean changed = false;
        try {
            if (PostBuildScanDescriptor.class.getClassLoader() != originalClassLoader) {
                changed = true;
                Thread.currentThread().setContextClassLoader(PostBuildScanDescriptor.class.getClassLoader());
            }
            // Code copied from https://github.com/jenkinsci/git-plugin/blob/f6d42c4e7edb102d3330af5ca66a7f5809d1a48e/src/main/java/hudson/plugins/git/UserRemoteConfig.java
            final CredentialsMatcher credentialsMatcher = CredentialsMatchers.anyOf(CredentialsMatchers.instanceOf(StandardUsernamePasswordCredentials.class));
            // Dont want to limit the search to a particular project for the drop down menu
            final AbstractProject<?, ?> project = null;
            boxModel = new StandardListBoxModel().withEmptySelection().withMatching(credentialsMatcher, CredentialsProvider.lookupCredentials(StandardCredentials.class, project, ACL.SYSTEM, Collections.<DomainRequirement>emptyList()));
        } finally {
            if (changed) {
                Thread.currentThread().setContextClassLoader(originalClassLoader);
            }
        }
        return boxModel;
    }

    /**
     * Fills the drop down list of possible Version phases
     * @return
     */
    public static ListBoxModel doFillHubVersionPhaseItems() {
        final ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
        final boolean changed = false;
        final ListBoxModel items = new ListBoxModel();
        try {
            items.add("In Planning", ProjectVersionPhaseEnum.PLANNING.toString());
            items.add("In Development", ProjectVersionPhaseEnum.DEVELOPMENT.toString());
            items.add("Released", ProjectVersionPhaseEnum.RELEASED.toString());
            items.add("Deprecated", ProjectVersionPhaseEnum.DEPRECATED.toString());
            items.add("Archived", ProjectVersionPhaseEnum.ARCHIVED.toString());
        } catch (final Exception e) {
            e.printStackTrace();
            System.err.println(e.getMessage());
        } finally {
            if (changed) {
                Thread.currentThread().setContextClassLoader(originalClassLoader);
            }
        }
        return items;
    }

    /**
     * Fills the drop down list of possible Version distribution types
     * @return
     */
    public static ListBoxModel doFillHubVersionDistItems() {
        final ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
        final boolean changed = false;
        final ListBoxModel items = new ListBoxModel();
        try {
            items.add("External", ProjectVersionDistributionEnum.EXTERNAL.toString());
            items.add("SaaS", ProjectVersionDistributionEnum.SAAS.toString());
            items.add("Internal", ProjectVersionDistributionEnum.INTERNAL.toString());
            items.add("Open Source", ProjectVersionDistributionEnum.OPENSOURCE.toString());
        } catch (final Exception e) {
            e.printStackTrace();
            System.err.println(e.getMessage());
        } finally {
            if (changed) {
                Thread.currentThread().setContextClassLoader(originalClassLoader);
            }
        }
        return items;
    }

    public static AutoCompletionCandidates doAutoCompleteHubProjectName(final HubServerInfo serverInfo, final String hubProjectName) throws IOException, ServletException {
        final AutoCompletionCandidates potentialMatches = new AutoCompletionCandidates();
        if (StringUtils.isNotBlank(serverInfo.getServerUrl()) && StringUtils.isNotBlank(serverInfo.getCredentialsId())) {
            final ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
            final boolean changed = false;
            try {
                if (hubProjectName.contains("$")) {
                    return potentialMatches;
                }

                final HubServicesFactory service = BuildHelper.getHubServicesFactory(null, serverInfo.getServerUrl(), serverInfo.getUsername(), serverInfo.getPassword(), serverInfo.getTimeout(), serverInfo.shouldTrustSSLCerts());
                final MetaService metaService = service.createMetaService();
                final ProjectRequestService projectService = service.createProjectRequestService();

                final List<ProjectView> suggestions = projectService.getAllProjectMatches(hubProjectName);

                final HubViewFilter<ProjectView> filter = new HubViewFilter<>();
                final List<ProjectView> accessibleSuggestions = filter.getAccessibleItems(metaService, suggestions);

                if (!accessibleSuggestions.isEmpty()) {
                    for (final ProjectView projectSuggestion : accessibleSuggestions) {
                        potentialMatches.add(projectSuggestion.name);
                    }
                }
            } catch (final Exception e) {
                // do nothing for exception, there is nowhere in the UI to display this error
            } finally {
                if (changed) {
                    Thread.currentThread().setContextClassLoader(originalClassLoader);
                }
            }

        }
        return potentialMatches;
    }

    public static FormValidation doCheckHubProjectName(final HubServerInfo serverInfo, final String hubProjectName, final String hubProjectVersion, final boolean dryRun) throws IOException, ServletException {
        // Query for the project version so hopefully the check methods run for both fields when the User changes the Name of the project
        if (StringUtils.isNotBlank(hubProjectName)) {
            final ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
            final boolean changed = false;
            try {
                if (StringUtils.isBlank(serverInfo.getServerUrl())) {
                    return FormValidation.error(Messages.HubBuildScan_getPleaseSetServerUrl());
                }
                if (StringUtils.isBlank(serverInfo.getCredentialsId())) {
                    return FormValidation.error(Messages.HubBuildScan_getCredentialsNotFound());
                }
                if (hubProjectName.contains("$")) {
                    return FormValidation.warning(Messages.HubBuildScan_getProjectNameContainsVariable());
                }

                final HubServicesFactory service = BuildHelper.getHubServicesFactory(null, serverInfo.getServerUrl(), serverInfo.getUsername(), serverInfo.getPassword(), serverInfo.getTimeout(), serverInfo.shouldTrustSSLCerts());
                final MetaService metaService = service.createMetaService();
                final ProjectRequestService projectService = service.createProjectRequestService();
                final ProjectView project = projectService.getProjectByName(hubProjectName);
                final List<ProjectView> projectList = new ArrayList<>();
                projectList.add(project);
                final HubViewFilter<ProjectView> filter = new HubViewFilter<>();
                final List<ProjectView> filteredList = filter.getAccessibleItems(metaService, projectList);
                if (filteredList.isEmpty()) {
                    return FormValidation.error(Messages.HubBuildScan_getProjectNotAccessible());
                }
                return FormValidation.ok(Messages.HubBuildScan_getProjectExistsIn_0_(serverInfo.getServerUrl()));
            } catch (final DoesNotExistException e) {
                return FormValidation.error(Messages.HubBuildScan_getProjectNonExistingIn_0_(serverInfo.getServerUrl()));
            } catch (final HubIntegrationException e) {
                final String message;
                if (e.getCause() != null) {
                    message = e.getCause().toString();
                    if (message.contains("(407)")) {
                        return FormValidation.error(e, message);
                    }
                }
                return FormValidation.error(e, e.getMessage());
            } catch (final Exception e) {
                String message;
                if (e.getCause() != null && e.getCause().getCause() != null) {
                    message = e.getCause().getCause().toString();
                } else if (e.getCause() != null) {
                    message = e.getCause().toString();
                } else {
                    message = e.toString();
                }
                if (message.toLowerCase().contains("service unavailable")) {
                    message = Messages.HubBuildScan_getCanNotReachThisServer_0_(serverInfo.getServerUrl());
                } else if (message.toLowerCase().contains("precondition failed")) {
                    message = message + ", Check your configuration.";
                }
                return FormValidation.error(e, message);
            } finally {
                if (changed) {
                    Thread.currentThread().setContextClassLoader(originalClassLoader);
                }
            }
        } else {
            return FormValidation.error(Messages.HubBuildScan_getProvideProjectName());
        }
    }

    public static FormValidation doCheckHubProjectVersion(final HubServerInfo serverInfo, final String hubProjectVersion, final String hubProjectName, final boolean dryRun) throws IOException, ServletException {
        if (StringUtils.isNotBlank(hubProjectVersion)) {
            final ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
            final boolean changed = false;
            try {
                if (StringUtils.isBlank(serverInfo.getServerUrl())) {
                    return FormValidation.error(Messages.HubBuildScan_getPleaseSetServerUrl());
                }
                if (StringUtils.isBlank(serverInfo.getCredentialsId())) {
                    return FormValidation.error(Messages.HubBuildScan_getCredentialsNotFound());
                }
                if (StringUtils.isBlank(hubProjectName)) {
                    // Error will be displayed for the project name field
                    return FormValidation.ok();
                }
                if (hubProjectVersion.contains("$")) {
                    return FormValidation.warning(Messages.HubBuildScan_getProjectVersionContainsVariable());
                }
                if (hubProjectName.contains("$")) {
                    // Warning will be displayed for the project name field
                    return FormValidation.ok();
                }

                final HubServicesFactory service = BuildHelper.getHubServicesFactory(null, serverInfo.getServerUrl(), serverInfo.getUsername(), serverInfo.getPassword(), serverInfo.getTimeout(), serverInfo.shouldTrustSSLCerts());
                final ProjectRequestService projectService = service.createProjectRequestService();
                ProjectView project = null;
                try {
                    project = projectService.getProjectByName(hubProjectName);
                } catch (final Exception e) {
                    // This error will already show up for the project name field
                    return FormValidation.ok();
                }
                final ProjectVersionRequestService projectVersionService = service.createProjectVersionRequestService();
                final List<ProjectVersionView> releases = projectVersionService.getAllProjectVersions(project);

                final StringBuilder projectVersions = new StringBuilder();
                for (final ProjectVersionView release : releases) {
                    if (release.versionName.equals(hubProjectVersion)) {
                        return FormValidation.ok(Messages.HubBuildScan_getVersionExistsIn_0_(project.name));
                    } else {
                        if (projectVersions.length() > 0) {
                            projectVersions.append(", " + release.versionName);
                        } else {
                            projectVersions.append(release.versionName);
                        }
                    }
                }
                return FormValidation.error(Messages.HubBuildScan_getVersionNonExistingIn_0_(project.name, projectVersions.toString()));
            } catch (final HubIntegrationException e) {
                final String message;
                if (e.getCause() != null) {
                    message = e.getCause().toString();
                    if (message.contains("(407)")) {
                        return FormValidation.error(e, message);
                    }
                }
                return FormValidation.error(e, e.getMessage());
            } catch (final Exception e) {
                String message;
                if (e.getCause() != null && e.getCause().getCause() != null) {
                    message = e.getCause().getCause().toString();
                } else if (e.getCause() != null) {
                    message = e.getCause().toString();
                } else {
                    message = e.toString();
                }
                if (message.toLowerCase().contains("service unavailable")) {
                    message = Messages.HubBuildScan_getCanNotReachThisServer_0_(serverInfo.getServerUrl());
                } else if (message.toLowerCase().contains("precondition failed")) {
                    message = message + ", Check your configuration.";
                }
                return FormValidation.error(e, message);
            } finally {
                if (changed) {
                    Thread.currentThread().setContextClassLoader(originalClassLoader);
                }
            }
        } else {
            return FormValidation.error(Messages.HubBuildScan_getProvideProjectVersion());
        }
    }

    public static FormValidation doCheckScanMemory(final String scanMemory) throws IOException, ServletException {
        final ValidationResults results = new ValidationResults();
        final HubScanConfigValidator validator = new HubScanConfigValidator();
        validator.setScanMemory(scanMemory);
        validator.validateScanMemory(results);

        if (!results.isSuccess()) {
            if (results.hasWarnings()) {
                return FormValidation.warning(results.getResultString(HubScanConfigFieldEnum.SCANMEMORY));
            } else if (results.hasErrors()) {
                return FormValidation.error(results.getResultString(HubScanConfigFieldEnum.SCANMEMORY));
            }
        }
        return FormValidation.ok();
    }

    public static FormValidation doCheckBomUpdateMaximumWaitTime(final String bomUpdateMaximumWaitTime) throws IOException, ServletException {
        try {
            final Integer waitTime = Integer.valueOf(bomUpdateMaximumWaitTime);
            if (waitTime <= 0) {
                return FormValidation.error("Bom wait time must be greater than 0.");
            }
        } catch (final NumberFormatException e) {
            return FormValidation.error("The String : " + bomUpdateMaximumWaitTime + " , is not an Integer.");
        }
        return FormValidation.ok();
    }
}
