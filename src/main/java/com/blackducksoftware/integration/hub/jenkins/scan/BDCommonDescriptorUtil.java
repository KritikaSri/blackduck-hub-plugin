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
package com.blackducksoftware.integration.hub.jenkins.scan;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;

import org.apache.commons.lang.StringUtils;

import com.blackducksoftware.integration.hub.api.generated.enumeration.ProjectVersionDistributionType;
import com.blackducksoftware.integration.hub.api.generated.enumeration.ProjectVersionPhaseType;
import com.blackducksoftware.integration.hub.api.generated.view.ProjectVersionView;
import com.blackducksoftware.integration.hub.api.generated.view.ProjectView;
import com.blackducksoftware.integration.hub.api.view.HubViewFilter;
import com.blackducksoftware.integration.hub.api.view.MetaHandler;
import com.blackducksoftware.integration.hub.configuration.HubScanConfigFieldEnum;
import com.blackducksoftware.integration.hub.configuration.HubScanConfigValidator;
import com.blackducksoftware.integration.hub.exception.DoesNotExistException;
import com.blackducksoftware.integration.hub.exception.HubIntegrationException;
import com.blackducksoftware.integration.hub.jenkins.HubServerInfo;
import com.blackducksoftware.integration.hub.jenkins.Messages;
import com.blackducksoftware.integration.hub.jenkins.failure.FailureConditionBuildStateEnum;
import com.blackducksoftware.integration.hub.jenkins.helper.BuildHelper;
import com.blackducksoftware.integration.hub.service.HubService;
import com.blackducksoftware.integration.hub.service.HubServicesFactory;
import com.blackducksoftware.integration.hub.service.ProjectService;
import com.blackducksoftware.integration.log.IntLogger;
import com.blackducksoftware.integration.log.LogLevel;
import com.blackducksoftware.integration.log.PrintStreamIntLogger;
import com.blackducksoftware.integration.validator.ValidationResults;

import hudson.model.AutoCompletionCandidates;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;

public class BDCommonDescriptorUtil {

    public static ListBoxModel doFillBuildStateOnFailureItems() {
        final ListBoxModel items = new ListBoxModel();
        for (final FailureConditionBuildStateEnum buildState : FailureConditionBuildStateEnum.values()) {
            items.add(buildState.getDisplayValue(), buildState.name());
        }
        return items;
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
            items.add("In Planning", ProjectVersionPhaseType.PLANNING.toString());
            items.add("In Development", ProjectVersionPhaseType.DEVELOPMENT.toString());
            items.add("Released", ProjectVersionPhaseType.RELEASED.toString());
            items.add("Deprecated", ProjectVersionPhaseType.DEPRECATED.toString());
            items.add("Archived", ProjectVersionPhaseType.ARCHIVED.toString());
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
            items.add("External", ProjectVersionDistributionType.EXTERNAL.toString());
            items.add("SaaS", ProjectVersionDistributionType.SAAS.toString());
            items.add("Internal", ProjectVersionDistributionType.INTERNAL.toString());
            items.add("Open Source", ProjectVersionDistributionType.OPENSOURCE.toString());
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

                IntLogger logger = new PrintStreamIntLogger(System.out, LogLevel.INFO);

                final HubServicesFactory service = BuildHelper.getHubServicesFactory(logger, serverInfo.getServerUrl(), serverInfo.getUsername(), serverInfo.getPassword(), serverInfo.getTimeout(), serverInfo.shouldTrustSSLCerts());

                ProjectService projectService = service.createProjectService();
                projectService.getAllProjectMatches(hubProjectName);
                final List<ProjectView> suggestions = projectService.getAllProjectMatches(hubProjectName);

                final HubViewFilter<ProjectView> filter = new HubViewFilter<>();
                final List<ProjectView> accessibleSuggestions = filter.getAccessibleItems(new MetaHandler(logger), suggestions);

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
                IntLogger logger = new PrintStreamIntLogger(System.out, LogLevel.INFO);
                final HubServicesFactory service = BuildHelper.getHubServicesFactory(logger, serverInfo.getServerUrl(), serverInfo.getUsername(), serverInfo.getPassword(), serverInfo.getTimeout(), serverInfo.shouldTrustSSLCerts());
                ProjectService projectService = service.createProjectService();
                final ProjectView project = projectService.getProjectByName(hubProjectName);
                final List<ProjectView> projectList = new ArrayList<>();
                projectList.add(project);
                final HubViewFilter<ProjectView> filter = new HubViewFilter<>();
                final List<ProjectView> filteredList = filter.getAccessibleItems(new MetaHandler(logger), projectList);
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
                IntLogger logger = new PrintStreamIntLogger(System.out, LogLevel.INFO);

                final HubServicesFactory service = BuildHelper.getHubServicesFactory(logger, serverInfo.getServerUrl(), serverInfo.getUsername(), serverInfo.getPassword(), serverInfo.getTimeout(), serverInfo.shouldTrustSSLCerts());
                HubService hubService = service.createHubService();
                ProjectService projectService = service.createProjectService();
                ProjectView project = null;
                try {
                    project = projectService.getProjectByName(hubProjectName);
                } catch (final Exception e) {
                    // This error will already show up for the project name field
                    return FormValidation.ok();
                }
                final List<ProjectVersionView> releases = hubService.getAllResponses(project, ProjectView.VERSIONS_LINK_RESPONSE);

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
