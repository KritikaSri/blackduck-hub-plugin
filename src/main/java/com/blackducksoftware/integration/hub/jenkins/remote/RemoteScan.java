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
package com.blackducksoftware.integration.hub.jenkins.remote;

import java.io.File;
import java.util.List;

import org.jenkinsci.remoting.Role;
import org.jenkinsci.remoting.RoleChecker;

import com.blackducksoftware.integration.hub.builder.HubScanConfigBuilder;
import com.blackducksoftware.integration.hub.certificate.HubCertificateHandler;
import com.blackducksoftware.integration.hub.dataservice.cli.CLIDataService;
import com.blackducksoftware.integration.hub.exception.HubIntegrationException;
import com.blackducksoftware.integration.hub.global.HubServerConfig;
import com.blackducksoftware.integration.hub.jenkins.helper.BuildHelper;
import com.blackducksoftware.integration.hub.model.request.ProjectRequest;
import com.blackducksoftware.integration.hub.model.view.ProjectVersionView;
import com.blackducksoftware.integration.hub.request.builder.ProjectRequestBuilder;
import com.blackducksoftware.integration.hub.scan.HubScanConfig;
import com.blackducksoftware.integration.hub.service.HubServicesFactory;
import com.blackducksoftware.integration.log.IntLogger;
import com.blackducksoftware.integration.phonehome.enums.ThirdPartyName;

import hudson.EnvVars;
import hudson.remoting.Callable;

public class RemoteScan implements Callable<String, HubIntegrationException> {
    private final IntLogger logger;

    private final String codeLocationName;

    private final String hubProjectName;

    private final String hubProjectVersion;

    private final String phase;

    private final String distribution;

    private final int scanMemory;

    private final boolean projectLevelAdjustments;

    private final String workingDirectoryPath;

    private final List<String> scanTargetPaths;

    private final boolean dryRun;

    private final boolean cleanupOnSuccessfulScan;

    private final String toolsDirectory;

    private final String thirdPartyVersion;

    private final String pluginVersion;

    private final HubServerConfig hubServerConfig;

    private final boolean performWorkspaceCheck;

    private final String[] excludePatterns;

    private final EnvVars envVars;

    private final boolean unmapPreviousCodeLocations;

    private final boolean deletePreviousCodeLocations;

    private final boolean shouldWaitForScansFinished;

    public RemoteScan(final IntLogger logger, final String codeLocationName, final String hubProjectName, final String hubProjectVersion, final String phase, final String distribution, final int scanMemory,
            final boolean projectLevelAdjustments, final String workingDirectoryPath, final List<String> scanTargetPaths, final boolean dryRun, final boolean cleanupOnSuccessfulScan, final String toolsDirectory,
            final String thirdPartyVersion, final String pluginVersion, final HubServerConfig hubServerConfig, final boolean performWorkspaceCheck, final String[] excludePatterns, final EnvVars envVars,
            final boolean unmapPreviousCodeLocations, final boolean deletePreviousCodeLocations, final boolean shouldWaitForScansFinished) {
        this.logger = logger;
        this.codeLocationName = codeLocationName;
        this.hubProjectName = hubProjectName;
        this.hubProjectVersion = hubProjectVersion;
        this.phase = phase;
        this.distribution = distribution;
        this.scanMemory = scanMemory;
        this.projectLevelAdjustments = projectLevelAdjustments;
        this.workingDirectoryPath = workingDirectoryPath;
        this.scanTargetPaths = scanTargetPaths;
        this.dryRun = dryRun;
        this.cleanupOnSuccessfulScan = cleanupOnSuccessfulScan;
        this.toolsDirectory = toolsDirectory;
        this.thirdPartyVersion = thirdPartyVersion;
        this.pluginVersion = pluginVersion;
        this.hubServerConfig = hubServerConfig;
        this.performWorkspaceCheck = performWorkspaceCheck;
        this.excludePatterns = excludePatterns;
        this.envVars = envVars;
        this.unmapPreviousCodeLocations = unmapPreviousCodeLocations;
        this.deletePreviousCodeLocations = deletePreviousCodeLocations;
        this.shouldWaitForScansFinished = shouldWaitForScansFinished;
    }

    @Override
    public String call() throws HubIntegrationException {
        try {
            final HubCertificateHandler certificateHandler = new HubCertificateHandler(logger);
            certificateHandler.importHttpsCertificateForHubServer(hubServerConfig.getHubUrl(), hubServerConfig.getTimeout());
            final HubServicesFactory services = BuildHelper.getHubServicesFactory(logger, hubServerConfig);

            services.addEnvironmentVariables(envVars);
            final CLIDataService cliDataService = services.createCLIDataService(logger, hubServerConfig.getTimeout() * 60 * 1000);

            final File workingDirectory = new File(workingDirectoryPath);
            final File toolsDir = new File(toolsDirectory);

            final HubScanConfigBuilder hubScanConfigBuilder = new HubScanConfigBuilder();
            hubScanConfigBuilder.setDryRun(dryRun);
            hubScanConfigBuilder.setWorkingDirectory(workingDirectory);
            hubScanConfigBuilder.setScanMemory(scanMemory);
            hubScanConfigBuilder.addAllScanTargetPaths(scanTargetPaths);
            hubScanConfigBuilder.setToolsDir(toolsDir);
            if (performWorkspaceCheck) {
                hubScanConfigBuilder.enableScanTargetPathsWithinWorkingDirectoryCheck();
            }
            hubScanConfigBuilder.setCleanupLogsOnSuccess(cleanupOnSuccessfulScan);
            hubScanConfigBuilder.setExcludePatterns(excludePatterns);
            hubScanConfigBuilder.setCodeLocationAlias(codeLocationName);
            hubScanConfigBuilder.setUnmapPreviousCodeLocations(unmapPreviousCodeLocations);
            hubScanConfigBuilder.setDeletePreviousCodeLocations(deletePreviousCodeLocations);

            final ProjectRequestBuilder projectRequestBuilder = new ProjectRequestBuilder();
            projectRequestBuilder.setProjectName(hubProjectName);
            projectRequestBuilder.setVersionName(hubProjectVersion);
            projectRequestBuilder.setPhase(phase);
            projectRequestBuilder.setDistribution(distribution);
            projectRequestBuilder.setProjectLevelAdjustments(projectLevelAdjustments);

            final HubScanConfig hubScanConfig = hubScanConfigBuilder.build();
            final ProjectRequest projectRequest = projectRequestBuilder.build();
            final ProjectVersionView projectVersionView = cliDataService.installAndRunControlledScan(hubServerConfig, hubScanConfig, projectRequest, shouldWaitForScansFinished, ThirdPartyName.JENKINS.getName(), thirdPartyVersion,
                    pluginVersion);
            return dryRun ? null : projectVersionView.json;
        } catch (final Exception e) {
            throw new HubIntegrationException(e.getMessage(), e);
        }
    }

    @Override
    public void checkRoles(final RoleChecker checker) throws SecurityException {
        checker.check(this, new Role(RemoteScan.class));
    }
}
