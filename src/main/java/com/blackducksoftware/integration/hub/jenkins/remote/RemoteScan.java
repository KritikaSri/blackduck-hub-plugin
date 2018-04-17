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
import java.io.IOException;
import java.util.List;

import org.jenkinsci.remoting.Role;
import org.jenkinsci.remoting.RoleChecker;

import com.blackducksoftware.integration.hub.api.generated.component.ProjectRequest;
import com.blackducksoftware.integration.hub.configuration.HubScanConfig;
import com.blackducksoftware.integration.hub.configuration.HubScanConfigBuilder;
import com.blackducksoftware.integration.hub.configuration.HubServerConfig;
import com.blackducksoftware.integration.hub.jenkins.helper.BuildHelper;
import com.blackducksoftware.integration.hub.service.HubServicesFactory;
import com.blackducksoftware.integration.hub.service.SignatureScannerService;
import com.blackducksoftware.integration.hub.service.model.ProjectRequestBuilder;
import com.blackducksoftware.integration.hub.service.model.ProjectVersionWrapper;
import com.blackducksoftware.integration.log.IntLogger;

import hudson.EnvVars;
import hudson.remoting.Callable;

public class RemoteScan implements Callable<ScanResponse, IOException> {
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

    private final HubServerConfig hubServerConfig;

    private final boolean performWorkspaceCheck;

    private final String[] excludePatterns;

    private final EnvVars envVars;

    private final boolean unmapPreviousCodeLocations;

    private final boolean deletePreviousCodeLocations;

    private final boolean shouldWaitForScansFinished;

    public RemoteScan(final IntLogger logger, final String codeLocationName, final String hubProjectName, final String hubProjectVersion, final String phase, final String distribution, final int scanMemory,
            final boolean projectLevelAdjustments, final String workingDirectoryPath, final List<String> scanTargetPaths, final boolean dryRun, final boolean cleanupOnSuccessfulScan, final String toolsDirectory,
            final HubServerConfig hubServerConfig, final boolean performWorkspaceCheck, final String[] excludePatterns, final EnvVars envVars,
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
        this.hubServerConfig = hubServerConfig;
        this.performWorkspaceCheck = performWorkspaceCheck;
        this.excludePatterns = excludePatterns;
        this.envVars = envVars;
        this.unmapPreviousCodeLocations = unmapPreviousCodeLocations;
        this.deletePreviousCodeLocations = deletePreviousCodeLocations;
        this.shouldWaitForScansFinished = shouldWaitForScansFinished;
    }

    @Override
    public ScanResponse call() throws IOException {
        try {
            final HubServicesFactory services = BuildHelper.getHubServicesFactory(logger, hubServerConfig);

            services.addEnvironmentVariables(envVars);
            final SignatureScannerService scannerService = services.createSignatureScannerService(hubServerConfig.getTimeout() * 60 * 1000);

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
            final ProjectVersionWrapper projectVersionWrapper = scannerService.installAndRunControlledScan(hubServerConfig, hubScanConfig, projectRequest, shouldWaitForScansFinished);
            return new ScanResponse(dryRun ? null : projectVersionWrapper.getProjectVersionView().json);
        } catch (final InterruptedException e) {
            logger.error("BD remote scan thread was interrupted.");
            return new ScanResponse(e);
        } catch (final Exception e) {
            return new ScanResponse(e);
        }
    }

    @Override
    public void checkRoles(final RoleChecker checker) throws SecurityException {
        checker.check(this, new Role(RemoteScan.class));
    }
}
