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

import com.blackducksoftware.integration.exception.EncryptionException;
import com.blackducksoftware.integration.hub.api.scan.ScanSummaryItem;
import com.blackducksoftware.integration.hub.builder.HubScanConfigBuilder;
import com.blackducksoftware.integration.hub.dataservice.cli.CLIDataService;
import com.blackducksoftware.integration.hub.exception.HubIntegrationException;
import com.blackducksoftware.integration.hub.global.HubServerConfig;
import com.blackducksoftware.integration.hub.rest.CredentialsRestConnection;
import com.blackducksoftware.integration.hub.rest.RestConnection;
import com.blackducksoftware.integration.hub.scan.HubScanConfig;
import com.blackducksoftware.integration.hub.service.HubServicesFactory;
import com.blackducksoftware.integration.log.IntLogger;
import com.blackducksoftware.integration.phone.home.enums.ThirdPartyName;

import hudson.remoting.Callable;

public class RemoteScan implements Callable<List<ScanSummaryItem>, HubIntegrationException> {
    private final IntLogger logger;

    private final String hubProjectName;

    private final String hubProjectVersion;

    private final String scanMemory;

    private final String workingDirectoryPath;

    private final List<String> scanTargetPaths;

    private final boolean dryRun;

    private final String toolsDirectory;

    private final String thirdPartyVersion;

    private final String pluginVersion;

    private final HubServerConfig hubServerConfig;

    private final boolean performWorkspaceCheck;

    public RemoteScan(IntLogger logger, String hubProjectName, String hubProjectVersion, String scanMemory, String workingDirectoryPath,
            List<String> scanTargetPaths, boolean dryRun, String toolsDirectory, String thirdPartyVersion,
            String pluginVersion, HubServerConfig hubServerConfig, boolean performWorkspaceCheck) {
        this.logger = logger;
        this.hubProjectName = hubProjectName;
        this.hubProjectVersion = hubProjectVersion;
        this.scanMemory = scanMemory;
        this.workingDirectoryPath = workingDirectoryPath;
        this.scanTargetPaths = scanTargetPaths;
        this.dryRun = dryRun;
        this.toolsDirectory = toolsDirectory;
        this.thirdPartyVersion = thirdPartyVersion;
        this.pluginVersion = pluginVersion;
        this.hubServerConfig = hubServerConfig;
        this.performWorkspaceCheck = performWorkspaceCheck;
    }

    @Override
    public List<ScanSummaryItem> call() throws HubIntegrationException {
        try {
            RestConnection restConnection = new CredentialsRestConnection(logger, hubServerConfig);
            restConnection.connect();

            final HubServicesFactory services = new HubServicesFactory(restConnection);
            final CLIDataService cliDataService = services.createCLIDataService(logger);

            File workingDirectory = new File(workingDirectoryPath);
            File toolsDir = new File(toolsDirectory);

            final HubScanConfigBuilder hubScanConfigBuilder = new HubScanConfigBuilder();
            hubScanConfigBuilder.setDryRun(dryRun);
            hubScanConfigBuilder.setProjectName(hubProjectName);
            hubScanConfigBuilder.setVersion(hubProjectVersion);
            hubScanConfigBuilder.setWorkingDirectory(workingDirectory);
            hubScanConfigBuilder.setScanMemory(scanMemory);
            hubScanConfigBuilder.addAllScanTargetPaths(scanTargetPaths);
            hubScanConfigBuilder.setToolsDir(toolsDir);
            hubScanConfigBuilder.setThirdPartyName(ThirdPartyName.JENKINS);
            hubScanConfigBuilder.setThirdPartyVersion(thirdPartyVersion);
            hubScanConfigBuilder.setPluginVersion(pluginVersion);
            if (performWorkspaceCheck) {
                // TODO hubScanConfigBuilder.enableScanTargetPathsWithinWorkingDirectoryCheck();
            }

            HubScanConfig hubScanConfig = hubScanConfigBuilder.build();

            List<ScanSummaryItem> scans = cliDataService.installAndRunScan(hubServerConfig, hubScanConfig);

            return scans;
        } catch (IllegalArgumentException e) {
            throw new HubIntegrationException(e.getMessage(), e);
        } catch (EncryptionException e) {
            throw new HubIntegrationException(e.getMessage(), e);
        }
    }

    @Override
    public void checkRoles(RoleChecker checker) throws SecurityException {
        checker.check(this, new Role(RemoteScan.class));
    }
}
