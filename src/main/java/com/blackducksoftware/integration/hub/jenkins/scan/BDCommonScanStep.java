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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;

import com.blackducksoftware.integration.exception.IntegrationException;
import com.blackducksoftware.integration.hub.api.codelocation.CodeLocationRequestService;
import com.blackducksoftware.integration.hub.api.item.MetaService;
import com.blackducksoftware.integration.hub.api.project.ProjectRequestService;
import com.blackducksoftware.integration.hub.api.project.version.ProjectVersionRequestService;
import com.blackducksoftware.integration.hub.builder.HubServerConfigBuilder;
import com.blackducksoftware.integration.hub.dataservice.report.RiskReportDataService;
import com.blackducksoftware.integration.hub.global.HubServerConfig;
import com.blackducksoftware.integration.hub.jenkins.HubJenkinsLogger;
import com.blackducksoftware.integration.hub.jenkins.HubServerInfo;
import com.blackducksoftware.integration.hub.jenkins.HubServerInfoSingleton;
import com.blackducksoftware.integration.hub.jenkins.Messages;
import com.blackducksoftware.integration.hub.jenkins.ScanJobs;
import com.blackducksoftware.integration.hub.jenkins.action.BomUpToDateAction;
import com.blackducksoftware.integration.hub.jenkins.action.HubReportAction;
import com.blackducksoftware.integration.hub.jenkins.action.HubScanFinishedAction;
import com.blackducksoftware.integration.hub.jenkins.cli.DummyToolInstallation;
import com.blackducksoftware.integration.hub.jenkins.cli.DummyToolInstaller;
import com.blackducksoftware.integration.hub.jenkins.exceptions.BDJenkinsHubPluginException;
import com.blackducksoftware.integration.hub.jenkins.exceptions.HubConfigurationException;
import com.blackducksoftware.integration.hub.jenkins.helper.BuildHelper;
import com.blackducksoftware.integration.hub.jenkins.helper.PluginHelper;
import com.blackducksoftware.integration.hub.jenkins.remote.DetermineTargetPath;
import com.blackducksoftware.integration.hub.jenkins.remote.RemoteScan;
import com.blackducksoftware.integration.hub.model.view.CodeLocationView;
import com.blackducksoftware.integration.hub.model.view.ProjectVersionView;
import com.blackducksoftware.integration.hub.model.view.ProjectView;
import com.blackducksoftware.integration.hub.model.view.ScanSummaryView;
import com.blackducksoftware.integration.hub.report.api.ReportData;
import com.blackducksoftware.integration.hub.rest.RestConnection;
import com.blackducksoftware.integration.hub.service.HubServicesFactory;
import com.blackducksoftware.integration.log.IntLogger;
import com.blackducksoftware.integration.util.CIEnvironmentVariables;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.ProxyConfiguration;
import hudson.model.Node;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskListener;
import jenkins.model.Jenkins;

public class BDCommonScanStep {

    private final ScanJobs[] scans;

    private final String hubProjectName;

    private final String hubProjectVersion;

    private final String scanMemory;

    private final boolean shouldGenerateHubReport;

    private final String bomUpdateMaxiumWaitTime;

    private final boolean dryRun;

    private final boolean cleanupOnSuccessfulScan;

    private final Boolean verbose;

    private final BomUpToDateAction bomUpToDateAction = new BomUpToDateAction();

    private final String[] excludePatterns;

    private final String codeLocationName;

    public BDCommonScanStep(final ScanJobs[] scans, final String hubProjectName, final String hubProjectVersion,
            final String scanMemory,
            final boolean shouldGenerateHubReport, final String bomUpdateMaxiumWaitTime, final boolean dryRun, final boolean cleanupOnSuccessfulScan,
            final Boolean verbose, final String[] excludePatterns, final String codeLocationName) {
        this.scans = scans;
        this.hubProjectName = hubProjectName;
        this.hubProjectVersion = hubProjectVersion;
        this.scanMemory = scanMemory;
        this.shouldGenerateHubReport = shouldGenerateHubReport;
        this.bomUpdateMaxiumWaitTime = bomUpdateMaxiumWaitTime;
        this.dryRun = dryRun;
        this.cleanupOnSuccessfulScan = cleanupOnSuccessfulScan;
        this.verbose = verbose;
        this.excludePatterns = excludePatterns;
        this.codeLocationName = codeLocationName;
    }

    public String getCodeLocationName() {
        return codeLocationName;
    }

    public ScanJobs[] getScans() {
        return scans;
    }

    public String[] getExcludePatterns() {
        return excludePatterns;
    }

    public String getHubProjectName() {
        return hubProjectName;
    }

    public String getHubProjectVersion() {
        return hubProjectVersion;
    }

    public String getScanMemory() {
        return scanMemory;
    }

    public int getScanMemoryInteger() {
        int memory = NumberUtils.toInt(scanMemory);
        if (memory <= 0) {
            memory = 4096;
        }
        return memory;
    }

    public boolean isShouldGenerateHubReport() {
        return shouldGenerateHubReport;
    }

    public String getBomUpdateMaxiumWaitTime() {
        return bomUpdateMaxiumWaitTime;
    }

    public boolean isDryRun() {
        return dryRun;
    }

    public Boolean isVerbose() {
        return verbose;
    }

    public boolean isCleanupOnSuccessfulScan() {
        return cleanupOnSuccessfulScan;
    }

    public BomUpToDateAction getBomUpToDateAction() {
        return bomUpToDateAction;
    }

    public HubServerInfo getHubServerInfo() {
        return HubServerInfoSingleton.getInstance().getServerInfo();
    }

    public void runScan(final Run run, final Node builtOn, final EnvVars envVars, final FilePath workspace,
            final HubJenkinsLogger logger, final Launcher launcher, final TaskListener listener,
            final String buildDisplayName, final String buildIdentifier)
            throws InterruptedException, IOException {

        final CIEnvironmentVariables variables = new CIEnvironmentVariables();
        variables.putAll(envVars);
        logger.setLogLevel(variables);
        if (run.getResult() == null) {
            run.setResult(Result.SUCCESS);
        }
        if (run.getResult() == Result.SUCCESS) {
            try {
                logger.alwaysLog("Initializing - Hub Jenkins Plugin - " + PluginHelper.getPluginVersion());
                logger.alwaysLog("Starting BlackDuck Scans...");

                if (validateGlobalConfiguration()) {

                    final DummyToolInstaller dummyInstaller = new DummyToolInstaller();
                    final String toolsDirectory = dummyInstaller.getToolDir(new DummyToolInstallation(), builtOn)
                            .getRemote();
                    final String workingDirectory = workspace.getRemote();
                    final List<String> scanTargetPaths = getScanTargets(logger, builtOn, envVars, workingDirectory);

                    String projectName = null;
                    String projectVersion = null;
                    if (StringUtils.isNotBlank(getHubProjectName()) && StringUtils.isNotBlank(getHubProjectVersion())) {
                        projectName = BuildHelper.handleVariableReplacement(envVars, getHubProjectName());
                        projectVersion = BuildHelper.handleVariableReplacement(envVars, getHubProjectVersion());
                    }

                    final String codeLocationName = BuildHelper.handleVariableReplacement(envVars, getCodeLocationName());

                    final HubServerConfigBuilder hubServerConfigBuilder = new HubServerConfigBuilder();
                    hubServerConfigBuilder.setHubUrl(getHubServerInfo().getServerUrl());
                    hubServerConfigBuilder.setUsername(getHubServerInfo().getUsername());
                    hubServerConfigBuilder.setPassword(getHubServerInfo().getPassword());
                    hubServerConfigBuilder.setTimeout(getHubServerInfo().getTimeout());

                    final Jenkins jenkins = Jenkins.getInstance();
                    if (jenkins != null) {
                        final ProxyConfiguration proxyConfig = jenkins.proxy;
                        if (proxyConfig != null) {
                            final URL actualUrl = new URL(getHubServerInfo().getServerUrl());
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

                    final HubServerConfig hubServerConfig = hubServerConfigBuilder.build();
                    hubServerConfig.print(logger);

                    final String thirdPartyVersion = Jenkins.getVersion().toString();
                    final String pluginVersion = PluginHelper.getPluginVersion();

                    final RemoteScan scan = new RemoteScan(logger, codeLocationName, projectName, projectVersion, getScanMemoryInteger(),
                            workingDirectory, scanTargetPaths, dryRun,
                            isCleanupOnSuccessfulScan(), toolsDirectory,
                            thirdPartyVersion, pluginVersion, hubServerConfig,
                            getHubServerInfo().isPerformWorkspaceCheck(), getExcludePatterns(), envVars);

                    final List<String> scanSummaryStrings = builtOn.getChannel().call(scan);

                    final RestConnection restConnection = BuildHelper.getRestConnection(logger, hubServerConfig);
                    restConnection.connect();

                    final List<ScanSummaryView> scanSummaries = new ArrayList<>();

                    for (final String scanString : scanSummaryStrings) {
                        final ScanSummaryView scanSummaryItem = restConnection.gson.fromJson(scanString, ScanSummaryView.class);
                        scanSummaries.add(scanSummaryItem);
                    }

                    final HubServicesFactory services = new HubServicesFactory(restConnection);
                    final MetaService metaService = services.createMetaService(logger);
                    ProjectVersionView version = null;
                    ProjectView project = null;
                    if (!isDryRun() && StringUtils.isNotBlank(projectName) && StringUtils.isNotBlank(projectVersion) && !scanSummaries.isEmpty()) {
                        version = getProjectVersionFromScanStatus(services.createCodeLocationRequestService(logger),
                                services.createProjectVersionRequestService(logger), metaService,
                                scanSummaries.get(0));
                        project = getProjectFromVersion(services.createProjectRequestService(), metaService, version);
                    }

                    bomUpToDateAction.setDryRun(isDryRun());

                    Long bomWait = 300000l;
                    if (!isDryRun()) {
                        try {
                            // User input is in minutes, need to changes to milliseconds
                            bomWait = Long.valueOf(bomUpdateMaxiumWaitTime) * 60 * 1000;
                        } catch (final NumberFormatException e) {
                            bomWait = 300000l;
                        }
                        // User input is in minutes, need to changes to milliseconds
                        logger.alwaysLog("--> Bom wait time : " + bomWait / 60 / 1000 + "m");
                    }

                    if (run.getResult().equals(Result.SUCCESS) && !isDryRun() && isShouldGenerateHubReport() && version != null) {

                        final HubReportAction reportAction = new HubReportAction(run);

                        final RiskReportDataService reportService = services.createRiskReportDataService(logger, bomWait);
                        logger.debug("Waiting for Bom to be updated.");
                        services.createScanStatusDataService(logger, bomWait).assertBomImportScansFinished(scanSummaries);

                        logger.debug("Generating the Risk Report.");
                        final ReportData reportData = reportService.getRiskReportData(project, version);
                        reportAction.setReportData(reportData);

                        run.addAction(reportAction);
                        bomUpToDateAction.setHasBomBeenUdpated(true);
                    } else {
                        bomUpToDateAction.setHasBomBeenUdpated(false);
                        bomUpToDateAction.setMaxWaitTime(bomWait);
                        bomUpToDateAction.setScanSummaries(scanSummaries);
                    }
                    if (version != null) {
                        String policyStatusLink = null;
                        try {
                            // not all HUb users have the policy module enabled
                            // so there will be no policy status link
                            policyStatusLink = metaService.getFirstLink(version, MetaService.POLICY_STATUS_LINK);
                        } catch (final Exception e) {
                            logger.debug(e.getMessage(), e);
                        }
                        bomUpToDateAction.setPolicyStatusUrl(policyStatusLink);
                    }
                    run.addAction(bomUpToDateAction);
                    run.addAction(new HubScanFinishedAction());
                }
            } catch (final BDJenkinsHubPluginException e) {
                logger.error(e.getMessage(), e);
                run.setResult(Result.UNSTABLE);
            } catch (final IntegrationException e) {
                logger.error(e.getMessage(), e);
                run.setResult(Result.UNSTABLE);
            } catch (final Exception e) {
                String message;
                if (e.getMessage() != null && e.getMessage().contains("Project could not be found")) {
                    message = e.getMessage();
                } else {

                    if (e.getCause() != null && e.getCause().getCause() != null) {
                        message = e.getCause().getCause().toString();
                    } else if (e.getCause() != null) {
                        message = e.getCause().toString();
                    } else {
                        message = e.toString();
                    }
                    if (message.toLowerCase().contains("service unavailable")) {
                        message = Messages.HubBuildScan_getCanNotReachThisServer_0_(getHubServerInfo().getServerUrl());
                    } else if (message.toLowerCase().contains("precondition failed")) {
                        message = message + ", Check your configuration.";
                    }
                }
                logger.error(message, e);
                run.setResult(Result.UNSTABLE);
            }
        } else {
            logger.alwaysLog("Build was not successful. Will not run Black Duck Scans.");
        }
        logger.alwaysLog("Finished running Black Duck Scans.");
    }

    private ProjectView getProjectFromVersion(final ProjectRequestService projectRequestService, final MetaService metaService,
            final ProjectVersionView version)
            throws IntegrationException {
        final String projectURL = metaService.getFirstLink(version, MetaService.PROJECT_LINK);
        final ProjectView projectVersion = projectRequestService.getItem(projectURL, ProjectView.class);
        return projectVersion;
    }

    private ProjectVersionView getProjectVersionFromScanStatus(final CodeLocationRequestService codeLocationRequestService,
            final ProjectVersionRequestService projectVersionRequestService, final MetaService metaService, final ScanSummaryView scanSummaryItem)
            throws IntegrationException {
        final CodeLocationView codeLocationItem = codeLocationRequestService
                .getItem(metaService.getFirstLink(scanSummaryItem, MetaService.CODE_LOCATION_BOM_STATUS_LINK), CodeLocationView.class);
        final String projectVersionUrl = codeLocationItem.getMappedProjectVersion();
        final ProjectVersionView projectVersion = projectVersionRequestService.getItem(projectVersionUrl, ProjectVersionView.class);
        return projectVersion;
    }

    public List<String> getScanTargets(final IntLogger logger, final Node builtOn, final EnvVars variables,
            final String workingDirectory) throws BDJenkinsHubPluginException, InterruptedException {
        final List<String> scanTargetPaths = new ArrayList<>();
        final ScanJobs[] scans = getScans();
        if (scans == null || scans.length == 0) {
            scanTargetPaths.add(workingDirectory);
        } else {
            for (final ScanJobs scanJob : scans) {
                if (StringUtils.isEmpty(scanJob.getScanTarget())) {
                    scanTargetPaths.add(workingDirectory);
                } else {
                    String target = BuildHelper.handleVariableReplacement(variables, scanJob.getScanTarget().trim());

                    try {
                        target = builtOn.getChannel().call(new DetermineTargetPath(workingDirectory, target));
                    } catch (final IOException e) {
                        logger.error("Problem getting the real path of the target : " + target
                                + " on this node. Error : " + e.getMessage(), e);
                    }
                    scanTargetPaths.add(target);
                }
            }
        }

        return scanTargetPaths;
    }

    /**
     * Validates that the Plugin is configured correctly. Checks that the User
     * has defined an iScan tool, a Hub server URL, a Credential, and that there
     * are at least one scan Target/Job defined in the Build
     *
     */
    public boolean validateGlobalConfiguration() throws HubConfigurationException {

        if (getHubServerInfo() == null) {
            throw new HubConfigurationException("Could not find the Hub global configuration.");
        }
        if (!getHubServerInfo().isPluginConfigured()) {
            // If plugin is not Configured, we try to find out what is missing.
            if (StringUtils.isEmpty(getHubServerInfo().getServerUrl())) {
                throw new HubConfigurationException("No Hub URL was provided.");
            }
            if (StringUtils.isEmpty(getHubServerInfo().getCredentialsId())) {
                throw new HubConfigurationException("No credentials could be found to connect to the Hub.");
            }
        }
        // No exceptions were thrown so return true
        return true;
    }

}
