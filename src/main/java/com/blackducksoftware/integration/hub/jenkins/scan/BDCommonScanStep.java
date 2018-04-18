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

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;

import com.blackducksoftware.integration.exception.IntegrationException;
import com.blackducksoftware.integration.hub.api.generated.enumeration.ProjectVersionDistributionType;
import com.blackducksoftware.integration.hub.api.generated.enumeration.ProjectVersionPhaseType;
import com.blackducksoftware.integration.hub.api.generated.view.ProjectVersionView;
import com.blackducksoftware.integration.hub.api.generated.view.ProjectView;
import com.blackducksoftware.integration.hub.api.view.MetaHandler;
import com.blackducksoftware.integration.hub.configuration.HubServerConfig;
import com.blackducksoftware.integration.hub.configuration.HubServerConfigBuilder;
import com.blackducksoftware.integration.hub.jenkins.HubJenkinsLogger;
import com.blackducksoftware.integration.hub.jenkins.HubServerInfo;
import com.blackducksoftware.integration.hub.jenkins.HubServerInfoSingleton;
import com.blackducksoftware.integration.hub.jenkins.Messages;
import com.blackducksoftware.integration.hub.jenkins.ScanJobs;
import com.blackducksoftware.integration.hub.jenkins.action.BomUpToDateAction;
import com.blackducksoftware.integration.hub.jenkins.action.HubReportV2Action;
import com.blackducksoftware.integration.hub.jenkins.action.HubScanFinishedAction;
import com.blackducksoftware.integration.hub.jenkins.cli.DummyToolInstallation;
import com.blackducksoftware.integration.hub.jenkins.cli.DummyToolInstaller;
import com.blackducksoftware.integration.hub.jenkins.exceptions.BDJenkinsHubPluginException;
import com.blackducksoftware.integration.hub.jenkins.exceptions.HubConfigurationException;
import com.blackducksoftware.integration.hub.jenkins.helper.BuildHelper;
import com.blackducksoftware.integration.hub.jenkins.helper.JenkinsProxyHelper;
import com.blackducksoftware.integration.hub.jenkins.helper.PluginHelper;
import com.blackducksoftware.integration.hub.jenkins.remote.DetermineTargetPath;
import com.blackducksoftware.integration.hub.jenkins.remote.RemoteScan;
import com.blackducksoftware.integration.hub.jenkins.remote.ScanResponse;
import com.blackducksoftware.integration.hub.report.api.ReportData;
import com.blackducksoftware.integration.hub.rest.RestConnection;
import com.blackducksoftware.integration.hub.service.HubService;
import com.blackducksoftware.integration.hub.service.HubServicesFactory;
import com.blackducksoftware.integration.hub.service.PhoneHomeService;
import com.blackducksoftware.integration.hub.service.ReportService;
import com.blackducksoftware.integration.log.IntLogger;
import com.blackducksoftware.integration.phonehome.PhoneHomeRequestBody;
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

    private final String phase;

    private final String distribution;

    private final String scanMemory;

    private final boolean projectLevelAdjustments;

    private final boolean shouldGenerateHubReport;

    private final String bomUpdateMaximumWaitTime;

    private final boolean dryRun;

    private final boolean cleanupOnSuccessfulScan;

    private final boolean unmapPreviousCodeLocations;

    private final boolean deletePreviousCodeLocations;

    private final Boolean verbose;

    private final BomUpToDateAction bomUpToDateAction = new BomUpToDateAction();

    private final String[] excludePatterns;

    private final String codeLocationName;

    private final boolean failureConditionsConfigured;

    public BDCommonScanStep(final ScanJobs[] scans, final String hubProjectName, final String hubProjectVersion, final String phase, final String distribution, final String scanMemory, final boolean projectLevelAdjustments,
            final boolean shouldGenerateHubReport, final String bomUpdateMaximumWaitTime, final boolean dryRun, final boolean cleanupOnSuccessfulScan, final Boolean verbose, final String[] excludePatterns, final String codeLocationName,
            final boolean unmapPreviousCodeLocations, final boolean deletePreviousCodeLocations, final boolean failureConditionsConfigured) {
        this.scans = scans;
        this.hubProjectName = hubProjectName;
        this.hubProjectVersion = hubProjectVersion;
        this.phase = phase;
        this.distribution = distribution;
        this.scanMemory = scanMemory;
        this.projectLevelAdjustments = projectLevelAdjustments;
        this.shouldGenerateHubReport = shouldGenerateHubReport;
        this.bomUpdateMaximumWaitTime = bomUpdateMaximumWaitTime;
        this.dryRun = dryRun;
        this.cleanupOnSuccessfulScan = cleanupOnSuccessfulScan;
        this.verbose = verbose;
        this.excludePatterns = excludePatterns;
        this.codeLocationName = codeLocationName;
        this.unmapPreviousCodeLocations = unmapPreviousCodeLocations;
        this.deletePreviousCodeLocations = deletePreviousCodeLocations;
        this.failureConditionsConfigured = failureConditionsConfigured;
    }

    public String getCodeLocationName() {
        return this.codeLocationName;
    }

    public ScanJobs[] getScans() {
        return this.scans;
    }

    public String[] getExcludePatterns() {
        return this.excludePatterns;
    }

    public String getHubProjectName() {
        return this.hubProjectName;
    }

    public String getHubProjectVersion() {
        return this.hubProjectVersion;
    }

    public String getPhase() {
        if (this.phase == null) {
            // set to the default if they have not configured a phase, should help with migration from older versions that did not include the phase in the config
            return ProjectVersionPhaseType.DEVELOPMENT.toString();
        }
        return this.phase;
    }

    public String getDistribution() {
        if (this.distribution == null) {
            // set to the default if they have not configured a distribution, should help with migration from older versions that did not include the distribution in the config
            return ProjectVersionDistributionType.EXTERNAL.toString();
        }
        return this.distribution;
    }

    public String getScanMemory() {
        return this.scanMemory;
    }

    public int getScanMemoryInteger() {
        int memory = NumberUtils.toInt(this.scanMemory);
        if (memory <= 0) {
            memory = 4096;
        }
        return memory;
    }

    public boolean isProjectLevelAdjustments() {
        return this.projectLevelAdjustments;
    }

    public boolean isShouldGenerateHubReport() {
        return this.shouldGenerateHubReport;
    }

    public String getBomUpdateMaximumWaitTime() {
        return this.bomUpdateMaximumWaitTime;
    }

    public boolean isDryRun() {
        return this.dryRun;
    }

    public Boolean isVerbose() {
        return this.verbose;
    }

    public boolean isCleanupOnSuccessfulScan() {
        return this.cleanupOnSuccessfulScan;
    }

    public BomUpToDateAction getBomUpToDateAction() {
        return this.bomUpToDateAction;
    }

    public boolean isUnmapPreviousCodeLocations() {
        return this.unmapPreviousCodeLocations;
    }

    public boolean isDeletePreviousCodeLocations() {
        return this.deletePreviousCodeLocations;
    }

    public boolean isFailureConditionsConfigured() {
        return this.failureConditionsConfigured;
    }

    public HubServerInfo getHubServerInfo() {
        return HubServerInfoSingleton.getInstance().getServerInfo();
    }

    public void runScan(final Run run, final Node builtOn, final EnvVars envVars, final FilePath workspace, final HubJenkinsLogger logger, final Launcher launcher, final TaskListener listener, final String buildDisplayName,
            final String buildIdentifier) {

        final CIEnvironmentVariables variables = new CIEnvironmentVariables();
        variables.putAll(envVars);
        logger.setLogLevel(variables);
        if (run.getResult() == null) {
            run.setResult(Result.SUCCESS);
        }
        if (run.getResult() != Result.SUCCESS) {
            logger.alwaysLog("Build was not successful. Will not run Black Duck Scans.");
        } else {
            try {
                logger.alwaysLog("Initializing - Hub Jenkins Plugin - " + PluginHelper.getPluginVersion());
                logger.alwaysLog("Starting BlackDuck Scans...");

                if (validateGlobalConfiguration()) {

                    final DummyToolInstaller dummyInstaller = new DummyToolInstaller();
                    final String toolsDirectory = dummyInstaller.getToolDir(new DummyToolInstallation(), builtOn).getRemote();
                    final String workingDirectory = workspace.getRemote();
                    final List<String> scanTargetPaths = getScanTargets(logger, builtOn, envVars, workingDirectory);

                    String projectName = null;
                    String projectVersion = null;
                    if (StringUtils.isNotBlank(getHubProjectName())) {
                        projectName = BuildHelper.handleVariableReplacement(envVars, getHubProjectName());
                    }
                    if (StringUtils.isNotBlank(getHubProjectVersion())) {
                        projectVersion = BuildHelper.handleVariableReplacement(envVars, getHubProjectVersion());
                    }

                    final String codeLocationName = BuildHelper.handleVariableReplacement(envVars, getCodeLocationName());

                    final HubServerConfigBuilder hubServerConfigBuilder = new HubServerConfigBuilder();
                    hubServerConfigBuilder.setHubUrl(getHubServerInfo().getServerUrl());
                    hubServerConfigBuilder.setUsername(getHubServerInfo().getUsername());
                    hubServerConfigBuilder.setPassword(getHubServerInfo().getPassword());
                    hubServerConfigBuilder.setTimeout(getHubServerInfo().getTimeout());
                    hubServerConfigBuilder.setAlwaysTrustServerCertificate(getHubServerInfo().shouldTrustSSLCerts());

                    final Jenkins jenkins = Jenkins.getInstance();
                    if (jenkins != null) {
                        final ProxyConfiguration proxyConfig = jenkins.proxy;
                        if (proxyConfig != null) {
                            if (JenkinsProxyHelper.shouldUseProxy(getHubServerInfo().getServerUrl(), proxyConfig.noProxyHost)) {
                                hubServerConfigBuilder.setProxyHost(proxyConfig.name);
                                hubServerConfigBuilder.setProxyPort(proxyConfig.port);
                                hubServerConfigBuilder.setProxyUsername(proxyConfig.getUserName());
                                hubServerConfigBuilder.setProxyPassword(proxyConfig.getPassword());
                            }
                        }
                    }

                    final HubServerConfig hubServerConfig = hubServerConfigBuilder.build();
                    hubServerConfig.print(logger);

                    final String thirdPartyVersion = Jenkins.getVersion().toString();
                    final String pluginVersion = PluginHelper.getPluginVersion();

                    HubServicesFactory services = null;
                    if (!isDryRun()) {
                        final RestConnection restConnection = BuildHelper.getRestConnection(logger, hubServerConfig);
                        restConnection.connect();

                        services = new HubServicesFactory(restConnection);

                        PhoneHomeService phoneHomeService = services.createPhoneHomeService();
                        PhoneHomeRequestBody.Builder builder = phoneHomeService.createInitialPhoneHomeRequestBodyBuilder();
                        builder.setArtifactId("blackduck-hub");
                        builder.setArtifactVersion(pluginVersion);
                        builder.addToMetaData("jenkins.version", thirdPartyVersion);
                        phoneHomeService.phoneHome(builder);
                    }

                    final RemoteScan scan = new RemoteScan(logger, codeLocationName, projectName, projectVersion, getPhase(), getDistribution(), getScanMemoryInteger(), isProjectLevelAdjustments(), workingDirectory, scanTargetPaths,
                            isDryRun(), isCleanupOnSuccessfulScan(), toolsDirectory, hubServerConfig, getHubServerInfo().isPerformWorkspaceCheck(), getExcludePatterns(), envVars,
                            isUnmapPreviousCodeLocations(), isDeletePreviousCodeLocations(), isShouldWaitForScansFinished());

                    final ScanResponse scanResponse = builtOn.getChannel().call(scan);
                    if (null != scanResponse.getException()) {
                        final Exception exception = scanResponse.getException();
                        if (exception instanceof InterruptedException) {
                            run.setResult(Result.ABORTED);
                            Thread.currentThread().interrupt();
                        } else {
                            logger.error(exception.getMessage(), exception);
                            run.setResult(Result.UNSTABLE);
                        }
                        return;
                    }
                    final String projectVersionViewJson = scanResponse.getVersionJson();

                    this.bomUpToDateAction.setDryRun(isDryRun());

                    Long bomWait = 300000l;
                    if (!isDryRun()) {
                        final MetaHandler metaHandler = new MetaHandler(logger);

                        ProjectVersionView version = null;
                        ProjectView project = null;
                        if (StringUtils.isNotBlank(projectName) && StringUtils.isNotBlank(projectVersion) && StringUtils.isNotBlank(projectVersionViewJson)) {
                            HubService hubService = services.createHubService();
                            version = hubService.getGson().fromJson(projectVersionViewJson, ProjectVersionView.class);
                            project = getProjectFromVersion(hubService, version);
                        }

                        try {
                            // User input is in minutes, need to changes to milliseconds
                            bomWait = Long.valueOf(getBomUpdateMaximumWaitTime()) * 60 * 1000;
                        } catch (final NumberFormatException e) {
                            bomWait = 300000l;
                        }
                        // User input is in minutes, need to changes to milliseconds
                        logger.alwaysLog("--> Bom wait time : " + bomWait / 60 / 1000 + "m");
                        logger.alwaysLog("--> Generate Report : " + isShouldGenerateHubReport());

                        if (run.getResult().equals(Result.SUCCESS) && isShouldGenerateHubReport()) {
                            if (project != null && version != null) {
                                final HubReportV2Action reportAction = new HubReportV2Action(run);

                                final ReportService reportService = services.createReportService(bomWait);

                                logger.debug("Generating the Risk Report.");
                                final ReportData reportData = reportService.getRiskReportData(project, version);
                                reportAction.setReportData(reportData);

                                run.addAction(reportAction);
                                this.bomUpToDateAction.setHasBomBeenUdpated(true);
                            } else {
                                logger.error("Could not find the Hub Project or Version for this scan. Check that the status directory exists.");
                                run.setResult(Result.UNSTABLE);
                                return;
                            }
                        } else {
                            this.bomUpToDateAction.setHasBomBeenUdpated(false);
                            this.bomUpToDateAction.setMaxWaitTime(bomWait);
                        }
                        if (version != null) {
                            String policyStatusLink = null;
                            try {
                                // not all HUB users have the policy module enabled
                                // so there will be no policy status link
                                policyStatusLink = metaHandler.getFirstLink(version, ProjectVersionView.POLICY_STATUS_LINK);
                            } catch (final Exception e) {
                                logger.debug("Could not get the policy status link, the Hub policy module is not enabled");
                            }
                            this.bomUpToDateAction.setPolicyStatusUrl(policyStatusLink);
                        }

                    }

                }
            } catch (final BDJenkinsHubPluginException e) {
                logger.error(e.getMessage(), e);
                run.setResult(Result.UNSTABLE);
            } catch (final IntegrationException e) {
                logger.error(e.getMessage(), e);
                run.setResult(Result.UNSTABLE);
            } catch (final InterruptedException e) {
                logger.error("BD scan caller thread was interrupted.", e);
                run.setResult(Result.ABORTED);
                Thread.currentThread().interrupt();
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
        }
        logger.alwaysLog("Finished running Black Duck Scans.");
        run.addAction(this.bomUpToDateAction);
        run.addAction(new HubScanFinishedAction());
    }

    private ProjectView getProjectFromVersion(final HubService hubService, final ProjectVersionView projectVersionView) throws IntegrationException {
        return hubService.getResponse(projectVersionView, ProjectVersionView.PROJECT_LINK_RESPONSE);
    }

    private boolean isShouldWaitForScansFinished() {
        return !isDryRun() && (isShouldGenerateHubReport() || isFailureConditionsConfigured());
    }

    public List<String> getScanTargets(final IntLogger logger, final Node builtOn, final EnvVars variables, final String workingDirectory) throws BDJenkinsHubPluginException, InterruptedException {
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
                        logger.error("Problem getting the real path of the target : " + target + " on this node. Error : " + e.getMessage(), e);
                    }
                    scanTargetPaths.add(target);
                }
            }
        }

        return scanTargetPaths;
    }

    /**
     * Validates that the Plugin is configured correctly. Checks that the User has defined an iScan tool, a Hub server URL, a Credential, and that there are at least one scan Target/Job defined in the Build
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
