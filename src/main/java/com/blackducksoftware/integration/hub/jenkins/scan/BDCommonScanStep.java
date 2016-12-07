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

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.json.JSONException;
import org.restlet.resource.ResourceException;

import com.blackducksoftware.integration.builder.ValidationResult;
import com.blackducksoftware.integration.builder.ValidationResultEnum;
import com.blackducksoftware.integration.builder.ValidationResults;
import com.blackducksoftware.integration.hub.HubIntRestService;
import com.blackducksoftware.integration.hub.HubSupportHelper;
import com.blackducksoftware.integration.hub.api.codelocation.CodeLocationItem;
import com.blackducksoftware.integration.hub.api.project.ProjectItem;
import com.blackducksoftware.integration.hub.api.project.version.ProjectVersionItem;
import com.blackducksoftware.integration.hub.api.report.HubReportGenerationInfo;
import com.blackducksoftware.integration.hub.api.report.ReportCategoriesEnum;
import com.blackducksoftware.integration.hub.api.scan.ScanSummaryItem;
import com.blackducksoftware.integration.hub.api.version.ReleaseItem;
import com.blackducksoftware.integration.hub.builder.HubScanJobConfigBuilder;
import com.blackducksoftware.integration.hub.dataservices.DataServicesFactory;
import com.blackducksoftware.integration.hub.exception.BDRestException;
import com.blackducksoftware.integration.hub.exception.HubIntegrationException;
import com.blackducksoftware.integration.hub.exception.ProjectDoesNotExistException;
import com.blackducksoftware.integration.hub.exception.UnexpectedHubResponseException;
import com.blackducksoftware.integration.hub.exception.VersionDoesNotExistException;
import com.blackducksoftware.integration.hub.jenkins.HubJenkinsLogger;
import com.blackducksoftware.integration.hub.jenkins.HubServerInfo;
import com.blackducksoftware.integration.hub.jenkins.HubServerInfoSingleton;
import com.blackducksoftware.integration.hub.jenkins.Messages;
import com.blackducksoftware.integration.hub.jenkins.ScanJobs;
import com.blackducksoftware.integration.hub.jenkins.action.BomUpToDateAction;
import com.blackducksoftware.integration.hub.jenkins.action.HubReportAction;
import com.blackducksoftware.integration.hub.jenkins.action.HubScanFinishedAction;
import com.blackducksoftware.integration.hub.jenkins.bom.RemoteBomGenerator;
import com.blackducksoftware.integration.hub.jenkins.cli.DummyToolInstallation;
import com.blackducksoftware.integration.hub.jenkins.cli.DummyToolInstaller;
import com.blackducksoftware.integration.hub.jenkins.exceptions.BDJenkinsHubPluginException;
import com.blackducksoftware.integration.hub.jenkins.exceptions.HubConfigurationException;
import com.blackducksoftware.integration.hub.jenkins.exceptions.HubScanToolMissingException;
import com.blackducksoftware.integration.hub.jenkins.helper.BuildHelper;
import com.blackducksoftware.integration.hub.jenkins.helper.PluginHelper;
import com.blackducksoftware.integration.hub.jenkins.remote.CLIRemoteInstall;
import com.blackducksoftware.integration.hub.jenkins.remote.GetCLI;
import com.blackducksoftware.integration.hub.jenkins.remote.GetCLIExists;
import com.blackducksoftware.integration.hub.jenkins.remote.GetCLIProvidedJRE;
import com.blackducksoftware.integration.hub.jenkins.remote.GetCanonicalPath;
import com.blackducksoftware.integration.hub.jenkins.remote.GetHostName;
import com.blackducksoftware.integration.hub.jenkins.remote.GetHostNameFromNetworkInterfaces;
import com.blackducksoftware.integration.hub.jenkins.remote.GetIsOsWindows;
import com.blackducksoftware.integration.hub.jenkins.remote.GetOneJarFile;
import com.blackducksoftware.integration.hub.job.HubScanJobConfig;
import com.blackducksoftware.integration.hub.job.HubScanJobFieldEnum;
import com.blackducksoftware.integration.log.IntLogger;
import com.blackducksoftware.integration.phone.home.PhoneHomeClient;
import com.blackducksoftware.integration.phone.home.enums.BlackDuckName;
import com.blackducksoftware.integration.phone.home.enums.ThirdPartyName;
import com.blackducksoftware.integration.phone.home.exception.PhoneHomeException;
import com.blackducksoftware.integration.phone.home.exception.PropertiesLoaderException;
import com.blackducksoftware.integration.util.CIEnvironmentVariables;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.ProxyConfiguration;
import hudson.model.Node;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.remoting.VirtualChannel;
import jenkins.model.Jenkins;

public class BDCommonScanStep {

    private final ScanJobs[] scans;

    private final String hubProjectName;

    private final String hubProjectVersion;

    private final String hubVersionPhase;

    private final String hubVersionDist;

    private final String scanMemory;

    private final boolean shouldGenerateHubReport;

    private final String bomUpdateMaxiumWaitTime;

    private final boolean dryRun;

    private final Boolean verbose;

    private final BomUpToDateAction bomUpToDateAction = new BomUpToDateAction();

    public BDCommonScanStep(final ScanJobs[] scans, final String hubProjectName, final String hubProjectVersion,
            final String hubVersionPhase, final String hubVersionDist, final String scanMemory,
            final boolean shouldGenerateHubReport, final String bomUpdateMaxiumWaitTime, final boolean dryRun,
            final Boolean verbose) {
        this.scans = scans;
        this.hubProjectName = hubProjectName;
        this.hubVersionPhase = hubVersionPhase;
        this.hubVersionDist = hubVersionDist;
        this.hubProjectVersion = hubProjectVersion;
        this.scanMemory = scanMemory;
        this.shouldGenerateHubReport = shouldGenerateHubReport;
        this.bomUpdateMaxiumWaitTime = bomUpdateMaxiumWaitTime;
        this.dryRun = dryRun;
        this.verbose = verbose;
    }

    public ScanJobs[] getScans() {
        return scans;
    }

    public String getHubProjectName() {
        return hubProjectName;
    }

    public String getHubVersionPhase() {
        return hubVersionPhase;
    }

    public String getHubVersionDist() {
        return hubVersionDist;
    }

    public String getHubProjectVersion() {
        return hubProjectVersion;
    }

    public String getScanMemory() {
        return scanMemory;
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

    public BomUpToDateAction getBomUpToDateAction() {
        return bomUpToDateAction;
    }

    public HubServerInfo getHubServerInfo() {
        return HubServerInfoSingleton.getInstance().getServerInfo();
    }

    public void runScan(final Run run, final Node builtOn, final EnvVars envVars, final FilePath workspace,
            final HubJenkinsLogger logger, final Launcher launcher, final TaskListener listener,
            final String buildDisplayName, final String buildIdentifier, final FilePath javaHome)
            throws InterruptedException, IOException {

        final CIEnvironmentVariables variables = new CIEnvironmentVariables();
        variables.putAll(envVars);
        logger.setLogLevel(variables);
        if (run.getResult() == null) {
            run.setResult(Result.SUCCESS);
        }
        if (run.getResult() == Result.SUCCESS) {
            try {
                logger.alwaysLog("Starting BlackDuck Scans...");

                final String localHostName = getLocalHostName(logger, builtOn);

                if (validateGlobalConfiguration()) {
                    final String workingDirectory = workspace.getRemote();

                    final List<String> scanTargetPaths = getScanTargets(logger, builtOn, envVars, workingDirectory);

                    String projectName = null;
                    String projectVersion = null;

                    if (StringUtils.isNotBlank(getHubProjectName()) && StringUtils.isNotBlank(getHubProjectVersion())) {
                        projectName = BuildHelper.handleVariableReplacement(envVars, getHubProjectName());
                        projectVersion = BuildHelper.handleVariableReplacement(envVars, getHubProjectVersion());

                    }
                    final HubScanJobConfigBuilder hubScanJobConfigBuilder = new HubScanJobConfigBuilder(true);
                    hubScanJobConfigBuilder.setDryRun(isDryRun());
                    hubScanJobConfigBuilder.setProjectName(projectName);
                    hubScanJobConfigBuilder.setVersion(projectVersion);
                    hubScanJobConfigBuilder.setPhase(getHubVersionPhase());
                    hubScanJobConfigBuilder.setDistribution(getHubVersionDist());
                    hubScanJobConfigBuilder.setWorkingDirectory(workingDirectory);
                    hubScanJobConfigBuilder.setShouldGenerateRiskReport(isShouldGenerateHubReport());
                    if (getBomUpdateMaxiumWaitTime() == null) {
                        // If a User migrates from version 1.4.0 to here and
                        // does not re-save the configuration the wait time will
                        // be null
                        hubScanJobConfigBuilder.setMaxWaitTimeForBomUpdate(
                                HubScanJobConfigBuilder.DEFAULT_BOM_UPDATE_WAIT_TIME_IN_MINUTES);
                    } else {
                        hubScanJobConfigBuilder.setMaxWaitTimeForBomUpdate(getBomUpdateMaxiumWaitTime());
                    }
                    hubScanJobConfigBuilder.setScanMemory(getScanMemory());
                    hubScanJobConfigBuilder.addAllScanTargetPaths(scanTargetPaths);
                    hubScanJobConfigBuilder.disableScanTargetPathExistenceCheck();

                    final ValidationResults<HubScanJobFieldEnum, HubScanJobConfig> builderResults = hubScanJobConfigBuilder
                            .buildResults();
                    final HubScanJobConfig jobConfig = builderResults.getConstructedObject();
                    printConfiguration(builtOn, listener, logger, jobConfig, buildDisplayName, buildIdentifier,
                            workingDirectory);

                    if (!builderResults.isSuccess()) {
                        final Map<HubScanJobFieldEnum, List<ValidationResult>> results = builderResults.getResultMap();
                        for (final Entry<HubScanJobFieldEnum, List<ValidationResult>> errorEntry : results.entrySet()) {
                            final StringBuilder errorBuilder = new StringBuilder();
                            for (final ValidationResult validationResult : errorEntry.getValue()) {
                                if (validationResult.getResultType() != ValidationResultEnum.OK) {
                                    if (errorBuilder.length() > 0) {
                                        errorBuilder.append("\n");
                                    }
                                    if (StringUtils.isNotBlank(validationResult.getMessage())) {
                                        errorBuilder.append(validationResult.getMessage());
                                    }
                                }
                            }
                            if (errorBuilder.length() > 0) {
                                logger.error(errorEntry.getKey().name() + " :: " + errorBuilder.toString());
                            }
                        }
                    }
                    final DummyToolInstaller dummyInstaller = new DummyToolInstaller();
                    final String toolsDirectory = dummyInstaller.getToolDir(new DummyToolInstallation(), builtOn)
                            .getRemote();

                    final String scanExec = getScanCLI(logger, builtOn, toolsDirectory, localHostName, envVars);

                    final String jrePath = getJavaExec(logger, builtOn, toolsDirectory, envVars, javaHome.getRemote());

                    final String oneJarPath = getOneJarFile(builtOn, toolsDirectory);

                    final DataServicesFactory service = BuildHelper.getDataServiceFactory(logger,
                            getHubServerInfo().getServerUrl(), getHubServerInfo().getUsername(),
                            getHubServerInfo().getPassword(), getHubServerInfo().getTimeout());

                    final HubIntRestService intRestService = BuildHelper.getRestService(logger,
                            getHubServerInfo().getServerUrl(), getHubServerInfo().getUsername(),
                            getHubServerInfo().getPassword(), getHubServerInfo().getTimeout());
                    // ProjectItem project = null;
                    // ProjectVersionItem version = null;
                    // if (!isDryRun() && StringUtils.isNotBlank(projectName) && StringUtils.isNotBlank(projectVersion))
                    // {
                    // project = ensureProjectExists(service, logger, projectName);
                    // if (!project.getMeta().isAccessible()) {
                    // throw new ProjectNotAccessibleException(Messages.HubBuildScan_getProjectNotAccessible());
                    // }
                    // version = ensureVersionExists(service, logger, projectVersion, project);
                    // logger.debug("Found Project : " + projectName);
                    // logger.debug("Found Version : " + projectVersion);
                    // }
                    final HubSupportHelper hubSupport = new HubSupportHelper();

                    hubSupport.checkHubSupport(service.getHubVersionRestService(), logger);

                    // Phone-Home
                    try {
                        final String hubVersion = service.getHubVersionRestService().getHubVersion();
                        String regId = null;
                        String hubHostName = null;
                        try {
                            regId = intRestService.getRegistrationId();
                        } catch (final Exception e) {
                            logger.debug("Could not get the Hub registration Id.");
                        }
                        try {
                            final URL url = new URL(getHubServerInfo().getServerUrl());
                            hubHostName = url.getHost();
                        } catch (final Exception e) {
                            logger.debug("Could not get the Hub Host name.");
                        }
                        bdPhoneHome(hubVersion, regId, hubHostName);
                    } catch (final Exception e) {
                        logger.debug("Unable to phone-home", e);
                    }

                    final JenkinsScanExecutor scan = new JenkinsScanExecutor(getHubServerInfo(),
                            jobConfig.getScanTargetPaths(), buildIdentifier, hubSupport, builtOn, launcher, logger);
                    scan.setVariables(variables);

                    final DateTime beforeScanTime = new DateTime();
                    run.setResult(runScan(builtOn, scan, logger, scanExec, jrePath, oneJarPath, jobConfig));
                    final DateTime afterScanTime = new DateTime();

                    ProjectVersionItem version = null;
                    ProjectItem project = null;
                    if (!isDryRun() && StringUtils.isNotBlank(projectName) && StringUtils.isNotBlank(projectVersion)) {
                        version = getProjectVersionFromScanStatus(builtOn.getChannel(), scan.getScanStatusDirectoryPath(), service);

                        project = getProjectFromVersion(version, service);
                    }

                    bomUpToDateAction.setDryRun(isDryRun());
                    if (run.getResult().equals(Result.SUCCESS) && !isDryRun() && isShouldGenerateHubReport() && StringUtils.isNotBlank(projectName)
                            && StringUtils.isNotBlank(projectVersion)) {

                        final HubReportGenerationInfo reportGenInfo = new HubReportGenerationInfo();
                        reportGenInfo.setService(intRestService);
                        reportGenInfo.setHostname(localHostName);
                        reportGenInfo.setProject(project);
                        reportGenInfo.setVersion(version);
                        reportGenInfo.setScanTargets(jobConfig.getScanTargetPaths());

                        reportGenInfo.setMaximumWaitTime(jobConfig.getMaxWaitTimeForBomUpdateInMilliseconds());

                        reportGenInfo.setBeforeScanTime(beforeScanTime);
                        reportGenInfo.setAfterScanTime(afterScanTime);

                        reportGenInfo.setScanStatusDirectory(scan.getScanStatusDirectoryPath());

                        generateHubReport(run, builtOn, logger, reportGenInfo, getHubServerInfo(), hubSupport,
                                bomUpToDateAction);
                    } else {
                        bomUpToDateAction.setHasBomBeenUdpated(false);
                        bomUpToDateAction.setAfterScanTime(afterScanTime);
                        bomUpToDateAction.setBeforeScanTime(beforeScanTime);
                        bomUpToDateAction.setLocalHostName(localHostName);
                        bomUpToDateAction.setMaxWaitTime(jobConfig.getMaxWaitTimeForBomUpdateInMilliseconds());
                        bomUpToDateAction.setScanStatusDirectory(scan.getScanStatusDirectoryPath());
                        bomUpToDateAction.setScanTargets(jobConfig.getScanTargetPaths());
                    }
                    if (version != null) {
                        String policyStatusLink = null;
                        try {
                            // not all HUb users have the policy module enabled
                            // so there will be no policy status link
                            policyStatusLink = version.getLink(ReleaseItem.POLICY_STATUS_LINK);
                        } catch (final Exception e) {
                            logger.debug("Could not get the policy status link.", e);
                        }
                        bomUpToDateAction.setPolicyStatusUrl(policyStatusLink);
                    }
                    run.addAction(bomUpToDateAction);
                    run.addAction(new HubScanFinishedAction());
                }
            } catch (final BDJenkinsHubPluginException e) {
                logger.error(e.getMessage(), e);
                run.setResult(Result.UNSTABLE);
            } catch (final HubIntegrationException e) {
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

    private ProjectVersionItem getProjectVersionFromScanStatus(VirtualChannel channel, String statusDirectory, DataServicesFactory services)
            throws IOException, InterruptedException, HubIntegrationException, BDRestException, URISyntaxException, UnexpectedHubResponseException {
        final FilePath statusDirectoryFilePath = new FilePath(channel, statusDirectory);
        if (!statusDirectoryFilePath.exists()) {
            throw new HubIntegrationException("The scan status directory does not exist.");
        }
        if (!statusDirectoryFilePath.isDirectory()) {
            throw new HubIntegrationException("The scan status directory provided is not a directory.");
        }
        final List<FilePath> statusFiles = statusDirectoryFilePath.list();
        if (statusFiles == null || statusFiles.size() == 0) {
            throw new HubIntegrationException("Can not find the scan status files in the directory provided.");
        }
        final String fileContent = statusFiles.get(0).readToString();
        final Gson gson = new GsonBuilder().create();
        final ScanSummaryItem scanSummaryItem = gson.fromJson(fileContent, ScanSummaryItem.class);
        CodeLocationItem codeLocationItem = services.getCodeLocationRestService().getItem(scanSummaryItem.getLink(ScanSummaryItem.CODE_LOCATION_LINK));
        String projectVersionUrl = codeLocationItem.getMappedProjectVersion();
        ProjectVersionItem projectVersion = services.getProjectVersionRestService().getItem(projectVersionUrl);
        return projectVersion;
    }

    private ProjectItem getProjectFromVersion(ProjectVersionItem version, DataServicesFactory services)
            throws IOException, BDRestException, URISyntaxException, UnexpectedHubResponseException {
        ProjectItem project = services.getProjectRestService().getItem(version.getLink(ProjectVersionItem.PROJECT_LINK));
        return project;
    }

    public String getLocalHostName(final IntLogger logger, final Node builtOn) throws InterruptedException {
        String localHostName = "";
        try {
            localHostName = builtOn.getChannel().call(new GetHostName());
        } catch (final IOException e) {
            // ignore the error, try to get the host name from the network
            // interfaces
        }
        if (StringUtils.isBlank(localHostName)) {
            try {
                localHostName = builtOn.getChannel().call(new GetHostNameFromNetworkInterfaces());
            } catch (final IOException e) {
                logger.error("Problem getting the Local Host name : " + e.getMessage(), e);
            }
        }
        logger.info("Hub Plugin running on machine : " + localHostName);
        return localHostName;
    }

    public List<String> getScanTargets(final IntLogger logger, final Node builtOn, final EnvVars variables,
            final String workingDirectory) throws BDJenkinsHubPluginException, InterruptedException {
        final List<String> scanTargetPaths = new ArrayList<String>();
        final ScanJobs[] scans = getScans();
        if (scans == null || scans.length == 0) {
            scanTargetPaths.add(workingDirectory);
        } else {
            for (final ScanJobs scanJob : scans) {
                if (StringUtils.isEmpty(scanJob.getScanTarget())) {
                    scanTargetPaths.add(workingDirectory);
                } else {
                    String target = BuildHelper.handleVariableReplacement(variables, scanJob.getScanTarget().trim());
                    // make sure the target provided doesn't already begin with
                    // a slash or end in a slash
                    // removes the slash if the target begins or ends with one
                    final File targetFile = new File(workingDirectory, target);

                    try {
                        target = builtOn.getChannel().call(new GetCanonicalPath(targetFile));
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

    private void generateHubReport(final Run run, final Node builtOn, final HubJenkinsLogger logger,
            final HubReportGenerationInfo reportGenInfo, final HubServerInfo serverInfo,
            final HubSupportHelper hubSupport, final BomUpToDateAction action) throws Exception {
        final HubReportAction reportAction = new HubReportAction(run);
        final RemoteBomGenerator remoteBomGenerator = new RemoteBomGenerator(reportGenInfo, hubSupport,
                builtOn.getChannel());
        final ReportCategoriesEnum[] categories = new ReportCategoriesEnum[2];
        categories[0] = ReportCategoriesEnum.VERSION;
        categories[1] = ReportCategoriesEnum.COMPONENTS;
        reportAction.setReportData(remoteBomGenerator.generateHubReport(logger, categories));
        run.addAction(reportAction);
        action.setHasBomBeenUdpated(true);
    }

    protected ProjectItem ensureProjectExists(final HubIntRestService service, final IntLogger logger,
            final String projectName) throws IOException, URISyntaxException, BDJenkinsHubPluginException {
        ProjectItem project = null;
        try {
            project = service.getProjectByName(projectName);

        } catch (final ProjectDoesNotExistException e) {
            // Project was not found, try to create it
            try {
                final String projectUrl = service.createHubProject(projectName);
                project = service.getProject(projectUrl);
            } catch (final BDRestException e1) {
                if (e1.getResource() != null) {
                    logger.error("Status : " + e1.getResource().getStatus().getCode());
                    logger.error("Response : " + e1.getResource().getResponse().getEntityAsText());
                }
                throw new BDJenkinsHubPluginException("Problem creating the Project. ", e1);
            }
        } catch (final BDRestException e) {
            if (e.getResource() != null) {
                if (e.getResource() != null) {
                    logger.error("Status : " + e.getResource().getStatus().getCode());
                    logger.error("Response : " + e.getResource().getResponse().getEntityAsText());
                }
                throw new BDJenkinsHubPluginException("Problem getting the Project. ", e);
            }
        }

        return project;
    }

    /**
     * Ensures the Version exists. Returns the version URL
     *
     * @throws UnexpectedHubResponseException
     */
    protected ProjectVersionItem ensureVersionExists(final HubIntRestService service, final IntLogger logger,
            final String projectVersion, final ProjectItem project)
            throws IOException, URISyntaxException, BDJenkinsHubPluginException, UnexpectedHubResponseException {
        ProjectVersionItem version = null;
        try {
            version = service.getVersion(project, projectVersion);
            if (!version.getPhase().equals(getHubVersionPhase())) {
                logger.warn(
                        "The selected Phase does not match the Phase of this Version. If you wish to update the Phase please do so in the Hub UI.");
            }
            if (!version.getDistribution().equals(getHubVersionDist())) {
                logger.warn(
                        "The selected Distribution does not match the Distribution of this Version. If you wish to update the Distribution please do so in the Hub UI.");
            }
        } catch (final VersionDoesNotExistException e) {
            try {
                final String versionURL = service.createHubVersion(project, projectVersion, getHubVersionPhase(),
                        getHubVersionDist());
                version = service.getProjectVersion(versionURL);
            } catch (final BDRestException e1) {
                if (e1.getResource() != null) {
                    logger.error("Status : " + e1.getResource().getStatus().getCode());
                    logger.error("Response : " + e1.getResource().getResponse().getEntityAsText());
                }
                throw new BDJenkinsHubPluginException("Problem creating the Version. ", e1);
            }
        } catch (final BDRestException e) {
            throw new BDJenkinsHubPluginException("Could not retrieve or create the specified version.", e);
        }
        return version;
    }

    public void printConfiguration(final Node builtOn, final TaskListener listener, final HubJenkinsLogger logger,
            final HubScanJobConfig jobConfig, final String buildDisplayName, final String buildIdentifier,
            final String workspace) throws IOException, InterruptedException {
        logger.alwaysLog("Initializing - Hub Jenkins Plugin - " + PluginHelper.getPluginVersion());

        if (StringUtils.isEmpty(builtOn.getNodeName())) {
            // Empty node name indicates master
            logger.alwaysLog("-> Running on : master");
        } else {
            logger.alwaysLog("Running on : " + builtOn.getNodeName());
        }
        logger.alwaysLog("-> Log Level : " + logger.getLogLevel());
        logger.alwaysLog("-> Using Url : " + getHubServerInfo().getServerUrl());
        logger.alwaysLog("-> Using Username : " + getHubServerInfo().getUsername());
        logger.alwaysLog("-> Using Build Full Name : " + buildDisplayName);
        logger.alwaysLog("-> Using Build Identifier : " + buildIdentifier);
        logger.alwaysLog("-> Using Build Workspace Path : " + workspace);
        logger.alwaysLog(
                "-> Using Hub Project Name : " + jobConfig.getProjectName() + ", Version : " + jobConfig.getVersion());
        logger.alwaysLog("-> Dry Run : " + isDryRun());

        logger.alwaysLog("-> Scanning the following targets  : ");
        for (final String target : jobConfig.getScanTargetPaths()) {
            logger.alwaysLog("-> " + target);
        }

        logger.alwaysLog("-> Generate Hub report : " + jobConfig.isShouldGenerateRiskReport());
        final String formattedTime = String.format("%d minutes", jobConfig.getMaxWaitTimeForBomUpdate());
        logger.alwaysLog("-> Maximum wait time for the BOM Update : " + formattedTime);
    }

    /**
     * Validates that the target of the scanJob exists, creates a ProcessBuilder
     * to run the shellscript and passes in the necessarry arguments, sets the
     * JAVA_HOME of the Process Builder to the one that the User chose, starts
     * the process and prints out all stderr and stdout to the Console Output.
     *
     */
    private Result runScan(final Node builtOn, final JenkinsScanExecutor scan,
            final HubJenkinsLogger logger, final String scanExec, final String javaExec, final String oneJarPath,
            final HubScanJobConfig jobConfig) throws IOException, HubConfigurationException, InterruptedException,
            BDJenkinsHubPluginException, HubIntegrationException, URISyntaxException {
        validateScanTargets(logger, jobConfig.getScanTargetPaths(), jobConfig.getWorkingDirectory(),
                builtOn.getChannel());
        scan.setLogger(logger);
        addProxySettingsToScanner(logger, scan);

        scan.setScanMemory(jobConfig.getScanMemory());
        scan.setWorkingDirectory(jobConfig.getWorkingDirectory());

        scan.setVerboseRun(isVerbose());
        scan.setDryRun(isDryRun());
        if (StringUtils.isNotBlank(jobConfig.getProjectName()) && StringUtils.isNotBlank(jobConfig.getVersion())) {

            scan.setProject(jobConfig.getProjectName());
            scan.setVersion(jobConfig.getVersion());
        }
        final com.blackducksoftware.integration.hub.ScanExecutor.Result result = scan.setupAndRunScan(scanExec,
                oneJarPath, javaExec);
        if (result == com.blackducksoftware.integration.hub.ScanExecutor.Result.SUCCESS) {
            return Result.SUCCESS;
        } else {
            return Result.UNSTABLE;
        }
    }

    public void addProxySettingsToScanner(final IntLogger logger, final JenkinsScanExecutor scan)
            throws BDJenkinsHubPluginException, HubIntegrationException, URISyntaxException, MalformedURLException {
        final Jenkins jenkins = Jenkins.getInstance();
        if (jenkins != null) {
            final ProxyConfiguration proxyConfig = jenkins.proxy;
            if (proxyConfig != null) {

                final URL serverUrl = new URL(getHubServerInfo().getServerUrl());

                final Proxy proxy = ProxyConfiguration.createProxy(serverUrl.getHost(), proxyConfig.name,
                        proxyConfig.port, proxyConfig.noProxyHost);

                if (proxy != Proxy.NO_PROXY && proxy.address() != null) {
                    final InetSocketAddress proxyAddress = (InetSocketAddress) proxy.address();
                    if (StringUtils.isNotBlank(proxyAddress.getHostName()) && proxyAddress.getPort() != 0) {
                        if (StringUtils.isNotBlank(jenkins.proxy.getUserName())
                                && StringUtils.isNotBlank(jenkins.proxy.getPassword())) {
                            scan.setProxyHost(proxyAddress.getHostName());
                            scan.setProxyPort(proxyAddress.getPort());
                            scan.setProxyUsername(jenkins.proxy.getUserName());
                            scan.setProxyPassword(jenkins.proxy.getPassword());

                        } else {
                            scan.setProxyHost(proxyAddress.getHostName());
                            scan.setProxyPort(proxyAddress.getPort());
                        }
                        if (logger != null) {
                            logger.debug("Using proxy: '" + proxyAddress.getHostName() + "' at Port: '"
                                    + proxyAddress.getPort() + "'");
                        }
                    }
                }
            }
        }
    }

    public void addProxySettingsToCLIInstaller(final IntLogger logger, final CLIRemoteInstall remoteCLIInstall)
            throws BDJenkinsHubPluginException, HubIntegrationException, URISyntaxException, MalformedURLException {
        final Jenkins jenkins = Jenkins.getInstance();
        if (jenkins != null) {
            final ProxyConfiguration proxyConfig = jenkins.proxy;
            if (proxyConfig != null) {

                final URL serverUrl = new URL(getHubServerInfo().getServerUrl());

                final Proxy proxy = ProxyConfiguration.createProxy(serverUrl.getHost(), proxyConfig.name,
                        proxyConfig.port, proxyConfig.noProxyHost);

                if (proxy != Proxy.NO_PROXY && proxy.address() != null) {
                    final InetSocketAddress proxyAddress = (InetSocketAddress) proxy.address();
                    if (StringUtils.isNotBlank(proxyAddress.getHostName()) && proxyAddress.getPort() != 0) {
                        if (StringUtils.isNotBlank(jenkins.proxy.getUserName())
                                && StringUtils.isNotBlank(jenkins.proxy.getPassword())) {
                            remoteCLIInstall.setProxyHost(proxyAddress.getHostName());
                            remoteCLIInstall.setProxyPort(proxyAddress.getPort());
                            remoteCLIInstall.setProxyUserName(jenkins.proxy.getUserName());
                            remoteCLIInstall.setProxyPassword(jenkins.proxy.getPassword());

                        } else {
                            remoteCLIInstall.setProxyHost(proxyAddress.getHostName());
                            remoteCLIInstall.setProxyPort(proxyAddress.getPort());
                        }
                        if (logger != null) {
                            logger.debug("Using proxy: '" + proxyAddress.getHostName() + "' at Port: '"
                                    + proxyAddress.getPort() + "'");
                        }
                    }
                }
            }
        }
    }

    public String getScanCLI(final HubJenkinsLogger logger, final Node node, final String toolsDirectory,
            final String localHostName, final EnvVars variables) throws IOException, InterruptedException, Exception {

        if (getHubServerInfo() == null) {
            logger.error("Could not find the Hub server information.");
            return null;
        }
        final CLIRemoteInstall remoteCLIInstall = new CLIRemoteInstall(logger, toolsDirectory, localHostName,
                getHubServerInfo().getServerUrl(), getHubServerInfo().getUsername(), getHubServerInfo().getPassword(),
                getHubServerInfo().getTimeout(), variables);

        addProxySettingsToCLIInstaller(logger, remoteCLIInstall);

        node.getChannel().call(remoteCLIInstall);

        final GetCLIExists cliExists = new GetCLIExists(logger, toolsDirectory);
        FilePath scanExec = null;
        if (node.getChannel().call(cliExists)) {
            final GetCLI getCLi = new GetCLI(logger, toolsDirectory);
            scanExec = new FilePath(node.getChannel(), node.getChannel().call(getCLi));
            logger.debug("Using this BlackDuck scan CLI at : " + scanExec.getRemote());
        } else {
            throw new HubScanToolMissingException("Could not find the CLI file to execute.");
        }
        return scanExec.getRemote();
    }

    public String getJavaExec(final HubJenkinsLogger logger, final Node builtOn, final String toolsDirectory,
            final EnvVars envVars, final String javaHome) throws IOException, InterruptedException, Exception {
        final GetCLIProvidedJRE getProvidedJre = new GetCLIProvidedJRE(toolsDirectory);
        String jrePath = builtOn.getChannel().call(getProvidedJre);

        if (StringUtils.isBlank(jrePath)) {
            FilePath javaExec = new FilePath(builtOn.getChannel(), javaHome);
            javaExec = new FilePath(javaExec, "bin");
            if (builtOn.getChannel().call(new GetIsOsWindows())) {
                javaExec = new FilePath(javaExec, "java.exe");
            } else {
                javaExec = new FilePath(javaExec, "java");
            }

            jrePath = javaExec.getRemote();
        }
        return jrePath;
    }

    public String getOneJarFile(final Node node, final String toolsDirectory)
            throws IOException, InterruptedException, Exception {
        final GetOneJarFile getOneJar = new GetOneJarFile(toolsDirectory);
        return node.getChannel().call(getOneJar);
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

    /**
     * Validates that all scan targets exist
     *
     */
    public boolean validateScanTargets(final IntLogger logger, final List<String> scanTargets,
            final String workingDirectory, final VirtualChannel channel)
            throws IOException, HubConfigurationException, InterruptedException {
        for (final String currTarget : scanTargets) {

            if (currTarget.length() < workingDirectory.length() || !currTarget.startsWith(workingDirectory)) {
                throw new HubConfigurationException("Can not scan targets outside of the workspace.");
            }

            final FilePath currentTargetPath = new FilePath(channel, currTarget);

            if (!currentTargetPath.exists()) {
                throw new IOException("Scan target could not be found : " + currTarget);
            } else {
                logger.debug("Scan target exists at : " + currTarget);
            }
        }
        return true;
    }

    /**
     * @param blackDuckVersion
     *            Version of the blackduck product, in this instance, the hub
     * @param regId
     *            Registration ID of the hub instance that this plugin uses
     * @param hubHostName
     *            Host name of the hub instance that this plugin uses
     *
     *            This method "phones-home" to the internal BlackDuck
     *            Integrations server. Every time a build is kicked off,
     */
    public void bdPhoneHome(final String blackDuckVersion, final String regId, final String hubHostName)
            throws IOException, PhoneHomeException, PropertiesLoaderException, ResourceException, JSONException {
        final String thirdPartyVersion = Jenkins.getVersion().toString();
        final String pluginVersion = PluginHelper.getPluginVersion();

        final PhoneHomeClient phClient = new PhoneHomeClient();
        phClient.callHomeIntegrations(regId, hubHostName, BlackDuckName.HUB, blackDuckVersion, ThirdPartyName.JENKINS,
                thirdPartyVersion, pluginVersion);
    }
}
