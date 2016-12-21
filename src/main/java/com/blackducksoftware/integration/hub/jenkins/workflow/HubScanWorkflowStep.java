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
package com.blackducksoftware.integration.hub.jenkins.workflow;

import java.io.IOException;

import javax.inject.Inject;
import javax.servlet.ServletException;

import org.jenkinsci.plugins.workflow.steps.AbstractStepDescriptorImpl;
import org.jenkinsci.plugins.workflow.steps.AbstractStepImpl;
import org.jenkinsci.plugins.workflow.steps.AbstractSynchronousNonBlockingStepExecution;
import org.jenkinsci.plugins.workflow.steps.StepContextParameter;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import com.blackducksoftware.integration.hub.jenkins.HubJenkinsLogger;
import com.blackducksoftware.integration.hub.jenkins.HubServerInfo;
import com.blackducksoftware.integration.hub.jenkins.HubServerInfoSingleton;
import com.blackducksoftware.integration.hub.jenkins.Messages;
import com.blackducksoftware.integration.hub.jenkins.ScanJobs;
import com.blackducksoftware.integration.hub.jenkins.scan.BDCommonDescriptorUtil;
import com.blackducksoftware.integration.hub.jenkins.scan.BDCommonScanStep;

import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AutoCompletionCandidates;
import hudson.model.Computer;
import hudson.model.Node;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;

public class HubScanWorkflowStep extends AbstractStepImpl {

    private final ScanJobs[] scans;

    private final String hubProjectName;

    private final String hubProjectVersion;

    private final String scanMemory;

    private final boolean shouldGenerateHubReport;

    private final String bomUpdateMaxiumWaitTime;

    private final boolean dryRun;

    private Boolean verbose;

    @DataBoundConstructor
    public HubScanWorkflowStep(final ScanJobs[] scans, final String hubProjectName, final String hubProjectVersion,
            final String scanMemory,
            final boolean shouldGenerateHubReport, final String bomUpdateMaxiumWaitTime, final boolean dryRun) {
        this.scans = scans;
        this.hubProjectName = hubProjectName;
        this.hubProjectVersion = hubProjectVersion;
        this.scanMemory = scanMemory;
        this.shouldGenerateHubReport = shouldGenerateHubReport;
        this.bomUpdateMaxiumWaitTime = bomUpdateMaxiumWaitTime;
        this.dryRun = dryRun;
    }

    public void setVerbose(final boolean verbose) {
        this.verbose = verbose;
    }

    public boolean isVerbose() {
        if (verbose == null) {
            verbose = true;
        }
        return verbose;
    }

    public ScanJobs[] getScans() {
        return scans;
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

    public boolean getShouldGenerateHubReport() {
        return shouldGenerateHubReport;
    }

    public String getBomUpdateMaxiumWaitTime() {
        return bomUpdateMaxiumWaitTime;
    }

    public boolean isDryRun() {
        return dryRun;
    }

    @Override
    public HubScanWorkflowStepDescriptor getDescriptor() {
        return (HubScanWorkflowStepDescriptor) super.getDescriptor();
    }

    @Extension(optional = true)
    public static final class HubScanWorkflowStepDescriptor extends AbstractStepDescriptorImpl {

        public HubScanWorkflowStepDescriptor() {
            super(Execution.class);
        }

        @Override
        public String getFunctionName() {
            return "hub_scan";
        }

        @Override
        public String getDisplayName() {
            return Messages.HubBuildScan_getDisplayName();
        }

        /**
         * @return the hubServerInfo
         */
        public HubServerInfo getHubServerInfo() {
            return HubServerInfoSingleton.getInstance().getServerInfo();
        }

        public FormValidation doCheckScanMemory(@QueryParameter("scanMemory") final String scanMemory)
                throws IOException, ServletException {
            return BDCommonDescriptorUtil.doCheckScanMemory(scanMemory);
        }

        public FormValidation doCheckBomUpdateMaxiumWaitTime(
                @QueryParameter("bomUpdateMaxiumWaitTime") final String bomUpdateMaxiumWaitTime)
                throws IOException, ServletException {
            return BDCommonDescriptorUtil.doCheckBomUpdateMaxiumWaitTime(bomUpdateMaxiumWaitTime);
        }

        /**
         * Fills the Credential drop down list in the global config
         *
         * @return
         */
        public ListBoxModel doFillHubCredentialsIdItems() {
            return BDCommonDescriptorUtil.doFillCredentialsIdItems();
        }

        /**
         * Fills the drop down list of possible Version phases
         *
         */
        public ListBoxModel doFillHubVersionPhaseItems() {
            return BDCommonDescriptorUtil.doFillHubVersionPhaseItems();
        }

        /**
         * Fills the drop down list of possible Version distribution types
         *
         */
        public ListBoxModel doFillHubVersionDistItems() {
            return BDCommonDescriptorUtil.doFillHubVersionDistItems();
        }

        public AutoCompletionCandidates doAutoCompleteHubProjectName(
                @QueryParameter("value") final String hubProjectName) throws IOException, ServletException {
            return BDCommonDescriptorUtil.doAutoCompleteHubProjectName(getHubServerInfo(), hubProjectName);
        }

        /**
         * Performs on-the-fly validation of the form field 'hubProjectName'.
         * Checks to see if there is already a project in the Hub with this
         * name.
         *
         */
        public FormValidation doCheckHubProjectName(@QueryParameter("hubProjectName") final String hubProjectName,
                @QueryParameter("hubProjectVersion") final String hubProjectVersion,
                @QueryParameter("dryRun") final boolean dryRun) throws IOException, ServletException {
            return BDCommonDescriptorUtil.doCheckHubProjectName(getHubServerInfo(), hubProjectName, hubProjectVersion,
                    dryRun);
        }

    }

    public static final class Execution extends AbstractSynchronousNonBlockingStepExecution<Void> {

        private static final long serialVersionUID = 1L;

        @Inject
        private transient HubScanWorkflowStep hubScanStep;

        @StepContextParameter
        private transient Computer computer;

        @StepContextParameter
        transient Launcher launcher;

        @StepContextParameter
        transient TaskListener listener;

        @StepContextParameter
        transient EnvVars envVars;

        @StepContextParameter
        private transient FilePath workspace;

        @StepContextParameter
        private transient Run run;

        @Override
        protected Void run() {
            final HubJenkinsLogger logger = new HubJenkinsLogger(listener);
            try {
                final Node node = computer.getNode();
                final BDCommonScanStep scanStep = new BDCommonScanStep(hubScanStep.getScans(),
                        hubScanStep.getHubProjectName(), hubScanStep.getHubProjectVersion(),
                        hubScanStep.getScanMemory(),
                        hubScanStep.getShouldGenerateHubReport(), hubScanStep.getBomUpdateMaxiumWaitTime(),
                        hubScanStep.isDryRun(), hubScanStep.isVerbose());

                scanStep.runScan(run, node, envVars, workspace, logger, launcher, listener,
                        run.getFullDisplayName(),
                        String.valueOf(run.getNumber()));

            } catch (final Exception e) {
                logger.error(e);
                run.setResult(Result.UNSTABLE);
            }
            return null;
        }

    }
}
