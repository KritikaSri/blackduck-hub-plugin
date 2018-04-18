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
import com.blackducksoftware.integration.hub.jenkins.Messages;
import com.blackducksoftware.integration.hub.jenkins.action.BomUpToDateAction;
import com.blackducksoftware.integration.hub.jenkins.action.HubScanFinishedAction;
import com.blackducksoftware.integration.hub.jenkins.exceptions.BDJenkinsHubPluginException;
import com.blackducksoftware.integration.hub.jenkins.failure.FailureConditionBuildStateEnum;
import com.blackducksoftware.integration.hub.jenkins.failure.HubCommonFailureStep;
import com.blackducksoftware.integration.hub.jenkins.scan.BDCommonDescriptorUtil;

import hudson.EnvVars;
import hudson.Extension;
import hudson.model.Computer;
import hudson.model.Node;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;

public class HubFailureConditionWorkflowStep extends AbstractStepImpl {

    private final boolean failBuildForPolicyViolations;

    private final String buildStateOnFailure;

    @DataBoundConstructor
    public HubFailureConditionWorkflowStep(final Boolean failBuildForPolicyViolations, final String buildStateOnFailure) {
        this.failBuildForPolicyViolations = failBuildForPolicyViolations;
        this.buildStateOnFailure = buildStateOnFailure;
    }

    public Boolean getFailBuildForPolicyViolations() {
        return failBuildForPolicyViolations;
    }

    public String getBuildStateOnFailure() {
        return buildStateOnFailure;
    }

    @Override
    public HubFailureConditionWorkflowStepDescriptor getDescriptor() {
        return (HubFailureConditionWorkflowStepDescriptor) super.getDescriptor();
    }

    @Extension(optional = true)
    public static final class HubFailureConditionWorkflowStepDescriptor extends AbstractStepDescriptorImpl {

        public HubFailureConditionWorkflowStepDescriptor() {
            super(Execution.class);
        }

        @Override
        public String getFunctionName() {
            return "hub_scan_failure";
        }

        @Override
        public String getDisplayName() {
            return Messages.HubFailureCondition_getDisplayName();
        }

        public FormValidation doCheckFailBuildForPolicyViolations(
                @QueryParameter("failBuildForPolicyViolations") final boolean failBuildForPolicyViolations)
                throws IOException, ServletException {
            return FormValidation.ok();
        }

        public ListBoxModel doFillBuildStateOnFailureItems() {
            return BDCommonDescriptorUtil.doFillBuildStateOnFailureItems();
        }
    }

    public static final class Execution extends AbstractSynchronousNonBlockingStepExecution<Void> {

        private static final long serialVersionUID = 1L;

        @Inject
        private transient HubFailureConditionWorkflowStep failureConditionStep;

        @StepContextParameter
        transient TaskListener listener;

        @StepContextParameter
        transient EnvVars envVars;

        @StepContextParameter
        private transient Run run;

        @StepContextParameter
        private transient Computer computer;

        @Override
        protected Void run() {
            final HubJenkinsLogger logger = new HubJenkinsLogger(listener);
            try {
                final Node node = computer.getNode();

                final HubCommonFailureStep commonFailureStep = createCommonFailureStep(
                        failureConditionStep.getFailBuildForPolicyViolations(), failureConditionStep.getBuildStateOnFailure());

                if (run.getResult() != Result.SUCCESS) {
                    logger.error("The Build did not run sucessfully, will not check the Hub Failure Conditions.");
                    return null;
                }
                if (run.getAction(HubScanFinishedAction.class) == null) {
                    logger.error("The Hub scan must be configured to run before the Failure Conditions.");
                    run.setResult(Result.UNSTABLE);
                    return null;
                }
                final BomUpToDateAction bomUpToDateAction = run.getAction(BomUpToDateAction.class);
                if (bomUpToDateAction == null) {
                    logger.error(
                            "Could not find the BomUpToDateAction in the Hub Failure Conditions. Make sure the Hub scan was run before the Failure Conditions.");
                    run.setResult(Result.UNSTABLE);
                    return null;
                }
                if (bomUpToDateAction.isDryRun()) {
                    logger.warn("Will not run the Failure conditions because this was a dry run scan.");
                    return null;
                }
                commonFailureStep.checkFailureConditions(run, node, envVars, logger, listener,
                        bomUpToDateAction);
            } catch (final Exception e) {
                logger.error(e);
                run.setResult(Result.UNSTABLE);
            }
            return null;
        }

        public HubCommonFailureStep createCommonFailureStep(final Boolean failBuildForPolicyViolations, final String buildStateOnFailure)
                throws BDJenkinsHubPluginException {
            final FailureConditionBuildStateEnum buildStateOnFailureEnum = FailureConditionBuildStateEnum
                    .getFailureConditionBuildStateEnum(buildStateOnFailure);
            if (buildStateOnFailureEnum == null) {
                throw new BDJenkinsHubPluginException("Invalid Build State on Failure Condition configured : " + buildStateOnFailure);
            }
            return new HubCommonFailureStep(failBuildForPolicyViolations, buildStateOnFailureEnum);
        }

    }

}
