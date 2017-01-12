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
package com.blackducksoftware.integration.hub.jenkins.failure;

import java.io.IOException;

import org.kohsuke.stapler.DataBoundConstructor;

import com.blackducksoftware.integration.hub.jenkins.HubJenkinsLogger;
import com.blackducksoftware.integration.hub.jenkins.action.BomUpToDateAction;
import com.blackducksoftware.integration.hub.jenkins.action.HubScanFinishedAction;
import com.blackducksoftware.integration.hub.jenkins.exceptions.BDJenkinsHubPluginException;

import hudson.EnvVars;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.Result;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Recorder;

public class HubFailureConditionStep extends Recorder {

    private final Boolean failBuildForPolicyViolations;

    private final String buildStateOnFailure;

    @DataBoundConstructor
    public HubFailureConditionStep(final Boolean failBuildForPolicyViolations, final String buildStateOnFailure) {
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
    public BuildStepMonitor getRequiredMonitorService() {
        return BuildStepMonitor.NONE;
    }

    @Override
    public HubFailureConditionStepDescriptor getDescriptor() {
        return (HubFailureConditionStepDescriptor) super.getDescriptor();
    }

    @Override
    public boolean perform(final AbstractBuild<?, ?> build, final Launcher launcher, final BuildListener listener)
            throws InterruptedException, IOException {
        final HubJenkinsLogger logger = new HubJenkinsLogger(listener);
        try {
            final EnvVars envVars = build.getEnvironment(listener);

            if (build.getResult() != Result.SUCCESS) {
                logger.error("The Build did not run sucessfully, will not check the Hub Failure Conditions.");
                return true;
            }
            if (build.getAction(HubScanFinishedAction.class) == null) {
                logger.error("The Hub scan must be configured to run before the Failure Conditions.");
                build.setResult(Result.UNSTABLE);
                return true;
            }

            final BomUpToDateAction bomUpToDateAction = build.getAction(BomUpToDateAction.class);
            if (bomUpToDateAction == null) {
                logger.error(
                        "Could not find the BomUpToDateAction in the Hub Failure Conditions. Make sure the Hub scan was run before the Failure Conditions.");
                build.setResult(Result.UNSTABLE);
                return true;
            }
            if (bomUpToDateAction.isDryRun()) {
                logger.warn("Will not run the Failure conditions because this was a dry run scan.");
                return true;
            }

            final HubCommonFailureStep commonFailureStep = createCommonFailureStep(getFailBuildForPolicyViolations(), getBuildStateOnFailure());
            commonFailureStep.checkFailureConditions(build, build.getBuiltOn(), envVars, logger,
                    listener,
                    bomUpToDateAction);
        } catch (final Exception e) {
            logger.error(e);
            build.setResult(Result.UNSTABLE);
        }
        return true;
    }

    public HubCommonFailureStep createCommonFailureStep(final Boolean failBuildForPolicyViolations, final String buildStateOnFailure)
            throws BDJenkinsHubPluginException {
        final FailureConditionBuildStateEnum buildStateOnFailureEnum = FailureConditionBuildStateEnum.getFailureConditionBuildStateEnum(buildStateOnFailure);
        if (buildStateOnFailureEnum == null) {
            throw new BDJenkinsHubPluginException("Invalid Build State on Failure Condition configured : " + buildStateOnFailure);
        }
        return new HubCommonFailureStep(failBuildForPolicyViolations, buildStateOnFailureEnum);
    }

}
