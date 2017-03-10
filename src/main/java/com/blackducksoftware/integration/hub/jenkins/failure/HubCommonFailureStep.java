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
import java.net.URISyntaxException;

import com.blackducksoftware.integration.exception.EncryptionException;
import com.blackducksoftware.integration.exception.IntegrationException;
import com.blackducksoftware.integration.hub.HubSupportHelper;
import com.blackducksoftware.integration.hub.exception.HubIntegrationException;
import com.blackducksoftware.integration.hub.jenkins.HubJenkinsLogger;
import com.blackducksoftware.integration.hub.jenkins.HubServerInfo;
import com.blackducksoftware.integration.hub.jenkins.HubServerInfoSingleton;
import com.blackducksoftware.integration.hub.jenkins.action.BomUpToDateAction;
import com.blackducksoftware.integration.hub.jenkins.action.HubVariableContributor;
import com.blackducksoftware.integration.hub.jenkins.exceptions.BDJenkinsHubPluginException;
import com.blackducksoftware.integration.hub.jenkins.helper.BuildHelper;
import com.blackducksoftware.integration.hub.model.enumeration.VersionBomPolicyStatusOverallStatusEnum;
import com.blackducksoftware.integration.hub.model.view.VersionBomPolicyStatusView;
import com.blackducksoftware.integration.hub.service.HubServicesFactory;
import com.blackducksoftware.integration.util.CIEnvironmentVariables;

import hudson.EnvVars;
import hudson.model.Node;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskListener;

public class HubCommonFailureStep {

    private final Boolean failBuildForPolicyViolations;

    private final FailureConditionBuildStateEnum buildStateOnFailure;

    public HubCommonFailureStep(final Boolean failBuildForPolicyViolations, final FailureConditionBuildStateEnum buildStateOnFailure) {
        this.failBuildForPolicyViolations = failBuildForPolicyViolations;
        this.buildStateOnFailure = buildStateOnFailure;
    }

    public Boolean getFailBuildForPolicyViolations() {
        return failBuildForPolicyViolations;
    }

    public FailureConditionBuildStateEnum getBuildStateOnFailure() {
        return buildStateOnFailure;
    }

    public boolean checkFailureConditions(final Run run, final Node builtOn, final EnvVars envVars,
            final HubJenkinsLogger logger, final TaskListener listener, final BomUpToDateAction bomUpToDateAction)
            throws InterruptedException, IOException, IllegalArgumentException, EncryptionException {

        final CIEnvironmentVariables variables = new CIEnvironmentVariables();
        variables.putAll(envVars);
        logger.setLogLevel(variables);

        if (!getFailBuildForPolicyViolations()) {
            logger.error("The Hub failure condition step has not been configured to do anything.");
            run.setResult(Result.UNSTABLE);
            return true;
        }
        Result resultToSetForFailureCondition = Result.SUCCESS;
        if (buildStateOnFailure == FailureConditionBuildStateEnum.UNSTABLE) {
            resultToSetForFailureCondition = Result.UNSTABLE;
        } else if (buildStateOnFailure == FailureConditionBuildStateEnum.FAILURE) {
            resultToSetForFailureCondition = Result.FAILURE;
        }

        final HubServerInfo serverInfo = HubServerInfoSingleton.getInstance().getServerInfo();
        try {
            if (bomUpToDateAction.isDryRun()) {
                logger.warn(
                        "Will not check failure conditions since this was a dry run.");
                return true;
            }
            // We use this conditional in case there are other failure
            // conditions in the future
            if (getFailBuildForPolicyViolations()) {
                if (bomUpToDateAction.getPolicyStatusUrl() == null) {
                    logger.error(
                            "Can not check policy violations, could not find the policy status URL for this Version.");
                    run.setResult(Result.UNSTABLE);
                    return true;
                }
                final HubServicesFactory service = getHubServicesFactory(logger, serverInfo);

                if (!bomUpToDateAction.isHasBomBeenUdpated()) {
                    logger.debug("Waiting for Bom to be updated.");
                    service.createScanStatusDataService(logger, bomUpToDateAction.getMaxWaitTime())
                            .assertBomImportScansFinished(bomUpToDateAction.getScanSummaries());
                }

                final HubSupportHelper hubSupport = new HubSupportHelper();
                hubSupport.checkHubSupport(service.createHubVersionRequestService(), null);

                VersionBomPolicyStatusView policyStatus = null;
                try {
                    policyStatus = service.createHubResponseService().getItem(bomUpToDateAction.getPolicyStatusUrl(), VersionBomPolicyStatusView.class);
                } catch (final HubIntegrationException e) {
                    // ignore exception, could not find policy information
                }
                if (policyStatus == null) {
                    logger.error("Could not find any information about the Policy status of the bom.");
                    return true;
                }

                logger.alwaysLog("--> Configured to set the Build Result to " + buildStateOnFailure.getDisplayValue() + " for Hub Failure Conditions.");
                if (policyStatus.getOverallStatus() == VersionBomPolicyStatusOverallStatusEnum.IN_VIOLATION) {
                    run.setResult(resultToSetForFailureCondition);
                }

                final HubVariableContributor variableContributor = new HubVariableContributor();

                if (policyStatus.getCountInViolation() == null) {
                    logger.error("Could not find the number of bom entries In Violation of a Policy.");
                } else {
                    logger.info("Found " + policyStatus.getCountInViolation().getValue()
                            + " bom entries to be In Violation of a defined Policy.");
                    variableContributor.setBomEntriesInViolation(policyStatus.getCountInViolation().getValue());
                }
                if (policyStatus.getCountInViolationOverridden() == null) {
                    logger.error("Could not find the number of bom entries In Violation Overridden of a Policy.");
                } else {
                    logger.info("Found " + policyStatus.getCountInViolationOverridden().getValue()
                            + " bom entries to be In Violation of a defined Policy, but they have been overridden.");
                    variableContributor.setViolationsOverriden(policyStatus.getCountInViolationOverridden().getValue());
                }
                if (policyStatus.getCountNotInViolation() == null) {
                    logger.error("Could not find the number of bom entries Not In Violation of a Policy.");
                } else {
                    logger.info("Found " + policyStatus.getCountNotInViolation().getValue()
                            + " bom entries to be Not In Violation of a defined Policy.");
                    variableContributor.setBomEntriesNotInViolation(policyStatus.getCountNotInViolation().getValue());
                }
                run.addAction(variableContributor);
            }
        } catch (final BDJenkinsHubPluginException e) {
            logger.error(e.getMessage(), e);
            run.setResult(Result.UNSTABLE);
        } catch (final IntegrationException e) {
            logger.error(e.getMessage(), e);
            run.setResult(Result.UNSTABLE);
        } catch (final URISyntaxException e) {
            logger.error(e.getMessage(), e);
            run.setResult(Result.UNSTABLE);
        }
        return true;
    }

    public HubServicesFactory getHubServicesFactory(final HubJenkinsLogger logger, final HubServerInfo serverInfo)
            throws IOException, URISyntaxException, BDJenkinsHubPluginException,
            HubIntegrationException, IllegalArgumentException, EncryptionException {
        return BuildHelper.getHubServicesFactory(logger, serverInfo.getServerUrl(), serverInfo.getUsername(),
                serverInfo.getPassword(), serverInfo.getTimeout());
    }

}
