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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.mockito.Mockito;

import com.blackducksoftware.integration.hub.HubIntRestService;
import com.blackducksoftware.integration.hub.HubSupportHelper;
import com.blackducksoftware.integration.hub.api.HubVersionRestService;
import com.blackducksoftware.integration.hub.api.policy.ComponentVersionStatusCount;
import com.blackducksoftware.integration.hub.api.policy.PolicyStatusEnum;
import com.blackducksoftware.integration.hub.api.policy.PolicyStatusItem;
import com.blackducksoftware.integration.hub.api.policy.PolicyStatusRestService;
import com.blackducksoftware.integration.hub.dataservices.DataServicesFactory;
import com.blackducksoftware.integration.hub.jenkins.HubJenkinsLogger;
import com.blackducksoftware.integration.hub.jenkins.HubServerInfo;
import com.blackducksoftware.integration.hub.jenkins.HubServerInfoSingleton;
import com.blackducksoftware.integration.hub.jenkins.PostBuildHubScan;
import com.blackducksoftware.integration.hub.jenkins.action.BomUpToDateAction;
import com.blackducksoftware.integration.hub.jenkins.action.HubScanFinishedAction;
import com.blackducksoftware.integration.hub.jenkins.mock.TestBuild;
import com.blackducksoftware.integration.hub.jenkins.mock.TestProject;
import com.blackducksoftware.integration.hub.jenkins.utils.TestBuildListener;

import hudson.model.Result;
import hudson.tasks.ArtifactArchiver;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Publisher;

public class HubFailureConditionStepUnitTest {

    @Rule
    public static JenkinsRule j = new JenkinsRule();

    private DataServicesFactory getMockedService(final String returnVersion, final PolicyStatusItem status)
            throws Exception {
        final DataServicesFactory service = Mockito.mock(DataServicesFactory.class);

        HubVersionRestService versionService = Mockito.mock(HubVersionRestService.class);
        PolicyStatusRestService policyService = Mockito.mock(PolicyStatusRestService.class);

        Mockito.doReturn(returnVersion).when(versionService).getHubVersion();
        Mockito.doReturn(status).when(policyService).getItem(Mockito.anyString());

        Mockito.doReturn(versionService).when(service).getHubVersionRestService();
        Mockito.doReturn(policyService).when(service).getPolicyStatusRestService();

        return service;
    }

    private HubIntRestService getMockedIntRestService() throws Exception {

        return Mockito.mock(HubIntRestService.class);
    }

    @WithoutJenkins
    @Test
    public void testConstructor() {
        Boolean failBuildForPolicyViolations = false;
        HubFailureConditionStep failureStep = new HubFailureConditionStep(failBuildForPolicyViolations);

        assertEquals(failBuildForPolicyViolations, failureStep.getFailBuildForPolicyViolations());

        failBuildForPolicyViolations = true;
        failureStep = new HubFailureConditionStep(failBuildForPolicyViolations);

        assertEquals(failBuildForPolicyViolations, failureStep.getFailBuildForPolicyViolations());
    }

    @WithoutJenkins
    @Test
    public void testGetRequiredMonitorService() {
        final Boolean failBuildForPolicyViolations = false;
        final HubFailureConditionStep failureStep = new HubFailureConditionStep(failBuildForPolicyViolations);

        assertEquals(BuildStepMonitor.NONE, failureStep.getRequiredMonitorService());
    }

    @Test
    public void testGetDescriptor() {
        final Boolean failBuildForPolicyViolations = false;
        final HubFailureConditionStep failureStep = new HubFailureConditionStep(failBuildForPolicyViolations);

        assertNotNull(failureStep.getDescriptor());
    }

    @Test
    public void testPerformBuildNotSuccessful() throws Exception {
        final Boolean failBuildForPolicyViolations = false;
        final HubFailureConditionStep failureStep = new HubFailureConditionStep(failBuildForPolicyViolations);

        final TestProject project = new TestProject(j.getInstance(), "Test Project");
        final TestBuild build = new TestBuild(project);

        // Test Build Unstable
        build.setResult(Result.UNSTABLE);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream stream = new PrintStream(baos);
        TestBuildListener listener = new TestBuildListener(stream);

        failureStep.perform(build, null, listener);

        String output = baos.toString();
        assertTrue(output,
                output.contains("The Build did not run sucessfully, will not check the Hub Failure Conditions."));

        // Test Build Failure
        build.setResult(Result.FAILURE);

        baos = new ByteArrayOutputStream();
        stream = new PrintStream(baos);
        listener = new TestBuildListener(stream);

        failureStep.perform(build, null, listener);

        output = baos.toString();
        assertTrue(output,
                output.contains("The Build did not run sucessfully, will not check the Hub Failure Conditions."));

        // Test Aborted
        build.setResult(Result.ABORTED);

        baos = new ByteArrayOutputStream();
        stream = new PrintStream(baos);
        listener = new TestBuildListener(stream);

        failureStep.perform(build, null, listener);

        output = baos.toString();
        assertTrue(output,
                output.contains("The Build did not run sucessfully, will not check the Hub Failure Conditions."));

        // Test NotBuilt
        build.setResult(Result.NOT_BUILT);

        baos = new ByteArrayOutputStream();
        stream = new PrintStream(baos);
        listener = new TestBuildListener(stream);

        failureStep.perform(build, null, listener);

        output = baos.toString();
        assertTrue(output,
                output.contains("The Build did not run sucessfully, will not check the Hub Failure Conditions."));
    }

    @Test
    public void testPerformNoPublishers() throws Exception {
        final Boolean failBuildForPolicyViolations = false;
        final HubFailureConditionStep failureStep = new HubFailureConditionStep(failBuildForPolicyViolations);

        final TestProject project = new TestProject(j.getInstance(), "Test Project");
        final TestBuild build = new TestBuild(project);
        build.setResult(Result.SUCCESS);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream stream = new PrintStream(baos);
        TestBuildListener listener = new TestBuildListener(stream);

        failureStep.perform(build, null, listener);

        String output = baos.toString();
        assertTrue(output, output.contains("The Hub scan must be configured to run before the Failure Conditions."));
        assertEquals(Result.UNSTABLE, build.getResult());

        build.setResult(Result.SUCCESS);

        project.setPublishersList(new ArrayList<Publisher>());

        baos = new ByteArrayOutputStream();
        stream = new PrintStream(baos);
        listener = new TestBuildListener(stream);

        failureStep.perform(build, null, listener);

        output = baos.toString();
        assertTrue(output, output.contains("The Hub scan must be configured to run before the Failure Conditions."));
        assertEquals(Result.UNSTABLE, build.getResult());
    }

    @Test
    public void testPerformNoHubScanStep() throws Exception {
        final Boolean failBuildForPolicyViolations = false;
        final HubFailureConditionStep failureStep = new HubFailureConditionStep(failBuildForPolicyViolations);

        final TestProject project = new TestProject(j.getInstance(), "Test Project");
        final TestBuild build = new TestBuild(project);
        build.setResult(Result.SUCCESS);
        final List<Publisher> publishers = new ArrayList<Publisher>();
        final ArtifactArchiver publisher = new ArtifactArchiver("");
        publishers.add(publisher);
        project.setPublishersList(publishers);

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final PrintStream stream = new PrintStream(baos);
        final TestBuildListener listener = new TestBuildListener(stream);

        failureStep.perform(build, null, listener);

        final String output = baos.toString();
        assertTrue(output, output.contains("The Hub scan must be configured to run before the Failure Conditions."));
        assertEquals(Result.UNSTABLE, build.getResult());
    }

    @Test
    public void testPerformOutOfOrder() throws Exception {
        final Boolean failBuildForPolicyViolations = false;
        final HubFailureConditionStep failureStep = new HubFailureConditionStep(failBuildForPolicyViolations);

        final TestProject project = new TestProject(j.getInstance(), "Test Project");
        final TestBuild build = new TestBuild(project);
        build.setResult(Result.SUCCESS);
        final List<Publisher> publishers = new ArrayList<Publisher>();
        final PostBuildHubScan hubScanStep = new PostBuildHubScan(null, null, null, null, null, null, false, null,
                false);
        publishers.add(hubScanStep);
        project.setPublishersList(publishers);

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final PrintStream stream = new PrintStream(baos);
        final TestBuildListener listener = new TestBuildListener(stream);

        failureStep.perform(build, null, listener);

        final String output = baos.toString();
        assertTrue(output, output.contains("The Hub scan must be configured to run before the Failure Conditions."));
        assertEquals(Result.UNSTABLE, build.getResult());

    }

    @Test
    public void testPerformNoFailureConditionSet() throws Exception {
        final Boolean failBuildForPolicyViolations = false;
        final HubFailureConditionStep failureStep = new HubFailureConditionStep(failBuildForPolicyViolations);

        final TestProject project = new TestProject(j.getInstance(), "Test Project");
        final TestBuild build = new TestBuild(project);
        build.setResult(Result.SUCCESS);
        final List<Publisher> publishers = new ArrayList<Publisher>();
        final PostBuildHubScan hubScanStep = new PostBuildHubScan(null, null, null, null, null, null, false, null,
                false);
        publishers.add(hubScanStep);
        project.setPublishersList(publishers);
        build.setScanFinishedAction(new HubScanFinishedAction());
        final BomUpToDateAction bomUpdatedAction = new BomUpToDateAction();
        bomUpdatedAction.setHasBomBeenUdpated(true);
        build.setBomUpdatedAction(bomUpdatedAction);

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final PrintStream stream = new PrintStream(baos);
        final TestBuildListener listener = new TestBuildListener(stream);

        failureStep.perform(build, null, listener);

        final String output = baos.toString();
        assertTrue(output, output.contains("The Hub failure condition step has not been configured to do anything."));
        assertEquals(Result.UNSTABLE, build.getResult());
    }

    @Test
    public void testPerformValidUnknownCountsNoPolicyLink() throws Exception {
        final Boolean failBuildForPolicyViolations = true;
        HubCommonFailureStep commonFailureStep = new HubCommonFailureStep(failBuildForPolicyViolations);
        commonFailureStep = Mockito.spy(commonFailureStep);

        HubFailureConditionStep failureStep = new HubFailureConditionStep(failBuildForPolicyViolations);
        HubFailureConditionStepDescriptor descriptor = failureStep.getDescriptor();
        failureStep = Mockito.spy(failureStep);
        final ComponentVersionStatusCount countsUnknown = new ComponentVersionStatusCount(PolicyStatusEnum.UNKNOWN, 0);
        final List<ComponentVersionStatusCount> counts = new ArrayList<ComponentVersionStatusCount>();
        counts.add(countsUnknown);

        final PolicyStatusItem policyStatus = new PolicyStatusItem(PolicyStatusEnum.NOT_IN_VIOLATION, null, counts,
                null);
        final DataServicesFactory service = getMockedService("3.0.0", policyStatus);

        final HubServerInfo serverInfo = new HubServerInfo("Fake Server", "Fake Creds", 499);
        HubServerInfoSingleton.getInstance().setServerInfo(serverInfo);

        final HubSupportHelper hubSupport = new HubSupportHelper();
        hubSupport.checkHubSupport(service.getHubVersionRestService(), null);
        Mockito.doReturn(service).when(commonFailureStep).getDataServices(Mockito.any(HubJenkinsLogger.class), Mockito.any(HubServerInfo.class));

        descriptor = Mockito.spy(descriptor);

        Mockito.doReturn(hubSupport).when(commonFailureStep).getCheckedHubSupportHelper();
        Mockito.doReturn(getMockedIntRestService()).when(commonFailureStep).getHubIntRestService(Mockito.any(HubJenkinsLogger.class),
                Mockito.any(HubServerInfo.class));
        Mockito.doReturn(descriptor).when(failureStep).getDescriptor();
        Mockito.doReturn(commonFailureStep).when(failureStep).createCommonFailureStep(Mockito.anyBoolean());

        final TestProject project = new TestProject(j.getInstance(), "Test Project");
        final TestBuild build = new TestBuild(project);
        build.setResult(Result.SUCCESS);
        final List<Publisher> publishers = new ArrayList<Publisher>();
        final PostBuildHubScan hubScanStep = new PostBuildHubScan(null, null, "VerisonName", null, null, null, false,
                null, false);
        publishers.add(hubScanStep);
        project.setPublishersList(publishers);
        build.setScanFinishedAction(new HubScanFinishedAction());
        final BomUpToDateAction bomUpdatedAction = new BomUpToDateAction();
        bomUpdatedAction.setHasBomBeenUdpated(true);
        build.setBomUpdatedAction(bomUpdatedAction);

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final PrintStream stream = new PrintStream(baos);
        final TestBuildListener listener = new TestBuildListener(stream);

        failureStep.perform(build, null, listener);

        final String output = baos.toString();
        assertTrue(output, output
                .contains("Can not check policy violations, could not find the policy status URL for this Version."));
        assertEquals(Result.UNSTABLE, build.getResult());
    }

    @Test
    public void testPerformValidUnknownCounts() throws Exception {
        final Boolean failBuildForPolicyViolations = true;
        HubCommonFailureStep commonFailureStep = new HubCommonFailureStep(failBuildForPolicyViolations);
        commonFailureStep = Mockito.spy(commonFailureStep);

        HubFailureConditionStep failureStep = new HubFailureConditionStep(failBuildForPolicyViolations);
        HubFailureConditionStepDescriptor descriptor = failureStep.getDescriptor();
        failureStep = Mockito.spy(failureStep);
        final ComponentVersionStatusCount countsUnknown = new ComponentVersionStatusCount(PolicyStatusEnum.UNKNOWN, 0);
        final List<ComponentVersionStatusCount> counts = new ArrayList<ComponentVersionStatusCount>();
        counts.add(countsUnknown);

        final PolicyStatusItem policyStatus = new PolicyStatusItem(PolicyStatusEnum.NOT_IN_VIOLATION, null, counts,
                null);
        final DataServicesFactory service = getMockedService("3.0.0", policyStatus);

        final HubServerInfo serverInfo = new HubServerInfo("Fake Server", "Fake Creds", 499);
        HubServerInfoSingleton.getInstance().setServerInfo(serverInfo);

        final HubSupportHelper hubSupport = new HubSupportHelper();
        hubSupport.checkHubSupport(service.getHubVersionRestService(), null);
        Mockito.doReturn(service).when(commonFailureStep).getDataServices(Mockito.any(HubJenkinsLogger.class), Mockito.any(HubServerInfo.class));

        descriptor = Mockito.spy(descriptor);

        Mockito.doReturn(hubSupport).when(commonFailureStep).getCheckedHubSupportHelper();
        Mockito.doReturn(getMockedIntRestService()).when(commonFailureStep).getHubIntRestService(Mockito.any(HubJenkinsLogger.class),
                Mockito.any(HubServerInfo.class));
        Mockito.doReturn(descriptor).when(failureStep).getDescriptor();
        Mockito.doReturn(commonFailureStep).when(failureStep).createCommonFailureStep(Mockito.anyBoolean());

        final TestProject project = new TestProject(j.getInstance(), "Test Project");
        final TestBuild build = new TestBuild(project);
        build.setResult(Result.SUCCESS);
        final List<Publisher> publishers = new ArrayList<Publisher>();
        final PostBuildHubScan hubScanStep = new PostBuildHubScan(null, null, "VerisonName", null, null, null, false,
                null, false);
        publishers.add(hubScanStep);
        project.setPublishersList(publishers);
        build.setScanFinishedAction(new HubScanFinishedAction());
        final BomUpToDateAction bomUpdatedAction = new BomUpToDateAction();
        bomUpdatedAction.setPolicyStatusUrl("URL");
        bomUpdatedAction.setHasBomBeenUdpated(true);
        build.setBomUpdatedAction(bomUpdatedAction);

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final PrintStream stream = new PrintStream(baos);
        final TestBuildListener listener = new TestBuildListener(stream);

        failureStep.perform(build, null, listener);

        final String output = baos.toString();
        assertTrue(output, output.contains("Could not find the number of bom entries In Violation of a Policy."));
        assertTrue(output,
                output.contains("Could not find the number of bom entries In Violation Overridden of a Policy."));
        assertTrue(output, output.contains("Could not find the number of bom entries Not In Violation of a Policy."));
        assertEquals(Result.SUCCESS, build.getResult());
    }

    @Test
    public void testPerformValidNoViolation() throws Exception {
        final Boolean failBuildForPolicyViolations = true;
        HubCommonFailureStep commonFailureStep = new HubCommonFailureStep(failBuildForPolicyViolations);
        commonFailureStep = Mockito.spy(commonFailureStep);

        HubFailureConditionStep failureStep = new HubFailureConditionStep(failBuildForPolicyViolations);
        HubFailureConditionStepDescriptor descriptor = failureStep.getDescriptor();
        failureStep = Mockito.spy(failureStep);
        final ComponentVersionStatusCount countsInViolation = new ComponentVersionStatusCount(
                PolicyStatusEnum.IN_VIOLATION, 0);
        final ComponentVersionStatusCount countsNotInViolation = new ComponentVersionStatusCount(
                PolicyStatusEnum.IN_VIOLATION_OVERRIDDEN, 12);
        final ComponentVersionStatusCount countsInViolationOverridden = new ComponentVersionStatusCount(
                PolicyStatusEnum.NOT_IN_VIOLATION, 45);
        final List<ComponentVersionStatusCount> counts = new ArrayList<ComponentVersionStatusCount>();
        counts.add(countsInViolationOverridden);
        counts.add(countsInViolation);
        counts.add(countsNotInViolation);

        final PolicyStatusItem policyStatus = new PolicyStatusItem(PolicyStatusEnum.NOT_IN_VIOLATION, null, counts,
                null);
        final DataServicesFactory service = getMockedService("3.0.0", policyStatus);
        final HubServerInfo serverInfo = new HubServerInfo("Fake Server", "Fake Creds", 499);
        HubServerInfoSingleton.getInstance().setServerInfo(serverInfo);

        final HubSupportHelper hubSupport = new HubSupportHelper();
        hubSupport.checkHubSupport(service.getHubVersionRestService(), null);
        Mockito.doReturn(service).when(commonFailureStep).getDataServices(Mockito.any(HubJenkinsLogger.class), Mockito.any(HubServerInfo.class));

        descriptor = Mockito.spy(descriptor);

        Mockito.doReturn(hubSupport).when(commonFailureStep).getCheckedHubSupportHelper();
        Mockito.doReturn(getMockedIntRestService()).when(commonFailureStep).getHubIntRestService(Mockito.any(HubJenkinsLogger.class),
                Mockito.any(HubServerInfo.class));
        Mockito.doReturn(descriptor).when(failureStep).getDescriptor();
        Mockito.doReturn(commonFailureStep).when(failureStep).createCommonFailureStep(Mockito.anyBoolean());

        final TestProject project = new TestProject(j.getInstance(), "Test Project");
        final TestBuild build = new TestBuild(project);
        build.setResult(Result.SUCCESS);
        final List<Publisher> publishers = new ArrayList<Publisher>();
        final PostBuildHubScan hubScanStep = new PostBuildHubScan(null, null, "VerisonName", null, null, null, false,
                null, false);
        publishers.add(hubScanStep);
        project.setPublishersList(publishers);
        build.setScanFinishedAction(new HubScanFinishedAction());
        final BomUpToDateAction bomUpdatedAction = new BomUpToDateAction();
        bomUpdatedAction.setPolicyStatusUrl("URL");
        bomUpdatedAction.setHasBomBeenUdpated(true);
        build.setBomUpdatedAction(bomUpdatedAction);

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final PrintStream stream = new PrintStream(baos);
        final TestBuildListener listener = new TestBuildListener(stream);

        failureStep.perform(build, null, listener);

        final String output = baos.toString();
        assertTrue(output, output.contains("Found " + policyStatus.getCountInViolation().getValue()
                + " bom entries to be In Violation of a defined Policy."));
        assertTrue(output, output.contains("Found " + policyStatus.getCountInViolationOverridden().getValue()
                + " bom entries to be In Violation of a defined Policy, but they have been overridden."));
        assertTrue(output, output.contains("Found " + policyStatus.getCountNotInViolation().getValue()
                + " bom entries to be Not In Violation of a defined Policy."));
        assertEquals(Result.SUCCESS, build.getResult());
    }

    @Test
    public void testPerformValidWithViolations() throws Exception {
        final Boolean failBuildForPolicyViolations = true;
        HubCommonFailureStep commonFailureStep = new HubCommonFailureStep(failBuildForPolicyViolations);
        commonFailureStep = Mockito.spy(commonFailureStep);

        HubFailureConditionStep failureStep = new HubFailureConditionStep(failBuildForPolicyViolations);
        HubFailureConditionStepDescriptor descriptor = failureStep.getDescriptor();
        failureStep = Mockito.spy(failureStep);

        final ComponentVersionStatusCount countsInViolation = new ComponentVersionStatusCount(
                PolicyStatusEnum.IN_VIOLATION, 3);
        final ComponentVersionStatusCount countsNotInViolation = new ComponentVersionStatusCount(
                PolicyStatusEnum.IN_VIOLATION_OVERRIDDEN, 12);
        final ComponentVersionStatusCount countsInViolationOverridden = new ComponentVersionStatusCount(
                PolicyStatusEnum.NOT_IN_VIOLATION, 45);
        final List<ComponentVersionStatusCount> counts = new ArrayList<ComponentVersionStatusCount>();
        counts.add(countsInViolationOverridden);
        counts.add(countsInViolation);
        counts.add(countsNotInViolation);
        final PolicyStatusItem policyStatus = new PolicyStatusItem(PolicyStatusEnum.IN_VIOLATION, null, counts, null);
        final DataServicesFactory service = getMockedService("3.0.0", policyStatus);

        final HubServerInfo serverInfo = new HubServerInfo("Fake Server", "Fake Creds", 499);
        HubServerInfoSingleton.getInstance().setServerInfo(serverInfo);

        final HubSupportHelper hubSupport = new HubSupportHelper();
        hubSupport.checkHubSupport(service.getHubVersionRestService(), null);
        Mockito.doReturn(service).when(commonFailureStep).getDataServices(Mockito.any(HubJenkinsLogger.class), Mockito.any(HubServerInfo.class));

        descriptor = Mockito.spy(descriptor);

        Mockito.doReturn(hubSupport).when(commonFailureStep).getCheckedHubSupportHelper();
        Mockito.doReturn(getMockedIntRestService()).when(commonFailureStep).getHubIntRestService(Mockito.any(HubJenkinsLogger.class),
                Mockito.any(HubServerInfo.class));
        Mockito.doReturn(descriptor).when(failureStep).getDescriptor();
        Mockito.doReturn(commonFailureStep).when(failureStep).createCommonFailureStep(Mockito.anyBoolean());

        final TestProject project = new TestProject(j.getInstance(), "Test Project");
        final TestBuild build = new TestBuild(project);
        build.setResult(Result.SUCCESS);
        final List<Publisher> publishers = new ArrayList<Publisher>();
        final PostBuildHubScan hubScanStep = new PostBuildHubScan(null, null, "VerisonName", null, null, null, false,
                null, false);
        publishers.add(hubScanStep);
        project.setPublishersList(publishers);
        build.setScanFinishedAction(new HubScanFinishedAction());
        final BomUpToDateAction bomUpdatedAction = new BomUpToDateAction();
        bomUpdatedAction.setPolicyStatusUrl("URL");
        bomUpdatedAction.setHasBomBeenUdpated(true);
        build.setBomUpdatedAction(bomUpdatedAction);

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final PrintStream stream = new PrintStream(baos);
        final TestBuildListener listener = new TestBuildListener(stream);

        failureStep.perform(build, null, listener);

        final String output = baos.toString();
        assertTrue(output, output.contains("Found " + policyStatus.getCountInViolation().getValue()
                + " bom entries to be In Violation of a defined Policy."));
        assertTrue(output, output.contains("Found " + policyStatus.getCountInViolationOverridden().getValue()
                + " bom entries to be In Violation of a defined Policy, but they have been overridden."));
        assertTrue(output, output.contains("Found " + policyStatus.getCountNotInViolation().getValue()
                + " bom entries to be Not In Violation of a defined Policy."));
        assertEquals(Result.FAILURE, build.getResult());
    }

    @Test
    public void testPerformDryRun() throws Exception {
        final Boolean failBuildForPolicyViolations = true;
        HubCommonFailureStep commonFailureStep = new HubCommonFailureStep(failBuildForPolicyViolations);
        commonFailureStep = Mockito.spy(commonFailureStep);

        HubFailureConditionStep failureStep = new HubFailureConditionStep(failBuildForPolicyViolations);
        HubFailureConditionStepDescriptor descriptor = failureStep.getDescriptor();
        failureStep = Mockito.spy(failureStep);

        final DataServicesFactory service = getMockedService("3.0.0", null);

        final HubServerInfo serverInfo = new HubServerInfo("Fake Server", "Fake Creds", 499);
        HubServerInfoSingleton.getInstance().setServerInfo(serverInfo);

        final HubSupportHelper hubSupport = new HubSupportHelper();
        hubSupport.checkHubSupport(service.getHubVersionRestService(), null);
        Mockito.doReturn(service).when(commonFailureStep).getDataServices(Mockito.any(HubJenkinsLogger.class), Mockito.any(HubServerInfo.class));

        descriptor = Mockito.spy(descriptor);

        Mockito.doReturn(hubSupport).when(commonFailureStep).getCheckedHubSupportHelper();
        Mockito.doReturn(getMockedIntRestService()).when(commonFailureStep).getHubIntRestService(Mockito.any(HubJenkinsLogger.class),
                Mockito.any(HubServerInfo.class));
        Mockito.doReturn(descriptor).when(failureStep).getDescriptor();
        Mockito.doReturn(commonFailureStep).when(failureStep).createCommonFailureStep(Mockito.anyBoolean());

        final TestProject project = new TestProject(j.getInstance(), "Test Project");
        final TestBuild build = new TestBuild(project);
        build.setResult(Result.SUCCESS);
        final List<Publisher> publishers = new ArrayList<Publisher>();
        final PostBuildHubScan hubScanStep = new PostBuildHubScan(null, null, "VerisonName", null, null, null, false,
                null, false);
        publishers.add(hubScanStep);
        project.setPublishersList(publishers);
        build.setScanFinishedAction(new HubScanFinishedAction());
        final BomUpToDateAction bomUpdatedAction = new BomUpToDateAction();
        bomUpdatedAction.setDryRun(true);
        bomUpdatedAction.setPolicyStatusUrl("URL");
        bomUpdatedAction.setHasBomBeenUdpated(true);
        build.setBomUpdatedAction(bomUpdatedAction);

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final PrintStream stream = new PrintStream(baos);
        final TestBuildListener listener = new TestBuildListener(stream);

        failureStep.perform(build, null, listener);

        final String output = baos.toString();
        assertTrue(output, output.contains("Will not run the Failure conditions because this was a dry run scan."));
        assertEquals(Result.SUCCESS, build.getResult());
    }
}
