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
package com.blackducksoftware.integration.hub.jenkins.action;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import com.blackducksoftware.integration.hub.api.report.AggregateBomViewEntry;
import com.blackducksoftware.integration.hub.api.report.HubRiskReportData;
import com.blackducksoftware.integration.hub.api.report.VersionReport;
import com.blackducksoftware.integration.hub.api.report.risk.RiskCategories;
import com.blackducksoftware.integration.hub.api.report.risk.RiskCounts;
import com.blackducksoftware.integration.hub.api.report.risk.RiskProfile;
import com.blackducksoftware.integration.hub.jenkins.Messages;

public class HubReportActionTest {

    @Test
    public void testSetReportHighRisks() {
        final RiskCounts counts = new RiskCounts(1, 0, 0, 0, 0);
        final RiskCategories categories = new RiskCategories(counts, counts, counts, counts, counts);
        final RiskProfile riskProfile = new RiskProfile(0, categories);
        final AggregateBomViewEntry bomEntry = new AggregateBomViewEntry(null, null, null, null, null, null, null, null,
                null, null, null, null, riskProfile, null);
        final List<AggregateBomViewEntry> aggregateBomViewEntries = new ArrayList<AggregateBomViewEntry>();
        aggregateBomViewEntries.add(bomEntry);
        final HubRiskReportData reportData = new HubRiskReportData();
        final VersionReport report = new VersionReport(null, aggregateBomViewEntries);
        reportData.setReport(report);
        final HubReportAction action = new HubReportAction(null);
        action.setReportData(reportData);
        assertNotNull(action.getBomEntries());
        assertEquals(1, action.getVulnerabilityRiskHighCount());
        assertEquals(0, action.getVulnerabilityRiskMediumCount());
        assertEquals(0, action.getVulnerabilityRiskLowCount());
        assertEquals(0, action.getVulnerabilityRiskNoneCount());

        assertEquals(1, action.getLicenseRiskHighCount());
        assertEquals(0, action.getLicenseRiskMediumCount());
        assertEquals(0, action.getLicenseRiskLowCount());
        assertEquals(0, action.getLicenseRiskNoneCount());

        assertEquals(1, action.getOperationalRiskHighCount());
        assertEquals(0, action.getOperationalRiskMediumCount());
        assertEquals(0, action.getOperationalRiskLowCount());
        assertEquals(0, action.getOperationalRiskNoneCount());
    }

    @Test
    public void testSetReportSecurityHighRisks() {
        final RiskCounts counts = new RiskCounts(1, 1, 1, 1, 1);
        final RiskCategories categories = new RiskCategories(counts, counts, counts, counts, counts);
        final RiskProfile riskProfile = new RiskProfile(0, categories);
        final AggregateBomViewEntry bomEntry = new AggregateBomViewEntry(null, null, null, null, null, null, null, null,
                null, null, null, null, riskProfile, null);
        final List<AggregateBomViewEntry> aggregateBomViewEntries = new ArrayList<AggregateBomViewEntry>();
        aggregateBomViewEntries.add(bomEntry);
        final HubRiskReportData reportData = new HubRiskReportData();
        final VersionReport report = new VersionReport(null, aggregateBomViewEntries);
        reportData.setReport(report);
        final HubReportAction action = new HubReportAction(null);
        action.setReportData(reportData);
        assertNotNull(action.getBomEntries());
        assertEquals(1, action.getVulnerabilityRiskHighCount());
        assertEquals(0, action.getVulnerabilityRiskMediumCount());
        assertEquals(0, action.getVulnerabilityRiskLowCount());
        assertEquals(0, action.getVulnerabilityRiskNoneCount());
    }

    @Test
    public void testSetReportSecurityMediumRisks() {
        final RiskCounts counts = new RiskCounts(0, 1, 1, 1, 1);
        final RiskCategories categories = new RiskCategories(counts, counts, counts, counts, counts);
        final RiskProfile riskProfile = new RiskProfile(0, categories);
        final AggregateBomViewEntry bomEntry = new AggregateBomViewEntry(null, null, null, null, null, null, null, null,
                null, null, null, null, riskProfile, null);
        final List<AggregateBomViewEntry> aggregateBomViewEntries = new ArrayList<AggregateBomViewEntry>();
        aggregateBomViewEntries.add(bomEntry);
        final HubRiskReportData reportData = new HubRiskReportData();
        final VersionReport report = new VersionReport(null, aggregateBomViewEntries);
        reportData.setReport(report);
        final HubReportAction action = new HubReportAction(null);
        action.setReportData(reportData);
        assertNotNull(action.getBomEntries());
        assertEquals(0, action.getVulnerabilityRiskHighCount());
        assertEquals(1, action.getVulnerabilityRiskMediumCount());
        assertEquals(0, action.getVulnerabilityRiskLowCount());
        assertEquals(0, action.getVulnerabilityRiskNoneCount());
    }

    @Test
    public void testSetReportMediumRisks() {
        final RiskCounts counts = new RiskCounts(0, 1, 0, 0, 0);
        final RiskCategories categories = new RiskCategories(counts, counts, counts, counts, counts);
        final RiskProfile riskProfile = new RiskProfile(0, categories);
        final AggregateBomViewEntry bomEntry = new AggregateBomViewEntry(null, null, null, null, null, null, null, null,
                null, null, null, null, riskProfile, null);
        final List<AggregateBomViewEntry> aggregateBomViewEntries = new ArrayList<AggregateBomViewEntry>();
        aggregateBomViewEntries.add(bomEntry);
        final HubRiskReportData reportData = new HubRiskReportData();
        final VersionReport report = new VersionReport(null, aggregateBomViewEntries);
        reportData.setReport(report);
        final HubReportAction action = new HubReportAction(null);
        action.setReportData(reportData);
        assertNotNull(action.getBomEntries());
        assertEquals(0, action.getVulnerabilityRiskHighCount());
        assertEquals(1, action.getVulnerabilityRiskMediumCount());
        assertEquals(0, action.getVulnerabilityRiskLowCount());
        assertEquals(0, action.getVulnerabilityRiskNoneCount());

        assertEquals(0, action.getLicenseRiskHighCount());
        assertEquals(1, action.getLicenseRiskMediumCount());
        assertEquals(0, action.getLicenseRiskLowCount());
        assertEquals(0, action.getLicenseRiskNoneCount());

        assertEquals(0, action.getOperationalRiskHighCount());
        assertEquals(1, action.getOperationalRiskMediumCount());
        assertEquals(0, action.getOperationalRiskLowCount());
        assertEquals(0, action.getOperationalRiskNoneCount());
    }

    @Test
    public void testSetReportLowRisks() {
        final RiskCounts counts = new RiskCounts(0, 0, 1, 0, 0);
        final RiskCategories categories = new RiskCategories(counts, counts, counts, counts, counts);
        final RiskProfile riskProfile = new RiskProfile(0, categories);
        final AggregateBomViewEntry bomEntry = new AggregateBomViewEntry(null, null, null, null, null, null, null, null,
                null, null, null, null, riskProfile, null);
        final List<AggregateBomViewEntry> aggregateBomViewEntries = new ArrayList<AggregateBomViewEntry>();
        aggregateBomViewEntries.add(bomEntry);
        final HubRiskReportData reportData = new HubRiskReportData();
        final VersionReport report = new VersionReport(null, aggregateBomViewEntries);
        reportData.setReport(report);
        final HubReportAction action = new HubReportAction(null);
        action.setReportData(reportData);
        assertNotNull(action.getBomEntries());
        assertEquals(0, action.getVulnerabilityRiskHighCount());
        assertEquals(0, action.getVulnerabilityRiskMediumCount());
        assertEquals(1, action.getVulnerabilityRiskLowCount());
        assertEquals(0, action.getVulnerabilityRiskNoneCount());

        assertEquals(0, action.getLicenseRiskHighCount());
        assertEquals(0, action.getLicenseRiskMediumCount());
        assertEquals(1, action.getLicenseRiskLowCount());
        assertEquals(0, action.getLicenseRiskNoneCount());

        assertEquals(0, action.getOperationalRiskHighCount());
        assertEquals(0, action.getOperationalRiskMediumCount());
        assertEquals(1, action.getOperationalRiskLowCount());
        assertEquals(0, action.getOperationalRiskNoneCount());
    }

    @Test
    public void testSetReportNoneRisks() {
        final RiskCounts counts = new RiskCounts(0, 0, 0, 0, 0);
        final RiskCategories categories = new RiskCategories(counts, counts, counts, counts, counts);
        final RiskProfile riskProfile = new RiskProfile(0, categories);
        final AggregateBomViewEntry bomEntry = new AggregateBomViewEntry(null, null, null, null, null, null, null, null,
                null, null, null, null, riskProfile, null);
        final List<AggregateBomViewEntry> aggregateBomViewEntries = new ArrayList<AggregateBomViewEntry>();
        aggregateBomViewEntries.add(bomEntry);
        final HubRiskReportData reportData = new HubRiskReportData();
        final VersionReport report = new VersionReport(null, aggregateBomViewEntries);
        reportData.setReport(report);
        final HubReportAction action = new HubReportAction(null);
        action.setReportData(reportData);
        assertNotNull(action.getBomEntries());
        assertEquals(0, action.getVulnerabilityRiskHighCount());
        assertEquals(0, action.getVulnerabilityRiskMediumCount());
        assertEquals(0, action.getVulnerabilityRiskLowCount());
        assertEquals(1, action.getVulnerabilityRiskNoneCount());

        assertEquals(0, action.getLicenseRiskHighCount());
        assertEquals(0, action.getLicenseRiskMediumCount());
        assertEquals(0, action.getLicenseRiskLowCount());
        assertEquals(1, action.getLicenseRiskNoneCount());

        assertEquals(0, action.getOperationalRiskHighCount());
        assertEquals(0, action.getOperationalRiskMediumCount());
        assertEquals(0, action.getOperationalRiskLowCount());
        assertEquals(1, action.getOperationalRiskNoneCount());
    }

    @Test
    public void testGetPercentageWholeNumbers() {
        final RiskCounts counts = new RiskCounts(1, 0, 0, 0, 0);
        final RiskCategories categories = new RiskCategories(counts, counts, counts, counts, counts);
        final RiskProfile riskProfile = new RiskProfile(0, categories);
        final AggregateBomViewEntry bomEntry = new AggregateBomViewEntry(null, null, null, null, null, null, null, null,
                null, null, null, null, riskProfile, null);
        final List<AggregateBomViewEntry> aggregateBomViewEntries = new ArrayList<AggregateBomViewEntry>();
        aggregateBomViewEntries.add(bomEntry);
        final HubRiskReportData reportData = new HubRiskReportData();
        final VersionReport report = new VersionReport(null, aggregateBomViewEntries);
        reportData.setReport(report);
        final HubReportAction action = new HubReportAction(null);
        action.setReportData(reportData);
        assertNotNull(action.getBomEntries());

        assertTrue(0.0 == action.getPercentage(0.0));
        assertTrue(100.0 == action.getPercentage(1.0));
    }

    @Test
    public void testGetPercentage() {
        final RiskCounts counts = new RiskCounts(1, 0, 0, 0, 0);
        final RiskCategories categories = new RiskCategories(counts, counts, counts, counts, counts);
        final RiskProfile riskProfile = new RiskProfile(0, categories);
        final AggregateBomViewEntry bomEntry = new AggregateBomViewEntry(null, null, null, null, null, null, null, null,
                null, null, null, null, riskProfile, null);
        final List<AggregateBomViewEntry> aggregateBomViewEntries = new ArrayList<AggregateBomViewEntry>();
        aggregateBomViewEntries.add(bomEntry);
        aggregateBomViewEntries.add(bomEntry);
        aggregateBomViewEntries.add(bomEntry);
        aggregateBomViewEntries.add(bomEntry);
        final HubRiskReportData reportData = new HubRiskReportData();
        final VersionReport report = new VersionReport(null, aggregateBomViewEntries);
        reportData.setReport(report);
        final HubReportAction action = new HubReportAction(null);
        action.setReportData(reportData);
        assertNotNull(action.getBomEntries());

        assertTrue(0.0 == action.getPercentage(0.0));
        assertTrue(25.0 == action.getPercentage(1.0));
        assertTrue(50.0 == action.getPercentage(2.0));
        assertTrue(75.0 == action.getPercentage(3.0));
        assertTrue(100.0 == action.getPercentage(4.0));
    }

    @Test
    public void testGetIconFileName() {
        final HubReportAction action = new HubReportAction(null);
        assertEquals("/plugin/blackduck-hub/images/Ducky-200.png", action.getIconFileName());
    }

    @Test
    public void testGetDisplayName() {
        final HubReportAction action = new HubReportAction(null);
        assertEquals(Messages.HubReportAction_getDisplayName(), action.getDisplayName());
    }

    @Test
    public void testGetUrlName() {
        final HubReportAction action = new HubReportAction(null);
        assertEquals("hub_risk_report", action.getUrlName());
    }
}
