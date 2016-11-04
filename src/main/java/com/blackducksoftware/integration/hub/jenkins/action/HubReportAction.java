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

import java.util.List;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;

import com.blackducksoftware.integration.hub.api.report.AggregateBomViewEntry;
import com.blackducksoftware.integration.hub.api.report.DetailedReleaseSummary;
import com.blackducksoftware.integration.hub.api.report.HubRiskReportData;
import com.blackducksoftware.integration.hub.api.report.VersionReport;
import com.blackducksoftware.integration.hub.jenkins.Messages;

import hudson.model.Action;
import hudson.model.Run;

public class HubReportAction implements Action {

    private final Run<?, ?> build;

    private HubRiskReportData reportData;

    public HubReportAction(final Run<?, ?> build) {
        this.build = build;
    }

    public Run<?, ?> getBuild() {
        return build;
    }

    public VersionReport getReport() {
        return reportData.getReport();
    }

    public DetailedReleaseSummary getReleaseSummary() {
        if (reportData == null || reportData.getReport() == null) {
            return null;
        }
        return reportData.getReport().getDetailedReleaseSummary();
    }

    public List<AggregateBomViewEntry> getBomEntries() {
        if (reportData == null || reportData.getReport() == null) {
            return null;
        }
        return reportData.getReport().getAggregateBomViewEntries();
    }

    public int getVulnerabilityRiskHighCount() {
        return reportData.getVulnerabilityRiskHighCount();
    }

    public int getVulnerabilityRiskMediumCount() {
        return reportData.getVulnerabilityRiskMediumCount();
    }

    public int getVulnerabilityRiskLowCount() {
        return reportData.getVulnerabilityRiskLowCount();
    }

    public int getVulnerabilityRiskNoneCount() {
        return reportData.getVulnerabilityRiskNoneCount();
    }

    public int getLicenseRiskHighCount() {
        return reportData.getLicenseRiskHighCount();
    }

    public int getLicenseRiskMediumCount() {
        return reportData.getLicenseRiskMediumCount();
    }

    public int getLicenseRiskLowCount() {
        return reportData.getLicenseRiskLowCount();
    }

    public int getLicenseRiskNoneCount() {
        return reportData.getLicenseRiskNoneCount();
    }

    public int getOperationalRiskHighCount() {
        return reportData.getOperationalRiskHighCount();
    }

    public int getOperationalRiskMediumCount() {
        return reportData.getOperationalRiskMediumCount();
    }

    public int getOperationalRiskLowCount() {
        return reportData.getOperationalRiskLowCount();
    }

    public int getOperationalRiskNoneCount() {
        return reportData.getOperationalRiskNoneCount();
    }

    public double getPercentage(final double count) {
        if (getBomEntries() == null) {
            return 0.0;
        }
        final double totalCount = getBomEntries().size();
        double percentage = 0;
        if (totalCount > 0 && count > 0) {
            percentage = (count / totalCount) * 100;
        }
        return percentage;
    }

    public String htmlEscape(final String valueToEscape) {
        if (StringUtils.isBlank(valueToEscape)) {
            return null;
        }
        return StringEscapeUtils.escapeHtml4(valueToEscape);
    }

    public void setReportData(final HubRiskReportData reportData) {
        this.reportData = reportData;
    }

    @Override
    public String getIconFileName() {
        return "/plugin/blackduck-hub/images/Ducky-200.png";
    }

    @Override
    public String getDisplayName() {
        return Messages.HubReportAction_getDisplayName();
    }

    @Override
    public String getUrlName() {
        return "hub_risk_report";
    }

}
