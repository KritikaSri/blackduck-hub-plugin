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

import com.blackducksoftware.integration.hub.jenkins.Messages;
import com.blackducksoftware.integration.hub.report.api.ReportData;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import hudson.model.Action;
import hudson.model.Run;

public class HubReportV2Action implements Action {

    private final Run<?, ?> build;

    private ReportData reportData;

    private String jsonReportData;

    public HubReportV2Action(final Run<?, ?> build) {
        this.build = build;
    }

    public Run<?, ?> getBuild() {
        return build;
    }

    public void setReportData(final ReportData reportData) {
        this.reportData = reportData;
        final Gson gson = new GsonBuilder().create();
        jsonReportData = gson.toJson(reportData);
    }

    public ReportData getReportData() {
        return reportData;
    }

    public String getJsonReportData() {
        return jsonReportData;
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
