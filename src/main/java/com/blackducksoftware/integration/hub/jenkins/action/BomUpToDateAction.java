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

import com.blackducksoftware.integration.hub.model.view.ScanSummaryView;

import hudson.model.Action;

public class BomUpToDateAction implements Action {

    private boolean hasBomBeenUdpated;

    private long maxWaitTime;

    private List<ScanSummaryView> scanSummaries;

    private String policyStatusUrl;

    private boolean dryRun;

    public boolean isHasBomBeenUdpated() {
        return hasBomBeenUdpated;
    }

    public void setHasBomBeenUdpated(final boolean hasBomBeenUdpated) {
        this.hasBomBeenUdpated = hasBomBeenUdpated;
    }

    public long getMaxWaitTime() {
        return maxWaitTime;
    }

    public void setMaxWaitTime(final long maxWaitTime) {
        this.maxWaitTime = maxWaitTime;
    }

    public List<ScanSummaryView> getScanSummaries() {
        return scanSummaries;
    }

    public void setScanSummaries(final List<ScanSummaryView> scanSummaries) {
        this.scanSummaries = scanSummaries;
    }

    public String getPolicyStatusUrl() {
        return policyStatusUrl;
    }

    public void setPolicyStatusUrl(final String policyStatusUrl) {
        this.policyStatusUrl = policyStatusUrl;
    }

    public boolean isDryRun() {
        return dryRun;
    }

    public void setDryRun(final boolean dryRun) {
        this.dryRun = dryRun;
    }

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return "Temp Action to verify we have already waited for the Bom to finish updating";
    }

    @Override
    public String getUrlName() {
        return null;
    }

}
