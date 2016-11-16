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
package com.blackducksoftware.integration.hub.jenkins.bom;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import com.blackducksoftware.integration.hub.HubIntRestService;
import com.blackducksoftware.integration.hub.api.report.HubReportGenerationInfo;
import com.blackducksoftware.integration.hub.api.scan.ScanSummaryItem;
import com.blackducksoftware.integration.hub.dataservices.scan.ScanStatusDataService;
import com.blackducksoftware.integration.hub.exception.BDRestException;
import com.blackducksoftware.integration.hub.exception.HubIntegrationException;
import com.blackducksoftware.integration.hub.exception.ProjectDoesNotExistException;
import com.blackducksoftware.integration.hub.exception.UnexpectedHubResponseException;
import com.blackducksoftware.integration.hub.polling.HubEventPolling;
import com.blackducksoftware.integration.log.IntLogger;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import hudson.FilePath;
import hudson.remoting.VirtualChannel;

public class RemoteHubEventPolling extends HubEventPolling {

    private final VirtualChannel channel;

    public RemoteHubEventPolling(final HubIntRestService service, final VirtualChannel channel) {
        super(service);
        this.channel = channel;
    }

    public VirtualChannel getChannel() {
        return channel;
    }

    @Override
    public void assertBomUpToDate(final HubReportGenerationInfo hubReportGenerationInfo, final IntLogger logger)
            throws InterruptedException, BDRestException, HubIntegrationException, URISyntaxException, IOException,
            ProjectDoesNotExistException, UnexpectedHubResponseException {
        if (StringUtils.isBlank(hubReportGenerationInfo.getScanStatusDirectory())) {
            throw new HubIntegrationException("The scan status directory must be a non empty value.");
        }
        final FilePath statusDirectory = new FilePath(getChannel(), hubReportGenerationInfo.getScanStatusDirectory());
        if (!statusDirectory.exists()) {
            throw new HubIntegrationException("The scan status directory does not exist.");
        }
        if (!statusDirectory.isDirectory()) {
            throw new HubIntegrationException("The scan status directory provided is not a directory.");
        }
        final List<FilePath> statusFiles = statusDirectory.list();
        if (statusFiles == null || statusFiles.size() == 0) {
            throw new HubIntegrationException("Can not find the scan status files in the directory provided.");
        }
        int expectedNumScans = 0;
        if (hubReportGenerationInfo.getScanTargets() != null && !hubReportGenerationInfo.getScanTargets().isEmpty()) {
            expectedNumScans = hubReportGenerationInfo.getScanTargets().size();
        }
        if (statusFiles.size() != expectedNumScans) {
            throw new HubIntegrationException("There were " + expectedNumScans + " scans configured and we found "
                    + statusFiles.size() + " status files.");
        }
        logger.info("Checking the directory : " + statusDirectory.getRemote() + " for the scan status's.");
        final List<ScanSummaryItem> scanSummaryItems = new ArrayList<ScanSummaryItem>();
        for (final FilePath currentStatusFile : statusFiles) {
            final String fileContent = currentStatusFile.readToString();
            final Gson gson = new GsonBuilder().create();
            final ScanSummaryItem scanSummaryItem = gson.fromJson(fileContent, ScanSummaryItem.class);
            if (scanSummaryItem.getMeta() == null || scanSummaryItem.getStatus() == null) {
                throw new HubIntegrationException("The scan status file : " + currentStatusFile.getRemote()
                        + " does not contain valid scan status json.");
            }
            scanSummaryItems.add(scanSummaryItem);
        }

        final long timeoutInMilliseconds = hubReportGenerationInfo.getMaximumWaitTime();
        final ScanStatusDataService scanStatusDataService = getService().getScanStatusDataService();
        scanStatusDataService.assertBomImportScansFinished(scanSummaryItems, timeoutInMilliseconds);
    }

}
