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
package com.blackducksoftware.integration.hub.jenkins;

import java.io.IOException;

import javax.servlet.ServletException;

import org.apache.commons.lang3.StringUtils;
import org.kohsuke.stapler.QueryParameter;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.FormValidation;

@Extension
public class ScanJobsDescriptor extends Descriptor<ScanJobs> {

    public ScanJobsDescriptor() {
        super(ScanJobs.class);
        load();
    }

    @Override
    public String getDisplayName() {
        return "";
    }

    /**
     * Performs on-the-fly validation of the form field 'scanTarget'.
     *
     */
    public FormValidation doCheckScanTarget(@QueryParameter("scanTarget") final String scanTarget)
            throws IOException, ServletException {
        if (StringUtils.isBlank(scanTarget)) {
            return FormValidation.warningWithMarkup(Messages
                    .HubBuildScan_getWorkspaceWillBeScanned());
        }

        return FormValidation.ok();
    }

}
