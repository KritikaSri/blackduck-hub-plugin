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

import javax.servlet.ServletException;

import org.kohsuke.stapler.QueryParameter;

import com.blackducksoftware.integration.hub.jenkins.Messages;
import com.blackducksoftware.integration.hub.jenkins.scan.BDCommonDescriptorUtil;

import hudson.Extension;
import hudson.model.AbstractProject;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Publisher;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;

@Extension(ordinal = 1)
public class HubFailureConditionStepDescriptor extends BuildStepDescriptor<Publisher> {

    public HubFailureConditionStepDescriptor() {
        super(HubFailureConditionStep.class);
    }

    @Override
    public boolean isApplicable(final Class<? extends AbstractProject> jobType) {
        return true;
    }

    @Override
    public String getDisplayName() {
        return Messages.HubFailureCondition_getDisplayName();
    }
    
    public ListBoxModel doFillHubVersionPhaseItems() {
        return BDCommonDescriptorUtil.doFillHubVersionPhaseItems();
    }

    public ListBoxModel doFillHubVersionDistItems() {
        return BDCommonDescriptorUtil.doFillHubVersionDistItems();
    }

    public FormValidation doCheckFailBuildForPolicyViolations(@QueryParameter("failBuildForPolicyViolations") final boolean failBuildForPolicyViolations)
            throws IOException, ServletException {
        return FormValidation.ok();
    }

    public ListBoxModel doFillBuildStateOnFailureItems() {
        return BDCommonDescriptorUtil.doFillBuildStateOnFailureItems();
    }

}
