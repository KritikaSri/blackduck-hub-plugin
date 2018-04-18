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
package com.blackducksoftware.integration.hub.jenkins.action;

import hudson.model.Action;

public class MavenClasspathAction implements Action {

    private String buildId;

    private String workingDirectory;

    private String mavenClasspathExtension;

    private Boolean isRecorder30 = false;

    private Boolean isRecorder31 = false;

    private String separator;

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return "Temp BlackDuck maven Action";
    }

    @Override
    public String getUrlName() {
        return null;
    }

    public String getBuildId() {
        return buildId;
    }

    public void setBuildId(String buildId) {
        this.buildId = buildId;
    }

    public String getWorkingDirectory() {
        return workingDirectory;
    }

    public void setWorkingDirectory(String workingDirectory) {
        this.workingDirectory = workingDirectory;
    }

    public String getMavenClasspathExtension() {
        return mavenClasspathExtension;
    }

    public void setMavenClasspathExtension(String mavenClasspathExtension) {
        this.mavenClasspathExtension = mavenClasspathExtension;
    }

    public Boolean getIsRecorder30() {
        return isRecorder30;
    }

    public void setIsRecorder30(Boolean isRecorder30) {
        this.isRecorder30 = isRecorder30;
    }

    public Boolean getIsRecorder31() {
        return isRecorder31;
    }

    public void setIsRecorder31(Boolean isRecorder31) {
        this.isRecorder31 = isRecorder31;
    }

    public String getSeparator() {
        return separator;
    }

    public void setSeparator(String separator) {
        this.separator = separator;
    }

}
