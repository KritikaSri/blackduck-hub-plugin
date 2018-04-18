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

import hudson.EnvVars;
import hudson.model.AbstractBuild;
import hudson.model.EnvironmentContributingAction;

public class HubVariableContributor implements EnvironmentContributingAction {

    public static final String BOM_ENTRIES_IN_VIOLATION = "BOM_ENTRIES_IN_VIOLATION";

    public static final String VIOLATIONS_OVERRIDEN = "VIOLATIONS_OVERRIDEN";

    public static final String BOM_ENTRIES_NOT_IN_VIOLATION = "BOM_ENTRIES_NOT_IN_VIOLATION";

    private Integer bomEntriesInViolation;

    private Integer violationsOverriden;

    private Integer bomEntriesNotInViolation;

    public HubVariableContributor() {
    }

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return null;
    }

    @Override
    public String getUrlName() {
        return null;
    }

    public Integer getBomEntriesInViolation() {
        return bomEntriesInViolation;
    }

    public void setBomEntriesInViolation(final Integer bomEntriesInViolation) {
        this.bomEntriesInViolation = bomEntriesInViolation;
    }

    public Integer getViolationsOverriden() {
        return violationsOverriden;
    }

    public void setViolationsOverriden(final Integer violationsOverriden) {
        this.violationsOverriden = violationsOverriden;
    }

    public Integer getBomEntriesNotInViolation() {
        return bomEntriesNotInViolation;
    }

    public void setBomEntriesNotInViolation(final Integer bomEntriesNotInViolation) {
        this.bomEntriesNotInViolation = bomEntriesNotInViolation;
    }

    @Override
    public void buildEnvVars(final AbstractBuild<?, ?> build, final EnvVars env) {
        if (getBomEntriesInViolation() != null) {
            env.put(BOM_ENTRIES_IN_VIOLATION, String.valueOf(getBomEntriesInViolation()));
        }
        if (getViolationsOverriden() != null) {
            env.put(VIOLATIONS_OVERRIDEN, String.valueOf(getViolationsOverriden()));
        }
        if (getBomEntriesNotInViolation() != null) {
            env.put(BOM_ENTRIES_NOT_IN_VIOLATION, String.valueOf(getBomEntriesNotInViolation()));
        }
    }

}
