/*
 * Copyright (C) 2017 Black Duck Software Inc.
 * http://www.blackducksoftware.com/
 * All rights reserved.
 *
 * This software is the confidential and proprietary information of
 * Black Duck Software ("Confidential Information"). You shall not
 * disclose such Confidential Information and shall use it only in
 * accordance with the terms of the license agreement you entered into
 * with Black Duck Software.
 */
package com.blackducksoftware.integration.hub.jenkins.failure;

public enum FailureConditionBuildStateEnum {
    SUCCESS("Success"), FAILURE("Failure"), UNSTABLE("Unstable");

    private final String displayValue;

    private FailureConditionBuildStateEnum(final String displayValue) {
        this.displayValue = displayValue;
    }

    public String getDisplayValue() {
        return displayValue;
    }

    public static FailureConditionBuildStateEnum getFailureConditionBuildStateByDisplayValue(final String displayValue) {
        for (final FailureConditionBuildStateEnum currentEnum : FailureConditionBuildStateEnum.values()) {
            if (currentEnum.getDisplayValue().equalsIgnoreCase(displayValue)) {
                return currentEnum;
            }
        }
        return null;
    }

    public static FailureConditionBuildStateEnum getFailureConditionBuildStateEnum(final String failureCondition) {
        if (failureCondition == null) {
            return null;
        }
        FailureConditionBuildStateEnum failureConditionEnum;
        try {
            failureConditionEnum = FailureConditionBuildStateEnum.valueOf(failureCondition.toUpperCase());
        } catch (final IllegalArgumentException e) {
            // ignore expection
            failureConditionEnum = null;
        }
        return failureConditionEnum;
    }
}
