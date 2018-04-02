package com.blackducksoftware.integration.hub.jenkins.remote;

import java.io.Serializable;

public class ScanResponse implements Serializable {
    private final Exception exception;
    private final String versionJson;

    public ScanResponse(final String versionJson) {
        this.exception = null;
        this.versionJson = versionJson;
    }

    public ScanResponse(final Exception exception) {
        this.exception = exception;
        this.versionJson = null;
    }

    public Exception getException() {
        return exception;
    }

    public String getVersionJson() {
        return versionJson;
    }
}
