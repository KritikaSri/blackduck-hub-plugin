package com.blackducksoftware.integration.hub.jenkins.tests.utils;

import hudson.console.ConsoleNote;
import hudson.model.BuildListener;
import hudson.model.Result;
import hudson.model.Cause;

import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.List;

public class TestBuildListener implements BuildListener {

    private PrintStream stream = null;

    public TestBuildListener(PrintStream stream) {
        this.stream = stream;
    }

    @Override
    public PrintWriter error(String txt) {
        if (txt != null) {
            stream.println(txt);
        }
        return null;
    }

    @Override
    public PrintStream getLogger() {
        return stream;
    }

    @Override
    public void annotate(ConsoleNote ann) throws IOException {
        // TODO Auto-generated function stub

    }

    @Override
    public void hyperlink(String url, String text) throws IOException {
        // TODO Auto-generated function stub

    }

    @Override
    public PrintWriter error(String format, Object... args) {
        if (format != null) {
            stream.println(format);
        }
        return null;
    }

    @Override
    public PrintWriter fatalError(String msg) {
        if (msg != null) {
            stream.println(msg);
        }
        return null;
    }

    @Override
    public PrintWriter fatalError(String format, Object... args) {
        if (format != null) {
            stream.println(format);
        }
        return null;
    }

    @Override
    public void started(List<Cause> causes) {
        // TODO Auto-generated function stub

    }

    @Override
    public void finished(Result result) {
        // TODO Auto-generated function stub

    }
}