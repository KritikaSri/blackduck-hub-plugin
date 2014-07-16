package com.blackducksoftware.integration.hub.jenkins;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;

import net.sf.json.JSONObject;

import org.restlet.Response;
import org.restlet.data.Cookie;
import org.restlet.data.CookieSetting;
import org.restlet.data.MediaType;
import org.restlet.data.Method;
import org.restlet.representation.EmptyRepresentation;
import org.restlet.representation.StringRepresentation;
import org.restlet.resource.ClientResource;
import org.restlet.util.Series;

import com.blackducksoftware.integration.hub.jenkins.exceptions.BDRestException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JenkinsHubIntRestService {
    private Series<Cookie> cookies;

    private String baseUrl;

    protected JenkinsHubIntRestService() {

    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * Gets the cookie for the Authorized connection to the Hub server. Returns the response code from the connection.
     * 
     * @param serverUrl
     *            String the Url for the Hub server
     * @param credentialUserName
     *            String the Username for the Hub server
     * @param credentialPassword
     *            String the Password for the Hub server
     * 
     * @return int Status code
     */
    public int setCookies(String credentialUserName, String credentialPassword) {
        Series<Cookie> cookies = getCookies();

        String url = getBaseUrl() + "/j_spring_security_check?j_username=" + credentialUserName + "&j_password=" + credentialPassword;
        ClientResource resource = new ClientResource(url);
        resource.setMethod(Method.POST);

        EmptyRepresentation rep = new EmptyRepresentation();

        resource.post(rep);
        if (cookies == null) {
            Series<CookieSetting> cookieSettings = resource.getResponse().getCookieSettings();
            Series<Cookie> requestCookies = resource.getRequest().getCookies();
            for (CookieSetting ck : cookieSettings) {
                Cookie cookie = new Cookie();
                cookie.setName(ck.getName());
                cookie.setDomain(ck.getDomain());
                cookie.setPath(ck.getPath());
                cookie.setValue(ck.getValue());
                cookie.setVersion(ck.getVersion());
                requestCookies.add(cookie);
            }

            this.cookies = requestCookies;
        } else {
            // cookies already set
        }

        return resource.getResponse().getStatus().getCode();
    }

    public Series<Cookie> getCookies() {
        return cookies;
    }

    public HashMap<String, Object> getProjectMatches(String hubProjectName) throws IOException, BDRestException {

        String url = getBaseUrl() + "/api/v1/search/PROJECT?q=" + hubProjectName + "&limit=20";
        ClientResource resource = new ClientResource(url);

        resource.getRequest().setCookies(cookies);
        resource.setMethod(Method.GET);
        resource.get();
        int responseCode = resource.getResponse().getStatus().getCode();

        HashMap<String, Object> responseMap = new HashMap<String, Object>();
        if (responseCode == 200 || responseCode == 204 || responseCode == 202) {
            Response resp = resource.getResponse();
            Reader reader = resp.getEntity().getReader();
            BufferedReader bufReader = new BufferedReader(reader);
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = bufReader.readLine()) != null) {
                sb.append(line + "\n");
            }
            byte[] mapData = sb.toString().getBytes();
            // Create HashMap from the Rest response
            ObjectMapper responseMapper = new ObjectMapper();
            responseMap = responseMapper.readValue(mapData, HashMap.class);
        } else {
            throw new BDRestException(Messages.HubBuildScan_getErrorConnectingTo_0_(responseCode));
        }
        return responseMap;
    }

    // TODO
    // public String getProjectId(String hubProjectName) throws IOException, BDRestException {
    //
    // String url = getBaseUrl() + "/api/v1/projects/name/" + hubProjectName + "?projectName=" + hubProjectName;
    // ClientResource resource = new ClientResource(url);
    //
    // resource.getRequest().setCookies(cookies);
    // resource.setMethod(Method.GET);
    // resource.get();
    // int responseCode = resource.getResponse().getStatus().getCode();
    //
    // HashMap<String, Object> responseMap = new HashMap<String, Object>();
    // if (responseCode == 200 || responseCode == 204 || responseCode == 202) {
    // Response resp = resource.getResponse();
    // Reader reader = resp.getEntity().getReader();
    // BufferedReader bufReader = new BufferedReader(reader);
    // StringBuilder sb = new StringBuilder();
    // String line;
    // while ((line = bufReader.readLine()) != null) {
    // sb.append(line + "\n");
    // }
    // byte[] mapData = sb.toString().getBytes();
    // // Create HashMap from the Rest response
    // ObjectMapper responseMapper = new ObjectMapper();
    // responseMap = responseMapper.readValue(mapData, HashMap.class);
    // } else {
    // throw new BDRestException(Messages.HubBuildScan_getErrorConnectingTo_0_(responseCode));
    // }
    // // TODO parse the response and Return the project Id
    // return null;
    // }

    public void getScanCodeLocations() {
        Series<Cookie> cookies = getCookies();
        String url = getBaseUrl() + "/api/v1/scnlocations";
        ClientResource resource = new ClientResource(url);
        // http://2m-internal.blackducksoftware.com/api.html#!/composite-asset-reference-rest-server/findScanCodeLocations_get_0
        // http://2m-internal.blackducksoftware.com/api.html#!/asset-reference-rest-server/createAssetReference_post_0
    }

    public String getProjectIdFromResponse(HashMap<String, Object> responseMap, String projectName) throws IOException, BDRestException {
        String projectId = null;
        if (responseMap.containsKey("hits") && ((ArrayList<LinkedHashMap>) responseMap.get("hits")).size() > 0) {
            ArrayList<LinkedHashMap> projectPotentialMatches = (ArrayList<LinkedHashMap>) responseMap.get("hits");
            // More than one match found
            if (projectPotentialMatches.size() > 1) {
                for (LinkedHashMap project : projectPotentialMatches) {
                    LinkedHashMap projectFields = (LinkedHashMap) project.get("fields");
                    if (((String) ((ArrayList) projectFields.get("name")).get(0)).equals(projectName)) {
                        // All of the fields are ArrayLists with the value at the first position
                        projectId = (String) ((ArrayList) projectFields.get("uuid")).get(0);
                    }

                }
            } else if (projectPotentialMatches.size() == 1) {
                // Single match was found
                LinkedHashMap projectFields = (LinkedHashMap) projectPotentialMatches.get(0).get("fields");
                if (((String) ((ArrayList) projectFields.get("name")).get(0)).equals(projectName)) {
                    // All of the fields are ArrayLists with the value at the first position
                    projectId = (String) ((ArrayList) projectFields.get("uuid")).get(0);
                }
            }
        }
        return projectId;
    }

    public HashMap<String, Object> getReleaseMatchesForProjectId(String projectId) throws IOException, BDRestException {

        Series<Cookie> cookies = getCookies();
        String url = getBaseUrl() + "/api/v1/projects/" + projectId + "/releases?limit=20";
        ClientResource resource = new ClientResource(url);

        resource.getRequest().setCookies(cookies);
        resource.setMethod(Method.GET);
        resource.get();
        int responseCode = resource.getResponse().getStatus().getCode();

        HashMap<String, Object> responseMap = new HashMap<String, Object>();
        if (responseCode == 200 || responseCode == 204 || responseCode == 202) {

            Response resp = resource.getResponse();
            Reader reader = resp.getEntity().getReader();
            BufferedReader bufReader = new BufferedReader(reader);
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = bufReader.readLine()) != null) {
                sb.append(line + "\n");
            }
            byte[] mapData = sb.toString().getBytes();

            // Create HashMap from the Rest response
            ObjectMapper responseMapper = new ObjectMapper();
            responseMap = responseMapper.readValue(mapData, HashMap.class);
        } else {
            throw new BDRestException(Messages.HubBuildScan_getErrorConnectingTo_0_(responseCode));
        }
        return responseMap;
    }

    public HashMap<String, Object> createHubProject(String projectName) throws IOException, BDRestException {

        Series<Cookie> cookies = getCookies();
        String url = getBaseUrl() + "/api/v1/projects";
        ClientResource resource = new ClientResource(url);

        resource.getRequest().setCookies(cookies);
        resource.setMethod(Method.POST);

        JSONObject obj = new JSONObject();
        obj.put("name", projectName);

        StringRepresentation stringRep = new StringRepresentation(obj.toString());
        stringRep.setMediaType(MediaType.APPLICATION_JSON);

        resource.post(stringRep);
        int responseCode = resource.getResponse().getStatus().getCode();

        HashMap<String, Object> responseMap = new HashMap<String, Object>();
        if (responseCode == 201) {

            Response resp = resource.getResponse();
            Reader reader = resp.getEntity().getReader();
            BufferedReader bufReader = new BufferedReader(reader);
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = bufReader.readLine()) != null) {
                sb.append(line + "\n");
            }
            byte[] mapData = sb.toString().getBytes();

            // Create HashMap from the Rest response
            ObjectMapper responseMapper = new ObjectMapper();
            responseMap = responseMapper.readValue(mapData, HashMap.class);
        } else {
            throw new BDRestException(Messages.HubBuildScan_getErrorConnectingTo_0_(responseCode));
        }
        return responseMap;
    }

    public int createHubRelease(String projectRelease, String projectId) throws IOException, BDRestException {
        Series<Cookie> cookies = getCookies();
        String url = getBaseUrl() + "/api/v1/releases";
        ClientResource resource = new ClientResource(url);

        JSONObject obj = new JSONObject();
        obj.put("projectId", projectId);
        obj.put("version", projectRelease);

        resource.getRequest().setCookies(cookies);
        resource.setMethod(Method.POST);
        StringRepresentation stringRep = new StringRepresentation(obj.toString());
        stringRep.setMediaType(MediaType.APPLICATION_JSON);

        resource.post(stringRep);
        int responseCode = resource.getResponse().getStatus().getCode();

        return responseCode;
    }
}
