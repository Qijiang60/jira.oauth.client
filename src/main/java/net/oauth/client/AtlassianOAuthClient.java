package net.oauth.client;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.google.common.collect.ImmutableList;
import net.oauth.*;
import net.oauth.client.httpclient4.HttpClient4;
import net.oauth.signature.RSA_SHA1;
import net.oauth.util.LogUtil;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.util.*;

import static net.oauth.OAuth.OAUTH_VERIFIER;

public class AtlassianOAuthClient {
    protected static final String SERVLET_BASE_URL = "/plugins/servlet";

    private static Logger logger = LoggerFactory.getLogger(AtlassianOAuthClient.class);

    private final String consumerKey;
    private final String privateKey;
    private final String baseUrl;
    private final String callback;
    private OAuthAccessor accessor;


    public AtlassianOAuthClient(String consumerKey, String privateKey, String baseUrl, String callback) {
        this.consumerKey = consumerKey;
        this.privateKey = privateKey;
        this.baseUrl = baseUrl;
        this.callback = callback;
    }

    public TokenSecretVerifierHolder getRequestToken() throws IOException, OAuthException, URISyntaxException{
        OAuthAccessor accessor = getAccessor();
        OAuthClient oAuthClient = new OAuthClient(new HttpClient4());
        List<OAuth.Parameter> callBack;
        if (callback == null || "".equals(callback)) {
            callBack = Collections.<OAuth.Parameter>emptyList();
        } else {
            callBack = ImmutableList.of(new OAuth.Parameter(OAuth.OAUTH_CALLBACK, callback));
        }

        OAuthMessage message = oAuthClient.getRequestTokenResponse(accessor, "POST", callBack);
        TokenSecretVerifierHolder tokenSecretVerifier = new TokenSecretVerifierHolder();
        tokenSecretVerifier.token = accessor.requestToken;
        tokenSecretVerifier.secret = accessor.tokenSecret;
        tokenSecretVerifier.verifier = message.getParameter(OAUTH_VERIFIER);
        return tokenSecretVerifier;
    }

    public String swapRequestTokenForAccessToken(String requestToken, String tokenSecret, String oauthVerifier) throws IOException, OAuthException, URISyntaxException{
        OAuthAccessor accessor = getAccessor();
        OAuthClient client = new OAuthClient(new HttpClient4());
        accessor.requestToken = requestToken;
        accessor.tokenSecret = tokenSecret;
        OAuthMessage message = client.getAccessToken(accessor, "POST",
                ImmutableList.of(new OAuth.Parameter(OAuth.OAUTH_VERIFIER, oauthVerifier)));
        return message.getToken();
    }

    public String makeAuthenticatedRequest(String accessToken, String method, String url, Collection<? extends Map.Entry> parameters, String jsonBody) throws IOException, URISyntaxException{
        OAuthAccessor accessor = getAccessor();
        HttpClient4 httpClient = new HttpClient4();
        OAuthClient client = new OAuthClient(httpClient);
        accessor.accessToken = accessToken;
        try {
            OAuthMessage oAuthMessage = accessor.newRequestMessage(method, url, parameters, IOUtils.toInputStream(jsonBody, "UTF-8"));
            OAuthMessage response = client.invoke(oAuthMessage, ParameterStyle.JSON);
            return enhanceResponse(response);
        } catch (OAuthException e) {
            logger.warn("Failed to invoke, url={}, accessToken={}, jsonBody={}, Caused by:{}", url, accessToken, jsonBody, LogUtil.printStackTrace(e));
            return handleOauthException(e);
        }
    }

    public String makeAuthenticatedRequestForUpdate(String accessToken, String url, String jsonBody) throws IOException, URISyntaxException{
        OAuthAccessor accessor = getAccessor();
        HttpClient4 httpClient = new HttpClient4();
        OAuthClient client = new OAuthClient(httpClient);
        accessor.accessToken = accessToken;
        try {
            OAuthMessage oAuthMessage = accessor.newRequestMessage(OAuthMessage.PUT, url, Collections.<Map.Entry>emptySet(), IOUtils.toInputStream(jsonBody, "UTF-8"));
            OAuthMessage response = client.invoke(oAuthMessage, ParameterStyle.JSON);
            return enhanceResponse(response);
        } catch (OAuthException e) {
            logger.warn("Failed to invoke, url={}, accessToken={}, jsonBody={}, Caused by:{}", url, accessToken, jsonBody, LogUtil.printStackTrace(e));
            return handleOauthException(e);
        }
    }

    private static String enhanceResponse( OAuthMessage response ) throws IOException {
        if(response!=null){
            OAuthResponseMessage responseMessage = (OAuthResponseMessage)response;
            int statusCode = responseMessage.getHttpResponse().getStatusCode();
            String responseStr = null;
            if(statusCode!=204){
                try{
                    InputStream inputStream = response.getBodyAsStream();
                    if(inputStream!=null){
                        responseStr = response.readBodyAsString();
                    }
                }catch (Exception e){
                    //
                }
            }
            if(statusCode==204 || StringUtils.isBlank(responseStr)){
                return "{ \"statusCode\" : " + statusCode + "}";
            }else{
                JSONObject jsonObject = JSON.parseObject(responseStr);
                jsonObject.fluentPut("statusCode", statusCode);
                return jsonObject.toJSONString();
            }
        }else{
            return null;
        }
    }

    private static String handleOauthException(OAuthException e){
        if(e instanceof OAuthProblemException){
            OAuthProblemException exception = (OAuthProblemException)e;
            int statusCode = exception.getHttpStatusCode();
            Map<String, Object> params = exception.getParameters();
            String returnJsonStr = "{}";
            Set<Map.Entry<String, Object>> set= params.entrySet();
            for(Map.Entry<String, Object> item :set){
                String key=item.getKey();
                if(key.contains("\"errorMessages\"") || key.contains("\"errors\"")){
                    returnJsonStr = key;
                    break;
                }
            }
            JSONObject returnJson = JSON.parseObject(returnJsonStr);
            return returnJson.fluentPut("statusCode", statusCode).toJSONString();
        }else{
            return new JSONObject().fluentPut("statusCode", 500).fluentPut("message", e.getMessage()).toJSONString();
        }
    }

    public String makeAuthenticatedRequest(String url, String accessToken) throws IOException, URISyntaxException{
        return makeAuthenticatedRequest(OAuthMessage.GET, url, accessToken, Collections.<Map.Entry>emptySet());
    }

    public String makeAuthenticatedRequest(String method, String url, String accessToken, Collection<? extends Map.Entry> parameters) throws IOException, URISyntaxException{
        OAuthAccessor accessor = getAccessor();
        OAuthClient client = new OAuthClient(new HttpClient4());
        accessor.accessToken = accessToken;
        try{
            OAuthMessage oAuthMessage = accessor.newRequestMessage(method, url, parameters);
            OAuthMessage response = client.invoke(oAuthMessage, ParameterStyle.QUERY_STRING);
            return enhanceResponse(response);
        } catch (OAuthException e) {
            logger.warn("Failed to invoke, url={}, accessToken={}, Caused by:{}", url, accessToken, LogUtil.printStackTrace(e));
            return handleOauthException(e);
        }
    }

    private final OAuthAccessor getAccessor() {
        if (accessor == null) {
            OAuthServiceProvider serviceProvider = new OAuthServiceProvider(getRequestTokenUrl(), getAuthorizeUrl(), getAccessTokenUrl());
            OAuthConsumer consumer = new OAuthConsumer(callback, consumerKey, null, serviceProvider);
            consumer.setProperty(RSA_SHA1.PRIVATE_KEY, privateKey);
            consumer.setProperty(OAuth.OAUTH_SIGNATURE_METHOD, OAuth.RSA_SHA1);
            accessor = new OAuthAccessor(consumer);
        }
        return accessor;
    }

    private String getAccessTokenUrl() {
        return baseUrl + SERVLET_BASE_URL + "/oauth/access-token";
    }

    private String getRequestTokenUrl() {
        return baseUrl + SERVLET_BASE_URL + "/oauth/request-token";
    }

    public String getAuthorizeUrlForToken(String token) {
        return getAuthorizeUrl() + "?oauth_token=" + token;
    }

    private String getAuthorizeUrl() {
        return baseUrl + SERVLET_BASE_URL + "/oauth/authorize";
    }
}
