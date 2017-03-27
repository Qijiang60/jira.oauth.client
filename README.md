# jira.oauth.client
```java
import net.oauth.OAuthException;
import net.oauth.client.AtlassianOAuthClient;
import net.oauth.client.TokenSecretVerifierHolder;

import java.io.IOException;
import java.net.URISyntaxException;

/**
 * Created by lisanlai on 2017/3/27.
 */
public class ClientTest {

    private static final String BASEURL = "Jira domain url";
    private static final String CONSUMER_KEY = "你自己配置的consumer key";
    private static final String CONSUMER_PRIVATE_KEY = "你自己生成的RSA private key";
    private static final String CALLBACK_URI = "http://requestb.in/12f4ung1";

    public static void main(String[] args) throws Exception {
        AtlassianOAuthClient jiraoAuthClient = new AtlassianOAuthClient(CONSUMER_KEY, CONSUMER_PRIVATE_KEY, BASEURL, CALLBACK_URI);
        //STEP 1: 获取request token
        TokenSecretVerifierHolder requestToken = jiraoAuthClient.getRequestToken();
        String authorizeUrl = jiraoAuthClient.getAuthorizeUrlForToken(requestToken.token);
        System.out.println("Token is " + requestToken.token);
        System.out.println("Token secret is " + requestToken.secret);
        System.out.println("Retrieved request token. go to " + authorizeUrl);

        //STEP2 : 授权， 打开STEP1里面获取到的authorize url
        //登录jira并点击allow按钮

        //STEP3 : 获取 access token
        //getAccessToken("810qrpbOePqXdMRWcoOuMLdoBoLuh9To", "M4O6qaRC4OVDKzQOCcVrmvvpCNkYmhpm", "0aOMdW");

    }

    public static void getAccessToken(String requestToken, String tokenSecret, String verifier) throws OAuthException, IOException, URISyntaxException {
        AtlassianOAuthClient jiraoAuthClient = new AtlassianOAuthClient(CONSUMER_KEY, CONSUMER_PRIVATE_KEY, BASEURL, CALLBACK_URI);
        String accessToken = jiraoAuthClient.swapRequestTokenForAccessToken(requestToken, tokenSecret, verifier);
        System.out.println("Access token is : " + accessToken);
    }

}

```

