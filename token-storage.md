# Token storage

## Chapters

1. Context
1. How client-side apps authenticate with APIs
1. localStorage - the hated one
1. Cookie is taking all of the cookies
1. The vulnerabilities
1. Cookie's double the trouble
1. Mending XSS
1. localStorage all the way... or is it?
1. Alternatives

## To be researched

- [ ] Storing JWT in httpOnly cookie

  - Can XSS exploit/still use this?
  - The attacker doesn't know the JWT, but can use them while XSS-ing. What
    happens when the attacker knows the JWT, like in the case of localStorage?

OAuth 2.0:

- [ ] How can Refresh Token provide seamless experience?
- [x] Implicit Flow?
- [ ] Content Security Policy (XSS mitigation)
- [ ] Why "Backend for Frontend" architecture needs PKCE?
      [link](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps#section-6.2)
- [ ] OAuth 2.1?

## Research note

Auth0 has this to say about protecting refresh token in SPAs:
[link](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/#When-to-Use-Refresh-Tokens)

> Keep in mind that according to the spec, when using the Implicit Flow, the
> authorization server should not issue refresh tokens. The Implicit flow is
> often implemented in Single-Page Applications (SPAs), which run on the
> frontend layer of a system architecture. There's no easy way of keeping a
> refresh token secure in the frontend layer on its own.

From Auth0: [link](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/#You-Can-Store-Refresh-Token-In-Local-Storage)

> Yes, you read that right. When we have refresh token rotation in place, we can
> store tokens in local storage or browser memory.

Refresh token rotation lifespan:

> A refresh token may have a long lifespan by configuration. However, the
> defined long lifespan of a refresh token is cut short with refresh token
> rotation. The refresh is only valid within the lifespan of the access token,
> which would be short-lived.

OAuth:

> OAuth was designed as an authorization protocol, so the end result of every
> OAuth flow is the app obtains an access token in order to be able to access or
> modify something about the user's account. **The access token itself says
> nothing about who the user is.** > [link](https://www.oauth.com/oauth2-servers/signing-in-with-google/)

OAuth server-side apps won't let browser know access token:

> The authorization code flow offers a few benefits over the other grant types.
> When the user authorizes the application, they are redirected back to the
> application with a temporary code in the URL. The application exchanges that
> code for the access token. When the application makes the request for the
> access token, that request can be authenticated with the client secret, which
> reduces the risk of an attacker intercepting the authorization code and using
> it themselves. This also means the access token is never visible to the user
> or their browser, so it is the most secure way to pass the token back to the
> application, reducing the risk of the token leaking to someone else.
> [link](https://www.oauth.com/oauth2-servers/server-side-apps/authorization-code/)

Client-side apps can't protect its secret, so it should use PCKE:

> If an app wants to use the authorization code grant but can't protect its
> secret (i.e. native mobile apps or single-page JavaScript apps), then the
> client secret is not required when making a request to exchange the auth code
> for an access token, and PKCE must be used as well. However, some services
> still do not support PKCE, so it may not be possible to perform an
> authorization flow from the single-page app itself, and the client-side
> JavaScript code may need to have a companion server-side component that
> performs the OAuth flow instead. [link](https://www.oauth.com/oauth2-servers/server-side-apps/user-experience/)

On why the `state` parameter is recommended: [link](https://stackoverflow.com/a/35988614)
- The app needs to be sure that it only exchange the Authorization Code it
  requested, not the Authorization Code of the attacker, or else it would access
  the resource in the name of the attacker, i.e. posting images to the
  attacker's account. Kind of sounds like CSRF. That is achieved using `state`.

Implicit Flow flaws:

- Redirect URI interception

  > Since the access token is sent as the fragment (hash) part of the redirect
  > URL (also called the front channel), it will be exposed to an attacker if
  > the redirect is intercepted.
  > [link](https://christianlydemann.com/implicit-flow-vs-code-flow-with-pkce/)

  Invalid point. The action after authorization is done should be written in the
  `state` parameter, just like Code flow. So, this is not explicit to the
  Implicit flow.

  > To prevent a malicious application from obtaining tokens using id of the
  > real client, an authorization server must only deliver the tokens to the
  > trusted, registered uris via url redirect.
  > [link](https://www.taithienbo.com/why-the-implicit-flow-is-no-longer-recommended-for-protecting-a-public-client/)

  <!-- This is wrong. Hash fragment won't be intercepted, it is only exposed to the
  browser. [link](https://stackoverflow.com/a/13389335) -->

- Access Token Leak in Browser History

  - Valid point, there is a hassle of removing the hash fragment from the URL
    in order to remove the access token from the browser history.

- Attacker getting token from the URL with XSS/JavaScript

  - This point also applies to the Code flow. Assuming that the entire Code flow
    is safe. In a SPA, the token is still visible to the JavaScript. XSS can
    access the token of the SPA even in the Code flow.
  - Libraries also has the same security concerns as XSS. They can access the
    token of Code flow too. The token storage is the same between the two flows.

- "Lack of client authentication"
  [link](https://www.taithienbo.com/why-the-implicit-flow-is-no-longer-recommended-for-protecting-a-public-client/)
  - A client-side app doesn't have any "client authentication". No Client secret
    is stored in a SPA. That applies to the Code flow as well, but not Code flow
    with PCKE.
  - A more correct statement is "Lack of verifying that the token receiver is
    indeed the requester". We assure that in a SPA using PCKE. In PCKE, only the
    true requester will be able to obtain an access token.

    We can think of it as if the client secret is per-request basis. For each
    request, there is a different client secret.

- "Confused deputy" [link](https://stackoverflow.com/a/17439317)
  - Using Implicit flow, the SPA should verify that the token is given to them,
    not some other malicious SPA. For example, a victim logs in googlefake.com
    using Google OAuth Implicit flow, then googlefake.com uses the access token
    received to log into google.com using that access token. If google.com is
    not checking that the token is given to googlefake.com instead of
    google.com, then the victim's Google account is compromised.
    
    Basically, an access token for an application that uses Google account
    should not grant access to Google.com or any other applications that also
    use a Google account for login.

