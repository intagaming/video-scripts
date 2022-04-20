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
1. Introducing OAuth. "That's not how it's supposed to work."
1. Authorization Code flow
1. Implicit flow
1. The case against Implicit flow
1. Authorization Code flow with PCKE
1. Refresh token
1. Refresh token rotation

"localStorage all the way... or is it?" -> This talks about the problem with
JWT. Is was not intended for security.

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
- [ ] Is `state` has a role of CSRF prevention when using PCKE?
- [ ] OpenID Connect

## Research note

### Refresh token

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

[Authorization server] Best practice when using refresh tokens:

> If the authorization server wishes to allow JavaScript apps to use refresh
> tokens, then they must also follow the best practices outlined in “OAuth 2.0
> Security Best Current Practice” and “OAuth 2.0 for Browser-Based Apps“, two
> recent documents adopted by the OAuth Working Group. Specifically, refresh
> tokens must be valid for only one use, and the authorization server must issue
> a new refresh token each time a new access token is issued in response to a
> refresh token grant. This provides the authorization server a way to detect if
> a refresh token has been copied and used by an attacker, since in normal
> operation of an app a refresh token would be used only once.
>
> Refresh tokens must also either have a set maximum lifetime, or expire if they
> are not used within some amount of time. This is again another way to help
> mitigate the risks of a stolen refresh token.
> [link](https://www.oauth.com/oauth2-servers/single-page-apps/security-considerations/)

---

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

---

### Implicit Flow:

The "flaws":

- "too insecure"

  From oauth.com:

  > For example, the spec provides no mechanism to return a refresh token in the
  > Implicit flow, as it was seen as too insecure to allow that. The spec also
  > recommends short lifetimes and limited scope for access tokens issued via
  > the Implicit flow.
  > [link](https://www.oauth.com/oauth2-servers/single-page-apps/implicit-flow/)

  Well, too insecure what?

  The Implicit flow **could** be made _relatively secure_ (as proven later) **if
  done correctly**, meaning they could work but there is a specific amount of
  effort to achieve that. But that's not impossible. And **relatively secure**
  is the keyword.

- Redirect URI interception

  > Since the access token is sent as the fragment (hash) part of the redirect
  > URL (also called the front channel), it will be exposed to an attacker if
  > the redirect is intercepted.
  > [link](https://christianlydemann.com/implicit-flow-vs-code-flow-with-pkce/)

  Relatively speaking. Firstly, The redirect URL must be registered:

  > In any case, with both the Implicit Flow as well as the Authorization Code
  > Flow with PKCE, the server must require registration of the redirect URL in
  > order to maintain the security of the flow.
  > [link](https://www.oauth.com/oauth2-servers/single-page-apps/implicit-flow/)

  Secondly, the action after the token is granted (in this instance, to redirect
  the user to some page/URL) _should_ be written in the `state` parameter, just
  like Code flow, which must match with the original intent to prevent "CSRF".

  > The state parameter serves two functions. When the user is redirected back
  > to your app, whatever value you include as the state will also be included
  > in the redirect. This gives your app a chance to persist data between the
  > user being directed to the authorization server and back again, such as
  > using the state parameter as a session key. This may be used to indicate
  > what action in the app to perform after authorization is complete, for
  > example, indicating which of your app's pages to redirect to after
  > authorization. This also serves as a CSRF protection mechanism.
  >
  > Note that the lack of using a client secret means that using the state
  > parameter is even more important for single-page apps.
  > [link](https://www.oauth.com/oauth2-servers/single-page-apps)

  If somehow the trusted URLs are compromised, only then the access token will
  be exposed. Whether one can assures that trusted URLs are not compromised is
  to be determined. Code flow suffers from the same problem too, so they need
  PCKE.

- Attacker getting token from the URL with XSS/JavaScript

  - This point also applies to the Code flow. Assuming that the entire Code flow
    is safe. In an SPA, the token is still visible to the JavaScript (as proven
    by using "Refresh token rotation" and the unnecessary of using `httpOnly`
    Cookie), so XSS can still access them no matter the flow.
  - Libraries also has the same security concerns as XSS. They can access the
    token of Code flow too. The token storage is the same between the two flows.

- "Confused deputy" [link](https://stackoverflow.com/a/17439317)

  - Using Implicit flow, the SPA should verify that the token is given to them,
    not some other (potentially malicious) SPA. This is necessary because in
    Implicit flow, we can't verify if the Token receiver was indeed requested
    the token.

    For example, a victim logs in googlefake.com using Google OAuth Implicit
    flow, and then googlefake.com uses that access token to log into google.com.
    If google.com is not checking that the token is given to googlefake.com
    instead of google.com, then the victim's Google account is compromised.

    Basically, an access token for an application that uses Google account login
    should not grant access to Google.com or any other applications that also
    use a Google account for login.

  - **However**, we should also do the same for the Code flow. If the Code is
    for the googlefake.com, then the same compromise happens, as the access
    token granted is for googlefake.com.
  - We can do that using the `state` parameter. (demonstrates the Code flow &
    the Implicit flow similarity)

  - The `state` parameter is checked upon the Token grant on the client-side. If
    somehow the attacker managed to inject a malicious token into the victim's
    browser, then a second measure takes place by checking the "audience" field
    `aud` on the Resource server i.e. your API.

The **real** Implicit flow flaws:

- Access Token Leak in Browser History

  - Valid point, there is a hassle of removing the hash fragment from the URL
    in order to remove the access token from the browser history.

- "Lack of client authentication"
  [link](https://www.taithienbo.com/why-the-implicit-flow-is-no-longer-recommended-for-protecting-a-public-client/)

  That's true. Implicit flow **implicitly assumes** that the receiver is indeed
  the requester. If the token is hijacked, i.e. the redirect URL is compromised
  and the attacker receives the token instead, then the token is indeed
  compromised.

  Remember that the `state` parameter only has a role of preventing the use of
  the wrong token in the legitimate, original app. If the token is gone to the
  incorrect target, that's a gone token, and they need not care about the
  `state`.

  However, this "Lack of client authentication" statement is a little ambiguous.
  You may ask "Isn't Client-side apps cannot store any secrets?"

  - A client-side app doesn't have a fixed client secret, no matter what flow
    you use, including the Code flow, because client-side apps could not store
    anything securely. In a mobile + Code flow scenario, if the attacker's app
    gets the Authorization Code, they could still go to exchange for an access
    token. This flaw is solved with PCKE. In this sense, the accurate statement
    is "Lack of client secret".
  - We assure that the receiver is indeed the requester in an SPA using PCKE. In
    PCKE, only the true requester will be able to exchange the code for an
    access token. This is the real "client authentication".

    We can think of it as if the client secret is per-request basis. For each
    request, there is a different client secret.

  If we registered an URL for redirection, but that URL is compromised, then in
  the Implicit flow we could do nothing more. The token is compromised. Whether
  we can assures that the URL wouldn't be compromised or not is, again, an open
  question.

Although the flaws could be prevented (EXCEPT the "client authentication" flaw),
it is still a hassle, and there could still be human errors.

---

Storing tokens: [link](https://www.oauth.com/oauth2-servers/single-page-apps/security-considerations/)

> Generally, the browser's LocalStorage API is the best place to store this data
> as it provides the easiest API to store and retrieve data and is about as
> secure as you can get in a browser. The downside is that any scripts on the
> page, even from different domains such as your analytics or ad network, will
> be able to access the LocalStorage of your application. This means anything
> you store in LocalStorage is potentially visible to third-party scripts on
> your page.
>
> Because of the risks of data leakage from third-party scripts, it is extremely
> important to have a good Content-Security Policy configured for your app so
> that you can be more confident that arbitrary scripts aren't able to run in
> the application. A good document on configuring a Content Security Policy is
> available from OWASP at
> https://owasp.org/www-project-cheat-sheets/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

Consider "handling OAuth flow on the backend", i.e. use a traditional web app
with session.
[link](https://www.oauth.com/oauth2-servers/single-page-apps/security-considerations/)

[OAuth 2.0 for Browser-Based Apps](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps)

[OAuth 2.0 Security Best Current
Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

---

The concerns flow of a client-side app should be:

Securely obtain the tokens -> Store the tokens -> Cares about the tokens'
lifetime

Obtaining the token: Using OAuth, or some custom authorization system.

Store the tokens: `localStorage`.

Cares about the tokens' lifetime: The purpose is keeping the user logged in for
as long as possible, without a re-login. That involves using refresh token,
because using just the access token is problematic in that if it's lost, it's
hard to handle the aftermath. The same can be said to losing a refresh token, so
Refresh token rotation is the solution, and it's the current best practice.

---

Question: Why can't access token just also act as a refresh token?

[link](https://stackoverflow.com/a/39003201)

I mean, it could still rotates like the Refresh token rotation, so if any access
token is used twice, the entire family of access token could just also be
invalidated.

Answer:

The most crucial reason is that the Access Token is exchanged with the Resource
Server (an API), but the Refresh Token is exchanged only with the Authorization
Server, like Google.

The Resource Server only has their hands on a short-lived Access Token, so if
the Resource Server's implementation is flawed and leaks the Access Token, for
example:

> query param in a log file on an insecure resource server, beta or poorly coded
> resource server app, JS SDK client on a non https site that puts the
> access_token in a cookie, etc
>
> [link](https://mailarchive.ietf.org/arch/msg/oauth/vSmJ0zjQzZFjeFbRz_qpvjfpAeU/)

... then they can only leak the short-lived Access Token. If this were to be a
Refresh Token instead, as in the case of an Access Token also being a Refresh
Token, then instead of a short 10-minute window of time of exploit, now the
attacker could have a much longer exploit time window of a Refresh Token,
assuming that the user never use that Refresh Token again in the meantime (to
invalidate it).

So, the Resource Server is not trusted to hold on to a more valuable Refresh
Token. They only have the user's authorization for a short time, say, 10
minutes. Don't send your Refresh Token there.
