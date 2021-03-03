CONTENT
- [SECURITY BASICS](#security-basics)
    - [MITM](#man-in-the-middle-attack)
    - [OWASP Top 10](#owasp-top-10)
    - [Same-Origin Policy](#same-origin-policy)
    - [CORS](#cross-origin-resource-sharing)
    - [CSP](#content-security-policy)
    - [CSRF](#cross-site-request-forgery)
    - [Auth Types](#auth-types)
        -[Cookies](#cookies)
        -[JWT](#jwt)
        -[Options for Auth in SPAs/APIs](#options-for-auth-in-spas/apis)
        -[OAuth](oauth)

# SECURITY BASICS

## Man-in-the-middle attack
A **man-in-the-middle** attack is a type of eavesdropping attack and consists
of sitting between the connection of two parties and either observing or
manipulating traffic.

*Techniques* of MITM Attacks:
- *Sniffing*: Attackers use packet capture tools to inspect packets at a low
  level. 
- *Packet Injection*: An attacker injects malicious packets into data
  communication streams.Packet injection usually involves first sniffing to
  determine how and when to craft and send packets.
- *Session Hijacking*: when an attacker gains access to an online session via a
  stolen session key or stolen browser cookies(by sniffing).
- *SSL stripping* - downgrades a HTTPS connection to HTTP by intercepting the
  TLS authentication sent from the application to the user, as a result
  requests go to a HTTP equivalent endpoint, forcing the host to make requests
  to the server unencrypted. Sensitive information can be leaked in plain text.

*Types* of MITM Attacks:
- *Email Hijacking*
- *Wi-Fi Eavesdropping*
- *DNS Spoofing* - altering a website's address record within a DNS (domain name
  server) server and a victim unknowingly visits the fake site.
- *IP Spoofing* - involves an attacker disguising himself as an application by
  altering packet headers in an IP(internet protocol) address. As a result,
  users attempting to access a URL connected to the application are sent to the
  attacker's website.
- *HTTPS spoofing* - sends a phony certificate to the victim's browser once the
  initial connection request to a secure site is made. It holds a digital
  thumbprint associated with the compromised application, which the browser
  verifies according to an existing list of trusted sites. The attacker is then
  able to access any data entered by the victim before it's passed to the
  application.
- *SSL hijacking* - occurs when an attacker passes forged authentication keys to
  both the user and application during a TCP handshake. This sets up what
  appears to be a secure connection when, in fact, the man in the middle
  controls the entire session.

Detecting a Man-in-the-middle attack can be difficult. If you aren't actively
searching to determine if your communications have been intercepted, a
Man-in-the-middle attack can potentially go unnoticed until it's too late.
*Checking for proper page authentication* and *implementing some sort of tamper
detection* are typically the key methods to detect a possible attack.

*To prevent*:
- Strong encryption mechanism on wireless access points
- Create separate wifi networks for guests, internal use, and business
  application data transfers.
- Force HTTPS
- Certificate Pinning: restricts which certificates are considered valid for a
  particular website 
- VPNs can be used to create a secure environment for sensitive information
  within a local area network. They use key-based encryption to create a subnet
  for secure communication.
- Enable multi-factor authentication (MFA) on all network assets and
  applications
<br>
<br>
## OWASP Top 10
The Open Web Application Security Project® (**OWASP**) is a nonprofit foundation
that works to improve the security of software.

By writing code and performing robust testing with these risks in mind,
developers can produce more secure code.

The **OWASP Top 10** is a list of the 10 most common web application security risks.

1. **Injection**(SQL, NoSQL, OS, LDAP): attacks happen when untrusted data is
   sent to a code interpreter through a form input or some other data
   submission to a web application.
   *To prevent*:
   - Use a safe API which avoids the use of the interpreter entirely
   - validating and/or sanitizing user-submitted data
   - Use positive or "whitelist" server-side input validation
   - Escape special characters
   - Use LIMIT and other SQL controls within queries(*parameterized queries*)
     to prevent mass disclosure of records in case of SQL injection.
   <br>
2. **Broken Authentication**: Vulnerabilities in authentication (login) systems
   can give attackers access to user or admin accounts.
   *To prevent*:
   - Implement multi-factor authentication
   - Do not deploy systems with default credentials
   - Enforce strong passwords
   - Harden all authentication-related processes like registration and
     credential recovery
   - Limit or delay failed login attempts
   - Use a secure, built-in, server-side session manager
   <br>
3. **Sensitive Data Exposure**: It consists of compromising data that should
   have been protected: credentials, credit card, social security, etc.
   *To prevent*:
   - Don't store sensitive data unless absolutely needed, use tokenization,
     discard it as soon as possible
   - Encrypt all sensitive data
   - Encrypt data in transit using secure protocols like TLS and HSTS
   - Disable caching for sensitive data
   - Store passwords using strong, salted hashing functions like Argon2, scrypt
     and bcrypt
   <br>
4. **XML External Entities (XXE)**: For web applications that parse XML input,
   a poorly configured XML parser can be tricked to send sensitive data to an
   unauthorized external entity.
   *To prevent*:
   - Use simpler data formats like JSON and avoid serialization
   - Validate XML
   - Patch or upgrade all XML processors and libraries
   - Disable XML external entity and DTD processing
   - Implement whitelisting and sanitization of server-side XML inputs
   <br>
5. **Broken Access control**: Restrictions on what authenticated users are
   allowed to do are often not properly enforced. Attackers can exploit these
   flaws to access unauthorized functionality and/or data.
   *To prevent*:
   - Adopt a least privileged approach (each role is granted the lowest
     level of access required to perform its tasks)
   - Deny access by default, except for public resources
   - Delete accounts that are no longer needed
   - Audit activity on servers and websites so that you are aware of who is
     doing what (and when)
   - Log failed access attempts and alert admins
   - Enforce record ownership━don't allow users to create, read or delete any
     record
   - Rate limit API and controller access
   - JWT tokens should be invalidated logout
   <br>
6. **Security misconfigurations**: It is often the result of using default
   configurations or displaying excessively verbose errors.
   *To prevent*:
   - Deploy minimal platforms and remove unused features and services.
   - Use templates to deploy development, test, and production environments
     that are preconfigured to meet the organization’s security policies.
   - Continuously monitor resources, applications, and servers for security
     misconfigurations and remediate detected issues in real time, using
     automated workflow wherever possible.
   <br>
7. **Cross Site Scripting (XSS)**: XSS vulnerabilities occur when web
   applications allow users to add custom code into a URL path or onto a
   website that will be seen by other users. 
   *Types of XSS*:
   - **Reflected XSS**: The application or API includes unvalidated and
     unescaped user input as part of HTML output. A successful attack can allow
     the attacker to execute arbitrary HTML and JavaScript in the victim’s
     browser. Typically the user will need to interact with some malicious link
     that points to an attacker-controlled page, such as malicious watering
     hole websites, advertisements, or similar.
   - **Stored XSS**: The application or API stores unsanitized user input that
     is viewed at a later time by another user.
   - **DOM XSS**: JavaScript frameworks and APIs that dynamically include
     attacker-controllable data to a page are vulnerable to DOM XSS. Ideally,
     the application would not send attacker-controllable data to unsafe
     JavaScript APIs. Typical XSS attacks include session stealing, account
     takeover, MFA bypass, DOM-node replacement or defacement (such as Trojan
     login panels), attacks against the user’s browser such as malicious
     software downloads, keylogging, and other client-side attacks.
   *To prevent*:
   - Escaping untrusted HTTP requests
   - Validating and/or sanitizing user-generated content
   - Using frameworks that automatically escape XSS by design, e.g. ReactJS
   - Take a zero-trust approach to user input data. Separate active browser
     content from unvalidated data
   - Implement code vulnerability testing at the design and development phases,
     and scan code in production environments as well
   - Use a web application firewall
   - Enabling a content security policy (CSP) 
   - Encode data on output: in HTTP responses encode the output to prevent it
     from being interpreted as active content. Depending on the output context,
     this might require applying combinations of HTML, URL, JavaScript, and CSS
     encoding
   - Use appropriate response headers: to prevent XSS in HTTP responses that
     aren't intended to contain any HTML or JavaScript, you can use the
     *Content-Type* and **X-Content-Type-Options** headers to ensure that
     browsers interpret the responses in the way you intend
   <br>
8. **Insecure Deserialization**: is the result of deserializing data from
   untrusted sources, and can result in serious consequences like DDoS attacks
   and remote code execution attacks.
   *To prevent*:
   - Prohibit the deserialization of data from untrusted sources
   - Implement digital signatures to ensure the integrity of serialized objects
   - Initiate type constraints during deserialization so that application code
     detects unexpected classes
   - Run deserialization code in low privilege environments to prevent
     unauthorized actions.
   <br>
9. **Using Components with known vulnerabilities**: No matter how secure your
   own code is, attackers can exploit APIs, dependencies and other third-party
   components if they are not themselves secure.
   *To prevent*:
   - Remove all unnecessary dependencies
   - Have an inventory of all your components on the client-side and
     server-side
   - Obtain components only from official sources
   - Get rid of components not actively maintained
   - Monitor sources like Common Vulnerabilities and Disclosures (CVE) and
     National Vulnerability Database (NVD) for vulnerabilities in the
     components
   <br>
10.**Insufficient logging and monitoring**: Failing to log errors or attacks
and poor monitoring practices can introduce a human element to security risks.
   *To prevent*:
   - Make sure that all login failures, access control failures, and
     server-side input validation failures are logged with context so that you
     can identify suspicious activity
   - Ensure that logs are generated in a format that can be easily consumed by
     a centralized log management solutions
   - Penetration testing
   - Establishing effective monitoring practices
<br>
<br>

## Same-Origin Policy

The **origin** denotes the exact location of a specific resource (image,
script, etc.). It consists of three main elements: the protocol (e.g., HTTP or
HTTPS), the hostname (e.g., hackedu.io) and the port (80, 443, 8080, etc.).

When the browser performs *same-origin policy* (SOP) checks, it compares the
originating location with the location of the requested resource.
The *SOP* purpose is to restrict cross-origin interactions between documents,
scripts, or media files.

It is a common misconception that same-origin policy blocks all cross-origin
resources. If that were true Content Delivery Networks (CDNs) wouldn't exist.
There are several HTML tags that generally allow embedded cross-origin
resources: iframe, img, script, video, link, object, embed, form. Please note
that they do not also permit cross-origin read. The difference between
embedding and reading a resource is that when embedded, the resource is copied
from the external origin and rendered locally, while reading the resource means
their origin is preserved.
<br>
<br>

## Cross-Origin Resource Sharing
*Cross-Origin Resource Sharing* (CORS) allows servers to specify trusted origins
that can be used in cross-origin requests by adding a HTTP header.
A CORS request can be either **Simple** or **Preflight**.

**Simple request**(no preliminary checks): HTTP method is `GET`, `POST`, or
`HEAD` and the `Content`-Type is `text/plain`, `application/x-www-form-urlencoded`
or `multipart/form-data`.
In this case, the browser adds an `Origin`: header describing the origin from
where the request has been initiated. Once the request is received the server
tells the browser if the CORS request is valid by appending the
`Access-Control-Allow-Origin` header to the response.
Once the browser receives the HTTP response, it checks whether the request
origin matches the value of `Access-Control-Allow-Origin` header. If the check
fails, the response is blocked immediately.

`Access-Control-Allow-Origin` header supports only a single origin. This means
you cannot specify multiple websites as the value of this header.  However, it
supports the wildcard operator (\*) which tells the server that any
cross-request should be allowed. This is a bad idea unless you want anyone to
consume your restful API.

Any request that is not considered *Simple* (i.e, uses a different HTTP method
or the `Content-Type`) is called a **Preflight** request. This is because the
browser sends a preflight request before the original request to make sure that
the original request is acceptable to the server.

CORS is just one method to relax same-origin policies. There are also other
methods, such as JSON with Padding (**JSONP**) or **cross-document messaging**.
JSONP works by constructing a `script` element (either in HTML markup or
inserted into the DOM via JavaScript), which requests to a remote data service
location. The response is a JavaScript with name of the pre-defined function
along with parameter being passed that is the JSON data being requested.
That's all there is to know about JSONP: it's a callback and script tags.

The *good* part of JSONP:
- compatible with all browsers
- easy to use
- cross-domain
The *bad* part of JSONP:
- not safe for passing data to server
- client-side control
- data type is limited (must be a JS file, which means it's a plain text, but
  don't forget data URI)
<br>
<br>

## Content Security Policy
**Content-Security-Policy(CSP)** is a standardized set of directives that tell
the browser what content sources can be trusted and which should be blocked.
You define the policy via an *HTTP header* with rules for all types of assets.
With CSP you can effectively disallow inline scripts and that means you’ll have
to move all of your own inline scripts to external files. However, that's good
practice anyway and usually allows you to reuse a greater amount of scripts
than before.

CSP helps guard against cross-site scripting attacks (XSS).

CSP-compliant browsers only run scripts contained source files that are
retrieved from *whitelisted domains*, and ignore all other scripts (including
inline script and HTML event handling attributes).
In addition to whitelisting domains from which a browser may load content,
servers can also specify the *allowed protocols*. For example, the server can
specify that browsers must load content via HTTPS.

If you use the **Content-Security-Policy-Report-Only** header (instead of the
Content-Security-Policy one), it will only report violations but won't block
any content. Both headers support the `report-uri` directive to indicate where
the reports should be sent to.

In addition, CSP can prevent the following common vulnerabilities:
- Unsigned inline CSS statements in `<style>` tags
- Unsigned inline Javascript in `<script>` tags
- Dynamic CSS using `CSSStyleSheet.insertRule()`
- Dynamic Javascript code using `eval()`

<br>
<br>

## Cross-Site Request Forgery 
**Cross-Site Request Forgery (CSRF)** is an attack that forces an end user to
execute unwanted actions on a web application in which they’re currently
authenticated.
A CSRF attack works because browser requests automatically include all cookies
including session cookies. Therefore, if the user is authenticated to the site,
the site cannot distinguish between legitimate requests and forged requests.
The impact of a successful CSRF attack is limited to the capabilities exposed
by the vulnerable application and privileges of the user. 

Let's suppose someone manages to trick you into visiting https://faceboook.com
(extra "o"). On this website, there is an iframe which loads the content of the
correct site https://facebook.com. As usual, you login into your Facebook
account. Now, the malicious website (faceboook.com) can read your private
messages or perform actions on your behalf with just a few Asynchronous
JavaScript and XML (AJAX) requests. One such attack is known as Cross-Site
Request Forgery (CSRF).

Any Cross-Site Scripting (XSS) can be used to defeat all CSRF mitigation techniques!

A CSRF token is a secure random token that is used to prevent CSRF attacks. A
CSRF secure application assigns a unique CSRF token for every user session.
These tokens are inserted within hidden parameters of HTML forms related to
critical server-side operations. They are then sent to client browsers. The
CSRF tokens must be a part of the HTML form - not stored in session cookies.

The following principles should be followed to defend against CSRF:
- Check if your framework has built-in CSRF protection and use it
    - If framework does not have built-in CSRF protection add *CSRF tokens* to
      all state changing requests (requests that cause actions on the site) and
      validate them on backend
- Always use `SameSite` Cookie Attribute for session cookies
- Implement at least one mitigation from Defense in Depth Mitigations section:
    - Use custom request headers
    - Verify the origin with standard headers
    - Use double submit cookies
- Consider implementing user interaction based protection for highly sensitive operations
- Do not use GET requests for state changing operations.
<br>
<br>

## Authorization Types

**authentication**: verifying identity (401 Unauthorized)
**authorization**: verifying permissions (403 Forbidden)

**stateful** (i.e. session using a cookie)
**stateless** (i.e. token using JWT / OAuth / other)
<br>

**Sessions**
*Flow*:
- user submits login credentials, e.g. email & password
- server verifies the credentials against the DB
- server creates a temporary user session
- sever issues a cookie with a session ID
- user sends the cookie with each request
- server validates it against the session store & grants access
- when user logs out, server destroys the sess. & clears the cookie

*Features*:
- every user session is stored server-side (**stateful**)
  - memory (e.g. file system)
  - cache (e.g. `Redis` or `Memcached`), or
  - DB (e.g. `Postgres`, `MongoDB`)
- each user is identified by a session ID
  - **opaque** ref.
    - no 3rd party can extract data out
    - only issuer (server) can map back to data
  - stored in a cookie
    - signed with a secret
    - protected with flags
- SSR web apps, frameworks (`Spring`, `Rails`), scripting langs (`PHP`)
<br>
**Tokens**
*Flow*:
- user submits login _credentials_, e.g. email & password
- server verifies the credentials against the DB
- sever generates a temporary **token** and embeds user data into it
- server responds back with the token (in body or header)
- user stores the token in client storage
- user sends the token along with each request
- server verifies the token & grants access
- when user logs out, token is cleared from client storage

*Features*:
- tokens are _not_ stored server-side, only on the client (**stateless**)
- _signed_ with a secret against tampering
  - verified and can be trusted by the server
- tokens can be *opaque* or *self-contained*
  - carries all required user data in its payload
  - reduces database lookups, but exposes data to XSS
- typically sent in `Authorization` header
- when a token is about to expire, it can be _refreshed_
  - client is issued both access & refresh tokens
- used in SPA web apps, web APIs, mobile apps
<br>
<br>

### Cookies

- `Cookie` header, just like `Authorization` or `Content-Type`
- used in session management, personalization, tracking
- consists of *name*, *value*, and (optional) *attributes* / *flags*
- set with `Set-Cookie` by server, appended with `Cookie` by browser

**Security**:
- signed (`HMAC`) with a secret to mitigate tampering
- *rarely* encrypted (`AES`) to protected from being read
  - no security concern if read by 3rd party
  - carries no meaningful data (random string)
  - even if encrypted, still a 1-1 match
- encoded (`URL`) - not for security, but compat

**Attributes**:
- `Domain` and `Path` (can only be used on a given site & route)
- `Expiration` (can only be used until expiry)
  - when omitted, becomes a *session cookie*
  - gets deleted when browser is closed

**Flags**:
- `HttpOnly` (cannot be read with JS on the client-side)
- `Secure` (can only sent over encrypted `HTTPS` channel), and
- `SameSite` (can only be sent from the same domain, i.e. no CORS sharing)

**CSRF**:
- unauthorized actions on behalf of the authenticated user
- mitigated with a CSRF token (e.g. sent in a separate `X-CSRF-TOKEN` cookie)
<br>
<br>

### JWT (JSON Web Tokens)
JSON Web Tokens (JWT) is a method of communicating between two parties securely.

- open standard for authorization & info exchange
- *compact*, *self-contained*, *URL-safe* tokens
- signed with *symmetric* (secret) or *asymmetric* (public/private) key
- contains **header** (meta), **payload** (claims), and **signature** delimited by `.`

**Security**:
- signed (`HMAC`) with a secret
  - guarantees that token was not tampered
  - any manipulation (e.g. exp. time) invalidates token
- *rarely* encrypted (`JWE`)
  - (web) clients need to read token payload
  - can't store the secret in client storage securely
- encoded (`Base64Url`) - not for security, but transport(one way of making
  sure the data is uncorrupted as it does not compress or encrypt data)
  - payload can be decoded and read
  - no sensitive/private info should be stored
  - access tokens should be short-lived

**XSS**:
- client-side script injections
- malicious code can access client storage to
  - steal user data from the token
  - initiate AJAX requests on behalf of user
- mitigated by sanitizing & escaping user input

**Client Storage**
JWT can be stored in client storage, `localStorage`(Browser key-value store
with a simple JS API) or `sessionStorage`:
  - `localStorage` has no expiration time
  - `sessionStorage` gets cleared when page is closed

*Pros*:
- domain-specific, each site has its own, other sites can't read/write
- max size higher than cookie (`5 MB` / domain vs. `4 KB` / cookie)

*Cons*:
- plaintext, hence not secure by design
- limited to string data, hence need to serialize
- can't be used by web workers
- stored permanently, unless removed explicitly
- accessible to any JS code running on the page (incl. XSS)
  - scripts can steal tokens or impersonate users

*Best for* public, non-sensitive, string data

*Worst for*:
- private sensitive data
- non-string data
- offline capabilities
<br>

**Sessions + Cookies vs. JWT**
*Pros*:
- session IDs are opaque and carry no meaningful data
- cookies can be secured with flags (same origin, HTTP-only, HTTPS, etc.)
- HTTP-only cookies can't be compromised with XSS exploits
- battle-tested 20+ years in many langs & frameworks

**Cons**
- server must store each user session in memory
- session auth must be secured against CSRF
- horizontal scaling is more challenging
  - risk of single point of failure
  - need sticky sessions with load balancing
<br>

**JWT Auth**
*Pros*:
- server does not need to keep track of user sessions
- horizontal scaling is easier (any server can verify the token)
- CORS is not an issue if `Authorization` header is used instead of `Cookie`
- FE and BE architecture is decoupled, can be used with mobile apps
- operational even if cookies are disabled

*Cons*:
- server still has to maintain a blacklist of revoked tokens
  - defeats the purpose of stateless tokens
  - a whitelist of active user sessions is more secure
- when scaling, the secret must be shared between servers
- data stored in token is "cached" and can go *stale* (out of sync)
- tokens stored in client storage are vulnerable to XSS
  - if JWT token is compromised, attacker can
    - steal user info, permissions, metadata, etc.
    - access website resources on user's behalf
- requires JavaScript to be enabled
<br>
<br>

### Options for Auth in SPAs/APIs
1. Sessions
2. Stateless JWT
3. Stateful JWT

**Stateless JWT**:
- user payload embedded in the token
- token is signed & `base64url` encoded
  - sent via `Authorization` header
  - stored in `localStorage` / `sessionStorage` (in plaintext)
- server retrieves user info from the token
- no user sessions are stored server side
- only revoked tokens are persisted
- refresh token sent to renew the access token

**Stateful JWT**:
- only user ref (e.g. ID) embedded in the token
- token is signed & `base64url` encoded
  - sent as an HTTP-only cookie (`Set-Cookie` header)
  - sent along with non-HTTP `X-CSRF-TOKEN` cookie
- server uses ref. (ID) in the token to retrieve user from the DB
- no user sessions stored on the server either
- revoked tokens still have to be persisted

**Sessions**:
- sessions are persisted server-side and linked by sess. ID
- session ID is signed and stored in a cookie
  - sent via `Set-Cookie` header
  - `HttpOnly`, `Secure`, & `SameSite` flags
  - scoped to the origin with `Domain` & `Path` attrs
- another cookie can hold CSRF token

**Verdict**: Sessions are (probably) better suited for web apps and websites.

**Why not JWT?**
- server state needs to be maintained either way
- sessions are easily extended or invalidated
- data is secured server side & doesn't leak through XSS
- CSRF is easier to mitigate than XSS (still a concern)
- data never goes stale (always in sync with DB)
- sessions are generally easier to set up & manage
- most apps/sites don't require enterprise scaling

**Important**
Regardless of auth mechanism:
- XSS can compromise user accounts
  - by leaking tokens from `localStorage`
  - via AJAX requests with user token in `Authorization`
  - via AJAX requests with `HttpOnly` cookies
- SSL/HTTPS must be configured
- security headers must be set

**Auxiliary measures**:
- IP verification
- user agent verification
- two-factor auth
- API throttling
<br>
<br>

### OAuth
**OAuth** is an open standard for *access delegation*, commonly used as a way to
grant websites or applications access to their information on other websites
but *without* giving them the *password*.
OAuth works over HTTPS and authorizes devices, APIs, servers, and applications
with access tokens rather than credentials. It decouples authentication from
authorization.
OAuth is an internet-scale solution because it's per application. You often
have the ability to log in to a dashboard to see what applications you've given
access to and to revoke consent.

OAuth is where:
1. App requests authorization from User
2. User authorizes App and delivers proof
3. App presents proof of authorization to server to get a Token
4. Token is restricted to only access what the User authorized for the specific App

OAuth is built on the following central components:
- Scopes and Consent:
    - Scopes are what you see on the authorization screens when an app requests
      permissions. Scopes decouple authorization policy decisions from
      enforcement.
    - The consent can vary based on the application. It can be a time-sensitive
      range (day, weeks, months), but not all platforms allow you to choose the
      duration. 
- Actors:
    - Resource Owner
    - Resource Server
    - Client
    - Authorization Server (The main engine of OAuth)
- Clients (can be public and confidential)
- Tokens (Access and Refresh tokens)
- Authorization Server
- Flows
    - *Implicit Flow*(2 Legged OAuth) is optimized for browser-only public clients. There is no
      backend server redeeming the authorization grant for an access token. An
      SPA is a good example of this flow’s use case. This flow is also called.
      *Cons*: lots of redirects and lots of room for errors.
    - *Authorization Code*(3 Legged) uses both the front channel and the back channel.
    - *Client Credential* is used for server-to-server scenarios
    - *Assertion Flow*  is similar to the client credential flow





--------------------
**Serialization** means taking objects from the application code and converting
them into a format that can be used for another purpose, such as storing the
data to disk or streaming it.

**Deserialization** is just the opposite: converting serialized data back into
objects the application can use.
