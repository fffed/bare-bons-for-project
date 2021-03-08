CONTENT
- [COMMUNICATION PROTOCOLS]
    - [TCP/TSL/UDP](#tsptsludp)
    - [HTTPS Purpose](#https-purpose)
    - [HTTP vs HTTP 2.0 Advantages](#http-vs-http-2.0-advantages)
- [SECURITY BASICS](#security-basics)
    - [MITM](#man-in-the-middle-attack)
    - [OWASP Top 10](#owasp-top-10)
    - [Same-Origin Policy](#same-origin-policy)
    - [CORS](#cross-origin-resource-sharing)
    - [CSP](#content-security-policy)
    - [CSRF](#cross-site-request-forgery)
    - [Authorization Types](#authorization-types)
        - [Cookies](#cookies)
        - [JWT](#jwt)
        - [Options for Auth in SPAs](#options-for-auth-in-spas--apis)
        - [OAuth](#oauth)
    - [Security Headers](#security-headers)
- [PERFORMANCE OPTIMIZATIONS](#performance-optimizations)
   - [Critical Rendering Path](#critical-rendering-path)
   - [High performant animations](#high-performant-animations)
   - [Repaint/reflow](#repaintreflow)
   - [Layout thrashing](#layout-thrashing)
   - [Performance measurement and profiling](#performance-measurement-and-profiling)
   - [RAIL Model](#rail-model)


# COMMUNICATION PROTOCOLS

## TCP/TSL/UDP basics

## HTTPS Purpose

## HTTP vs HTTP 2.0 Advantages

HTTP 2.0 in a nutshell:
- New binary framing
- One connection (session)
- Many parallel requests (streams)
- Header compression
- Stream prioritization
- Server push

**HTTP server push** server can push multiple resources in response to one
request. Client can cancel stream if it doesn't want the resource. Resource
goes into browsers cache. "Inlining" is a variant of "Server Push".

# SECURITY BASICS

## Man-in-the-middle attack
A **man-in-the-middle** attack is a type of eavesdropping attack and consists
of sitting between the connection of two parties and either observing or
manipulating traffic(e.g., chrome pluggin).

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

Tools to improve the security and code quality:
 - Static Application Security Testing (SAST) Tools
 - Dynamic Application Security Testing (DAST) Tools (Primarily for web apps)
 - Interactive Application Security Testing (IAST) Tools (Primarily for web apps and web APIs)
 - Keeping Open Source libraries up-to-date (to avoid Using Components with Known Vulnerabilities)
 - Static Code Quality Tools(SonarQube, npm audit)


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

   *Types* of attacks:
   - Brute-force Attack
   - Rainbow Tables Cracking(Rainbow Table is a large dictionary with
     pre-calculated hashes and the passwords from which they were calculated).
     To protect against a rainbow-table attack, combine a random value,
     referred to as salt, with the password before encrypting it.
   - Session Stealing
   
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
   unauthorized external entity. Also for FE actual svg and pdf formats.
   
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
   - Enforce record ownership - don't allow users to create, read or delete any
     record
   - Rate limit API and controller access
   - JWT tokens should be invalidated on logout
   <br>
6. **Security misconfigurations**: It is often the result of using default
   configurations or displaying excessively verbose errors.
   
   *To prevent*:
   - group roles instead of an individual user access 
   - whitelisting
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
     `Content-Type` and `X-Content-Type-Options` headers to ensure that
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
10. **Insufficient logging and monitoring**: Failing to log errors or attacks
and poor monitoring practices can introduce a human element to security risks.

   *To prevent*:
   - Make sure that all login failures, access control failures, and
     server-side input validation failures are logged with context so that you
     can identify suspicious activity
   - Ensure that logs are generated in a format that can be easily consumed by
     a centralized log management solutions
   - Penetration testing
   - Establishing effective monitoring practices

Any question could be escalate to security team if necessary that could help.
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

Helmet.js helps you secure your Express apps by setting various HTTP headers.
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

HTTPS helps with preventing CSRF attacks
<br>
<br>

## Authorization Types

**authentication**: verifying identity (401 Unauthorized)
**authorization**: verifying permissions (403 Forbidden)

**stateful** (i.e. session using a cookie)
**stateless** (i.e. token using JWT / OAuth / other)

**Basic authentication** is a simple authentication scheme built into the HTTP
protocol. The client sends HTTP requests with the `Authorization` header that
contains the word `Basic` word followed by a space and a base64-encoded string
`username:password`.
<br>

**SESSIONS**

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

**TOKENS**

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
- encoded (`URL`) - not for security

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
- signed with *symmetric* (secret) or *asymmetric* (public/private) key(if
  someone could read data from token he couldn't sign it with exactly the same
  signature without 'secret')
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
  - no sensitive/private info should be stored (as could be easily read)
  - access tokens should be short-lived

*Amazon Cognito* provides authentication, authorization, and user management for
your web and mobile apps. Your users can sign in directly with a user name and
password, or through a third party such as Facebook, Amazon, Google or Apple.

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

### Options for Auth in SPAs / APIs
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

*Pros*:
 - Popularity — most companies use OAuth in their APIs.
 - Simplicity of implementation and a large amount of manuals and reference materials.
 - Availability of the ready-made solutions that can be changed to fit your needs.

*Cons*:
 - Data misuse
 - There is no common format, as a result, each service requires its own implementation.
 - When a token is stolen, an attacker gains access to the secure data for a
   while. To minimize this risk a token with signature can be used.
 - If service have some problems then everyone would experience them also
<br>
<br>

## Security Headers
**HTTP security headers** are a subset of HTTP headers and are exchanged between a
web client and a server to specify the security-related details of HTTP communication.
HTTP security headers provide an extra layer of security by restricting
behaviors that the browser and server allow once the web application is
running.

*The Most Important HTTP Security Headers*:
- *Strict-Transport-Security*: HTTP Strict Transport Security (HSTS) enforces the
  use of encrypted HTTPS connections instead of plain-text HTTP communication.
- *Content-Security-Policy*: allows you to precisely control permitted content
  sources and many other parameters(prevent XSS).
- *X-Frame-Options*: prevent a page from being loaded into any iframes(prevent XSS) 
- *X-Content-Type-Options*: tells the browser, strictly follow provided
  Mime/Type, and don't try to guess.
- *Feature-Policy*:  is designed to turn off features that you don't expect to
  be used(e.g. webcam)
- *Referrer-Policy*: controls how much of the referrer information (host, query
  params, etc) are sent within the request.  
- *Cache Control*: indicates the preferences for caching the page output.   
<br>
<br>

# PERFORMANCE OPTIMIZATIONS

## Critical Rendering Path

The **Critical Rendering Path** is the sequence of steps the browser goes through
to convert the HTML, CSS, and JavaScript into pixels on the screen. Optimizing
the critical render path improves render performance.

1. Constructing the DOM Tree
2. Constructing the CSSOM Tree
3. Running JavaScript
4. Creating the Render Tree
5. Generating the Layout
6. Painting

Once the browser gets the response, it starts parsing it. When it encounters a
dependency, it tries to download it. If it's a *stylesheet* file, the browser
will have to parse it completely before rendering the page, and that's why
**CSS is** said to be **render blocking**. If it's a *script*, the browser has
to: stop parsing, download the script, and run it. Only after that can it
continue parsing, because JavaScript programs can alter the contents of a web
page (HTML, in particular). And that's why **JS is** called **parser blocking**.
This why, if we have a JavaScript file that references elements within the
document, it must be placed after the appearance of that document.

*Sync* scripts block the parser - use `async` scripts.

DOM is constructed incrementally, as the bytes arrive on the "wire". Unlike
HTML parsing, CSS is not incremental - we must wait for the entire file.

The **Render Tree** is a combination of both the DOM and CSSOM. It is a Tree that
represents what will be eventually rendered on the page. This means that it
only captures the visible content and will not include, for example, elements
that have been hidden with CSS using `display: none`.

Once render tree is ready, perform **layout (reflow)** (aka, compute size of
all the nodes, etc.), it's based on *meta* `viewport` tag in HTML.Once layout
is complete, render pixels to the screen.

**Initial view** - also known as **"above the fold"**, is the part of a web page
visible to a user before they scroll.

**Stylesheets optimization**:
The browser will only treat the resources that match the current *media*
(device type, screen size) as necessary, while lowering the priority of all the
other stylesheets (they will be processed anyway, but not as part of the
critical rendering path). For example, if you add the `media="print"` attribute
to the style tag these styles won't interfere with your critical rendering
path. To further improve the process, you can also make some of the styles
inlined. This saves us at least one roundtrip to the server that would have
otherwise been required to get the stylesheet.

**Performance Optimization Strategies**:
1. Optimize your networking stack: reduce DNS lookups, avoid redirects, fewer
   HTTP requests, use CDN
2. Minimizing the amount of data to be transferred over the wire:
    - **Minifying**,
    - **Compressing**(gzip)
    - **Caching**(`Expires` header),
    - optimize images and pick optimal format
3. Reducing the total number of resources to be transferred over the wire
4. Inline just the required resources for above the fold
5. Defer the rest until after the above the fold is visible
6. Lazy load / defer images and defer / async JS

**Tools to help**:
- Identify critical CSS via Chrome DevTools(Timeline)
<br>
<br>

## High performant animations

There used to be just one way to do a timed loop in JavaScript - `setInterval()`.
For the purposes of animation, the goal is sixty “frames” per second to appear
smooth.
You can stop an animation by getting the timeout or interval reference, and
clearing it.
The problem is that even though we specify this precision accurately, the
browser might be busy performing other operations, and our setTimeout calls
might not make it in time for the repaint, and it's going to be delayed to the
next cycle. This is bad because we lose one frame, and in the next the
animation is performed 2 times.

`requestAnimationFrame` is an API that passes the responsibility of scheduling
animation drawing directly to the browser. It will signal to the browser that a
script-based animation needs to be resampled by enqueuing a **callback** to the
**animation frame request callback list**.

Why better?
- The browser can optimize it, so animations will be smoother
- Frames are only drawn when the browser is ready to paint and there are no
  ready frames waiting to be drawn.
- Animations in background tabs, minimized windows, or otherwise hidden parts
  of a page will stop, allowing the CPU to chill
- More battery-friendly

`requestAnimationFrame` does not:
- Guarantee when it'll paint; only that it'll paint when needed.
- Guarantee the synchronicity of the animations. For example, if you start two
animations at the same time but then one of the animations is in an area that
is visible and the other is not, the first animation will go on playing while
the other will not.
- Paint until the callback function has finished executing, even if you try to
  trigger a reflow mid-callback by using any of the methods that would trigger
  a reflow and repaint in normal conditions, like `getComputedStyle()`


16 milliseconds(60fps, 11.11ms for 90fps) is not a lot of time! The budget is split between:
- Application code(our code)
- Style recalculation
- Layout recalculation
- Garbage collection
- Painting
(Not necessarily in this order, and we (hopefully) don't have to perform all of
them on each frame!)

If we can't finish work in 16 ms *frame* is "dropped" - not rendered. We will
wait until next `vsync`.

Dropped frames = "jank".

To prevent junks:
- Your code must yield control in less than 16 ms! (Aim for <10ms, browser needs to
do extra work: GC, layout, paint. "10 ms" is not absolute - e.g. slower CPU's)
- Browser won't (can't) interrupt your code: split long-running functions,
  aggregate events (e.g. handle scroll events once per frame)

*CSS3 Animations*
If we use properties that only affect the composition step of the rendering
algorithm, we will get the best performance: animate with `transform` and
`opacity` properties.

*Hardware Acceleration*:
GPU is really fast at compositing, matrix operations and alpha blends.
Certain elements are GPU backed automatically: canvas, video, CSS3 animations.

Forcing a GPU layer (to ensure that the browser knows what you plan to
animate):
- In CSS: `will-change` its fallback - `transform:translateZ(0)`,
- In JavaScript: Setting a transform with a 3D characteristic such as
  `translate3d()` and `matrix3d()` will create a layer.

Don't abuse it, it can hurt performance: every layer you create requires GPU
memory and management.

Reduce complexity!

If you need some data processing for an animation, you should consider moving
the task to a web worker. Good use cases are tasks such as data sorting,
searching, and model generation.

CSS(declarative) vs JavaScript(imperative) performance:
- CSS-based animations, and Web Animations where supported natively, are
  typically handled on a thread known as the **"compositor thread"**. This is
  different from the browser's "main thread", where styling, layout, painting,
  and JavaScript are executed. This means that if the browser is running some
  expensive tasks on the main thread, these animations can keep going without
  being interrupted.
- Other changes to `transforms` and `opacity` can, in many cases, also be
  handled by the compositor thread.
- If any animation triggers paint, layout, or both, the "main thread" will be
  required to do work. This is true for both CSS- and JavaScript-based
  animations, and the overhead of layout or paint will likely dwarf any work
  associated with CSS or JavaScript execution, rendering the question moot.
- Animating in JavaScript does give you a lot of control: starting, pausing,
  reversing, interrupting and cancelling are trivial. Some effects, like
  parallax scrolling, can only be achieved in JavaScript.


**Debounce** or **throttle** your input handlers.

The **FLIP technique** pre-optimizes an animation before execution. The idea is to
invert the state of animations. Normally, we animate “straight ahead,” doing
some expensive calculations on every single frame. FLIP precalculates the
changes based on their final states. The first frame is an offset of the final
state. This way the animation plays out in a much cheaper way.


Eliminate jank and memory leaks:
  - Performance == 60 FPS:
      - 16.6 ms budget per frame
      - Shared budget for your code, GC, layout, and painting
      - Use frames view to hunt down and eliminate jank
  - Profile and optimize your code:
      - Profile your JavaScript code
      - Profile the cost of layout and rendering!
      - Minimize CPU > GPU interaction
  - Eliminate JS and DOM memory leaks:
      - Monitor and diff heap usage to identify memory leaks
<br>
<br>

## Repaint/Reflow
The user or your application can perform other tasks during the time that a
repaint or reflow occurring - browser blocking.

Layout phase calculates the size of each element:
- width, height, position
- margins, padding, absolute and relative positions
- propagate height based on contents of each element, etc... 

If we resize the parent container - all elements under it (and around it,
possibly) will have to be recomputed!

Be careful about triggering expensive layout updates: adding nodes, removing
nodes, updating styles, ...

Style recalculation is forcing a layout update (change in size, position, etc.).

- Layout is normally scoped to the whole document.
- The number of DOM elements will affect performance; you should avoid
  triggering layout wherever possible.
- Assess layout model performance; new Flexbox is typically faster than
  float-based layout models.
- Avoid forced synchronous layouts and layout thrashing; read style values then
  make style changes.

**Reflow** is the web browser process for re-calculating the positions and
geometries of elements in the document.

What can trigger reflow:
- resizing the browser window
- scrolling
- using JavaScript methods involving computed styles
- adding or removing elements from the DOM, and changing an element's classes
- etc...

Reflow only has a *cost* if the document has changed and *invalidated* the layout.
Something *Invalidates* + Something *Triggers* = **Costly Reflow**

To minimize reflow:
- Reduce unnecessary DOM depth. Changes at one level in the DOM tree can cause
  changes at every level of the tree - all the way up to the root, and all the
  way down into the children of the modified node.
- Minimize CSS rules, remove unused CSS rules and update classes low in the DOM
  tree
- If you make complex rendering changes such as animations, do so out of the
  flow. Use position-absolute or position-fixed to accomplish this.
- Don't change styles by multiple statements
- Batch DOM changes:
    - Use a `documentFragment` to hold temp changes
    - Clone, update, replace the node
    - Hide the element with `display: none`
- Don't ask for computed styles repeatedly, cache them into variable


DOM/CSSOM modification → dirty tree: ideally, recalculated once, immediately
prior to paint, except you can force a *synchronous* layout (vary bad)!
First iteration marks tree as dirty, second iteration forces layout:
```javascript
  for (n in nodes) {
    n.style.left = n.offsetLeft + 1 + "px";
  }
```
Changing any property apart from `transform` and `opacity` always triggers painting.

Paint process has variable costs based on:
- Total area that needs to be (re)painted: we want to update the minimal amount
- Pixel rendering cost varies based on applied effects: some styles are more
  expensive than others

Paint process in a nutshell - Given layout information of all elements:
- Apply all the visual styles to each element
- Composite all the elements and layers into a bitmap
- Push the pixels to the screen

Paint process has variable costs based on:
- Total area that needs to be (re)painted (We want to update the minimal
  amount)
- Pixel rendering cost varies based on applied effects (Some styles are more
  expensive than others)

Rendering:
- Viewport is split into rectangular tiles - each tile is rendered and cached
- Elements can have own layers - allows reuse of same texture; layers can be
  composited by GPU

Reduce complexity!
<br>
<br>

## Layout thrashing
**Layout Thrashing** is where a web browser has to reflow or repaint a web page
many times before the page is 'loaded'.

Depending on the number of reflows and the complexity of the web page, there is
potential to cause significant delay when loading the page, especially on lower
powered devices such as mobile phones.

When the DOM is written to, layout is **'invalidated'**, and at some point needs to
be reflowed.

Web browsers try to minimize the work by putting operations that require a
reflow into a queue to execute at some point in the future. When required, the
browser will execute everything in the queue as a single reflow. But sometimes
we don't allow the browser to be lazy. If our script requests style information
such as `offsetWidth` or `scrollTop`, the only way that the browser can be sure
to return the correct answer is to execute any reflow operations that are in
the queue.  This means that whenever we request some layout information, we
could potentially be forcing a page reflow.

If we ask for a geometric value back from the DOM before the current operation
(or frame) is complete, the browser has to perform layout early, this is known
as **forced synchonous layout**.

*To prevent*: write your JavaScript in such a way that the number of times the
page has to be reflowed is minimised.
<br>
<br>

## Performance measurement and profiling
Use an Incognito window when profiling code.

<br>
<br>

## RAIL Model
**RAIL**, an acronym for Response, Animation, Idle, and Load, is a performance
model originated by the Google Chrome team in 2015, focused on user experience
and performance within the browser. The performance mantra of RAIL is "Focus on
the user; the end goal isn't to make your site perform fast on any specific
device, it's to make users happy."

**Respond** to users immediately, acknowledging any user input in 100ms or less.

When **animating** or scrolling, render each frame in under 16ms, aiming for
consistency and avoiding jank.

When using the main JavaScript thread, work in chunks for less than 50ms to
free up the thread for user interactions(**Idle**).

Deliver interactive content in less than 1(5?) second(**Load**).

The RAIL model is ultimately just one way of thinking about web performance.
Putting the user in the center of performance.

We don't want to have a quick loading page that then goes unresponsive. We also
don't want a responsive page that takes forever to load. Rather all of these
aspects have an important place in the performance conversation, and RAIL
reminds us of that.

Tips for using the RAIL model:
1. Know your audience
2. Keep up with web development trends
3. Know when to upgrade
4. Prioritize your critical rendering path
5. Identify solutions, not just problems
<br>
<br>






--------------------




-------------------
**Serialization** means taking objects from the application code and converting
them into a format that can be used for another purpose, such as storing the
data to disk or streaming it.

**Deserialization** is just the opposite: converting serialized data back into
objects the application can use.



