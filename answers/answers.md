CONTENT
- [SECURITY BASICS](#security-basics)
    - [MITM](#man-in-the-middle-attack)
    - [OWASP Top 10](#owasp-top-10)
    - [Same-Origin Policy](#same-origin-policy)
    - [CORS](#cross-origin-resource-sharing)

# SECURITY BASICS

## Man-in-the-middle attack

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
- data type is limited (must be a JS file, which means it's a plain text, but don't forget data URI)
<br>
<br>

## CSRF
Let's suppose someone manages to trick you into visiting https://faceboook.com
(extra "o"). On this website, there is an iframe which loads the content of the
correct site https://facebook.com. As usual, you login into your Facebook
account. Now, the malicious website (faceboook.com) can read your private
messages or perform actions on your behalf with just a few Asynchronous
JavaScript and XML (AJAX) requests. One such attack is known as Cross-Site
Request Forgery (CSRF).
<br>
<br>










--------------------
**Serialization** means taking objects from the application code and converting
them into a format that can be used for another purpose, such as storing the
data to disk or streaming it.

**Deserialization** is just the opposite: converting serialized data back into
objects the application can use.
