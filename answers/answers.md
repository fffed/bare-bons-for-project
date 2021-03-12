# CONTENT
- [PROGRAMMING PARADIGMS](#programming-paradigms)
    - [OOP Principles, pros/cons](#oop-principles-proscons)
    - [Functional Programming, pros/cons](#functional-programming-proscons)
    - [FP vs OOP paradigms, composition over inheritance](#fp-vs-oop-paradigms-composition-over-inheritance)
    - [Reactive programming, pros/cons](#reactive-programming-proscons)
- [COMMUNICATION PROTOCOLS](#communication-protocols)
    - [TCP/TLS/UDP](#tsptlsudp)
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
   - [PRPL pattern](#prpl-pattern)
   - [Network optimizations](#network-optimizations)
   - [CPU bound operations optimizations](#cpu-bound-operations-optimizations)
   - [Web Workers](#web-workers)
   - [Service Workers](#service-workers)
   - [Memory leaks detection](#memory-leaks-detection)
   - [V8 hidden classes and inline caching techniques](#v8-hidden-classes-and-inline-caching-techniques)
   - [Event Loop, microtasks](#event-loop-microtasks)
- [WEB APPLICATION DESIGN AND FRAMEWORK](#web-application-design-and-framework)
   - [SPA vs MPA pros/cons](#spa-vs-mpa-proscons)
   - [SSR vs CSR pros/cons](#ssr-vs-csr-proscons)
   - [Micro-frontends vs monorepos](#micro-frontends-vs-monorepos)
   - [PWA](#pwa)

# PROGRAMMING PARADIGMS

## OOP Principles, pros/cons
**OOP** is a methodology to design a program using classes and objects and aims
to implement real-world entities like(four basic concepts) inheritance,
polymorphism, abstraction and encapsulation.
The main aim of OOP is to **bind together the data and the functions that
operate on them** so that no other part of the code can access this data except
that function.

**Object** - any entity that has state and behavior.

**Class** - logical collection of objects.

**Inheritance**: the capability of an object to derive properties and
characteristics from another object. It provides code *reusability*. It is used
to achieve runtime polymorphism.

**Polymorphism**: If one task is performed in different ways. We could use method
*overloading* and method *overriding* to achieve polymorphism. Example can be to
speak something; for example, a cat speaks meow, dog barks woof, etc.

**Abstraction**: hiding internal details and showing functionality. It reduce
complexity and increase efficiency. We could use *abstract class* and *interface*
to achieve abstraction.  Overall, abstraction helps isolate the impact of
changes made to the code so that if something goes wrong, the change will only
affect the variables shown and not the outside code.

**Encapsulation**: binding (or wrapping) code and data together into a single unit
that keeps both safe from outside interference and misuse.

It provides: 
- Security - controlled access 
- Hide Implementation and Expose Behaviours(ease to support)
- Loose Coupling - modify the implementation at any time
- Better maintenance

OPP +/- (over procedural programming):
- +provides a clear structure for programs 
- +program easier to read and understand 
- +it allows for the parallel development 
- +reusability (via inheritance), scalability, decomposition
- +It offers flexibility through polymorphism
- +security - protects information through encapsulation.
- -more complex structure of a program(переусложнение)
- -everything should be an object (все строется на объектах)
- -trouble with shared state, different things competing for the same resources 
- -OOP codebase can be extremely resistant to change: the relation among all
  the available classes become artificial 
- -problems with multithreading, data management, and mutability if not done right.

# Functional programming, pros/cons
**Functional programming** is **declarative** rather than **imperative** (what
to do, rather than how to do it), and application *state flows through pure
functions*.
Contrast with object oriented programming, where application state is usually
shared and colocated with methods in objects.

Functional programming is a programming paradigm based on some fundamental
principles:

- Pure functions
- Function composition
- Avoid shared state
- Avoid mutating state
- Avoid side effects

A **pure function** is a function that has no side-effects and given the same
inputs, always returns the same output: they are *predictable*, *independent*
(do not use values in surrounding environment), so it helps with memoization as
we can save the result and return it when necessary.

A **side effect** is any application state change that is observable outside
the called function other than its return value.

One of pure function properties is **referential transparency**: you can
replace a function call with its resulting value without changing the meaning
of the program.

**Function composition** is the process of combining two or more functions in
order to produce a new function or perform some computation.

**Shared state** is any variable, object, or memory space that exists in a
shared scope, or as the property of an object being passed between scopes. A
shared scope can include global scope or closure scopes. Often, in object
oriented programming, objects are shared between scopes by adding properties to
other objects.

An **immutable object** is an object that can't be modified after it's created.

Immutability Pros:
- Easier to write, use and *reason about* the code
- *Predictable State*: Object once created cannot be modified
- As there are no side effects so *testing* becomes *easy*
- *Thread safety*: Immutable objects are useful in multi-threaded applications
  because multiple threads can act on the data of immutable objects without
  worrying about changes to the data by other threads.
- *Comparing* two immutable objects are very *cheap* operation. One can simply
  compare the objects address and then tell whether they are equal or not.

Immutability Cons:
- *performance impact*: Immutability works fine with primitive object. In case
  of non-primitive data structure like array it becomes overhead to copy data
  from one location to another location. There is not full proof solution for
  this but we can implement a strategy called “structural sharing”, which
  yields much less memory overhead than expected.

In many functional programming languages, there are special immutable data
structures called **trie data structures** (pronounced “tree”) which are
effectively *deep frozen* — meaning that no property can change, regardless of
the level of the property in the object hierarchy.

**First-Class Citizen** Functions: when function are treated like any other
variable.

**Recursion** is a way of solving problems via the smaller versions of the same
problem. We solve the problem via the smaller sub-problems till we reach the
trivial version of the problem i.e. base case. In other words, a recursive
function is a function that *calls itself* until a "*base condition*" is true,
and execution stops.
The recursive function has two parts: *Base Case* and *Recursive Structure*.

Why we need Recursion?
- it  breaks problems into smaller, independent sub problems(*Divide and Conque*),
  which substantially makes it easier to parallelize

**Disadvantage**: *Stack Overflow* problem; if performance is vital, use loops instead.

A **higher-order function** is a function that gets a function as an argument.
It may or may not return a function as its resulting output.

**Currying** is the process of taking a function that accepts `n` arguments and
turning it into `n` functions that each accepts a single argument. Currying
always returns another function with only one argument until all of the
arguments have been applied. So, we just keep calling the returned function
until we've exhausted all the arguments and the final value gets returned.

**Partial application** is a more generalized version of currying. It is any
function that takes a function with multiple parameters and returns one with
fewer parameters (`.bind` in JS).

Both partial application and currying are related to the ways we invoke
functions — specifically, functions that have more than one parameter. They
allow us to call those functions providing just some of the arguments, leaving
the rest "*for later*".

The concept of *pipe* is simple — it combines `n` functions. It's a pipe flowing
left-to-right, calling each function with the output of the last one.
The main difference between *compose* and *pipe* is the order of the composition.
Compose performs a right-to-left function composition.

**FP Cons**: Over exploitation of FP features such as point-free style and
large compositions can potentially reduce readability because the resulting
code is often more abstractly specified, more terse, and less concrete.

## FP vs OOP paradigms, composition over inheritance

Difference base on key criteria

| Criteria      |           FP                             |           OOP                                     |
|---------------|------------------------------------------|---------------------------------------------------|
| Definition    | focus on function evaluation             | focus on the concept of objects                   |
| Data          | uses immutable data                      | uses the mutable data                             |
| Model         | follows a declarative programming model  | follows an imperative programming model           |
| Support       | supports parallel programming            | doesn't support parallel programming              |
| Execution     | statements can be excecuted in any order | statements should be executed in particular order |
| Iteration     | uses recursion                           | uses loops                                        |
| Basic element | functions & variables                    | objects & methods                                 |

**Inheritance** is a technique we can use to create derived classes that borrow
everything from their parents, except private properties and methods.
Another benefit from the inheritance, mainly on strongly typed languages such
as JAVA, TypeScript, is that variables declared with the type of your parent
class can hold objects from its child classes as well.

**Composition** is creating small reusable functions to make code *modular* and
it allows us to model a **has one** relationship between objects. This in turn,
helps to *encapsulate* state and behavior inside a component and then use that
component from other classes, formally known as composite.
The point of a *component-based approach* is that you can now easily maintain
and modify the code for any of them without affecting the main classes or their
code. These type of relationship is called **loosely coupled**.

**Which one is better then?**
One of the drawbacks to inheritance is that it is based on the fact that it
won't change. We create a class and give it properties and methods that
describe the class. But say, down the road, we need to update that class and
add more functionality. Adding a new method to the base class will create
rippling effects through your entire program.
This is the **tight coupling problem**, things having to depend on one another,
which leads to the **fragile base class problem**, seemingly safe changes cause
unforeseen repercussions. It is the opposite of small reusable code. Changing
one small thing in either of the class or subclasses could break the program.
Another problem is **hierarchy** where you may need to create a subclass that
can only do 1 part of the class, but instead you get everything passed down to
it.
Composition creates a more stable environment that is easier to change in the
future. The key is to decide which structure is better for your project. You
can use ideas from both of these styles to write your code.

**The case for Inheritance**:
Inheritance makes sense because we tend to relate OOP concepts to real-world
objects and then we try to generalize their behavior by generalizing their
nature.  In other words, we don't think of a cat and a doc as having 4 legs and
a set of organs that allow them to either bark or meow. We think of them as
animals, which translates to inheritance.  And because of that, the ideal use
case for going with inheritance is having 80% of your code being common between
two or more classes and at the same time, having the specific code being very
different. Not only that, but having the certainty that there is no case where
you'd need to swap the specific code with each other. Then inheritance is
definitely the way to go, with it you'll have a simpler internal architecture
and less code to think about.

**The case for composition**:
The generic code can be abstracted into different components, which in turn can
be as complex as they need (as long as they keep their public interface the
same) and that we can swap them during runtime, which is very flexible.
The other great benefit I see is that while with inheritance, if you need to
create a new specific class (like adding a `Lion` class now), you'd have to
understand the code of the `FourLeggedAnimal` class to make sure you now what
you're getting from it. And this would be just so that you can implement a
different version of the `speak` method. However, if you went with composition,
all you’d have to do is create a new class implementing the new logic for the
speak method, unaware of anything else, and that's it.
Of course, withing the context of this example, the extra cognitive load of
reading a very simple class might seem irrelevant, however, consider a
real-world scenario where you'd have to go through hundreds of lines of code
just to make sure you understand a base class. That's definitely not ideal.

- Use Inheritance when the relationship is “X is of Y type”.
- Use Composition when the relationship is “X has a Y capability”.

## Reactive programming, pros/cons
**Reactive programming** is a declarative programming paradigm concerned with
data streams and the propagation of change ("react" to changes that happen).

For example, in an imperative programming setting, `a := b + c` would mean that
`a` is being assigned the result of `b + c` in the instant the expression is
evaluated, and later, the values of `b` and `c` can be changed with no effect
on the value of `a`. On the other hand, in reactive programming, the value of
`a` is automatically updated whenever the values of `b` or `c` change, without
the program having to re-execute the statement `a := b + c` to determine the
presently assigned value of `a`.

The most common approaches to data propagation are:

- **Pull**: The value consumer is in fact proactive, in that it regularly
  queries the observed source for values and reacts whenever a relevant value
  is available. This practice of regularly checking for events or value changes
  is commonly referred to as **polling**.
- **Push**: The value consumer receives a value from the source whenever the
  value becomes available. These values are self-contained, e.g. they contain
  all the necessary information, and no further information needs to be queried
  by the consumer.
- **Push-pull**: The value consumer receives a *change notification*, which is a
  short description of the change, e.g. "some value changed" – this is the *push
  part*. However, the notification does not contain all the necessary
  information (viz. does not contain the actual values), so the consumer needs
  to query the source for more information (the specific value) after it
  receives the notification – this is the *pull part*. This method is commonly
  used when there is a large volume of data that the consumers might be
  potentially interested in. So in order to reduce throughput and latency, only
  light-weight notifications are sent; and then those consumers which require
  more information will request that specific information. This approach also
  has the drawback that the source might be overwhelmed by many requests for
  additional information after a notification is sent.

RxJS is JavaScript library for transforming, composing and querying
asynchronous streams of data. RxJS can be used both in the browser or in the
server-side using Node.js.

A **stream** is a sequence of ongoing events ordered in time. It can be anything
like user inputs, button clicks or data structures. You can listen to a stream
and react to it.
Stream emit three things during its timeline, a *value*, an *error*, and *complete
signal*.

**Observables** (functions) provide support for passing messages between
publishers and subscribers in your application.

Observable -> Subscription <- Observer

**Basic Merging**: Takes 2+ Observables and merges them into a single
Observable. The merged observable is a subscriber of ALL of its merged sources.

**Advantages of RP**:

- Improves user experience: as it's asynchronous in nature
- A lot simpler to do async/threaded work (via built-in methods)
- Use resources efficiently (not blocking)

**Disadvantages of RP**:

- learning curve
- More memory intensive: This can lead to memory leakage
- hard to debug
- time to start
- data immutability required
- managing concurrency
- complexity of testing

Suits for highly interactive UI, artificial intelligence, machine learning,
real-time data streaming:

- Social networks, chats
- Games  
- Audio and video apps
<br>
[Back to Top](#content)
<br>

# COMMUNICATION PROTOCOLS

## TCP/TLS/UDP basics
There are two types of Internet Protocol (IP) traffic:

- Transmission Control Protocol: **TCP**  is connection oriented – means that the
  communicating devices should establish a connection before transmitting data
  and should close the connection after transmitting the data
- User Datagram Protocol: **UDP** is the Datagram oriented and connectionless
  protocol. There is no overhead for opening, maintaining and terminating a
  connection. 

A short example to understand the differences clearly:
Suppose there are two houses, H1 and H2 and a letter have to be sent from H1 to
H2. But there is a river in between those two houses. Now how can we send the
letter?
*Solution 1*: Make a bridge over the river and then it can it delivered (TCP).
*Solution 2*: Get it delivered through a pigeon(UDP).

TCP:

- Web browsing, email and file transfer are common applications that make use of it
- Is used to control segment size, rate of data exchange, flow control and
  network congestion
- Is preferred where error correction facilities are required at network
  interface level

UDP:

- The delivery of data to the destination cannot be guaranteed
- Has only the basic error checking mechanism using checksums
- There is no retransmission of lost packets
- There is no sequencing of data. If ordering is required, it has to be managed
  by the application layer
- Supports Broadcasting - sending to all on a network, and multicasting –
  sending to all subscribers
- Is used by DNS, DHCP, Trivial File Transfer Protocol(TFTP), SNMP, RIP, and
  Voice over IP(VoIP).
- Is suitable for applications that need fast, efficient transmission, such as
  games. UDP's stateless nature is also useful for servers that answer small
  queries from huge numbers of clients.
- Streaming of data: Packets are sent individually and are checked for
  integrity only if they arrive. Packets have definite boundaries which are
  honored upon receipt, meaning a read operation at the receiver socket will
  yield an entire message as it was originally sent.
- Is largely used by time sensitive applications
- Is faster, simpler and more efficient than TCP

When the **SSL** protocol was standardized, it was renamed to **Transport Layer
Security (TLS)**. Many use the TLS and SSL names interchangeably, but
technically, they are different, since each describes a different version of
the protocol.

**TLS** was designed to operate on top of a reliable transport protocol such as
TCP. However, it has also been adapted to run over UDP. The Datagram Transport
Layer Security (DTLS) protocol is based on the TLS protocol and is able to
provide similar security guarantees while preserving the datagram delivery
model.

The TLS protocol is designed to provide three essential services to all
applications running above it: *encryption*, *authentication*, and *data integrity*.

**Encryption**: A mechanism to obfuscate what is sent from one host to another.
**Authentication**: A mechanism to verify the validity of provided identification
material.
**Integrity**: A mechanism to detect message tampering and forgery.

Some performance-critical features, such as HTTP/2, explicitly require the use
of TLS 1.2 or higher and will abort the connection otherwise.

As part of the TLS handshake, the protocol also allows both peers to
authenticate their identity. When used in the browser, this authentication
mechanism allows the client to verify that the server is who it claims to be
(e.g., your bank) and not someone simply pretending to be the destination by
spoofing its name or IP address.

Cryptographic hash function

By enabling client and server applications to support TLS, it ensures that data
transmitted between them is encrypted with secure algorithms and not viewable
by third parties.

Types of validation:

- **Domain validation (DV)**: validates that a certificate owner controls a
  given domain name. Such a basic validation technique is good enough for blogs
  and websites that don't handle sensitive information, but isn't ideal for
  those that do.
- **Organization validation (OV)**
- **Extended validation (EV)**

If your website allows logins or payments, you should invest in a TLS
certificate that offers *OV* or *EV*. These two types differ in
the verification process with the EV being more strict.



## HTTPS Purpose
Unencrypted communication—via HTTP and other protocols—creates a large number
of privacy, security, and integrity vulnerabilities. Such exchanges are
susceptible to interception, manipulation, and impersonation, and can reveal
users credentials, history, identity, and other sensitive information. Our
applications need to protect themselves, and our users, against these threats
by delivering data over HTTPS.

The purpose of HTTPS is to ensure the protection, integrity, and privacy of the
data exchanged between a server and a client (usually a browser). It also
authenticates websites and confirms its trustworthiness.

HTTPS is an encrypted version of HTTP and:

- HTTPS protects the **integrity** of the website (rewriting content, injecting
  unwanted and malicious content)
- HTTPS protects the **privacy** and security of the user
- HTTPS enables powerful features on the web: accessing users geolocation,
  taking pictures, recording video, enabling offline app experiences, and more,
  require explicit user opt-in that, in turn, requires HTTPS

A common objection and roadblock towards widespread adoption of HTTPS has been
the requirement to purchase certificates from one of the trusted
authorities—see Chain of Trust and Certificate Authorities. The Let’s Encrypt
(free and open) project launched in 2015 solves this particular problem.


The only way to enable HTTPS on your website is to get a TLS certificate and
install it on your server. Transport Layer Security (TLS) is a cryptographic
protocol designed to provide communications security over a computer network.

Pretty much all the benefits of HTTPS tie back to SEO:
- Lightweight ranking signal
- Better security and privacy
- Preserves referral data: If your website is still on HTTP and you’re using
  web analytics services like Google Analytics, so no referral data is passed
  from HTTPS to HTTP pages.
- Enables the use of modern protocols that enhance security and site speed
- Prevents Man-In-The-Middle Content Hijacking

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
<br>
[Back to top](#content)
<br>

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
[Back to top](#content)
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
page (HTML, in particular). And that's why **JS** is called **parser blocking**.
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

**Performance Optimization Strategies**(The main is to minimize the amount of
resources that have to be processed):
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
7. Improve user perception with layout placeholders
8. Use deferential serving: separate bundles for different browsers/users.

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

`requestAnimationFrame` method tells the browser that you wish to perform an
animation and requests that the browser calls a specified function to update an
animation before the next repaint(it will be called before each frame). It will
signal to the browser that a script-based animation needs to be resampled by
enqueuing a **callback** to the **animation frame request callback list**.

Any rAFs queued **in event handlers** will be executed in the same frame
(multiple callback -> one frame).
Any rAFs queued **in a rAF** will be executed in the next frame.

Why better?
- The browser can optimize it, so animations will be smoother
- Frames are only drawn when the browser is ready to paint and there are no
  ready frames waiting to be drawn.
- Animations in background tabs, minimized windows, or otherwise hidden parts
  of a page will stop, allowing the CPU to chill
- More battery-friendly

`requestAnimationFrame` does not:
- Guarantee when it'll paint; only that it'll paint when needed(frame could be
  skipped).
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

**Compositing** is a process that ensures that layers of your website are drawn in
the correct order.

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
*Why Profiling?*
As the project evolve more code and logic is added to the frontend, and you might
start experiencing some slowdown. This is fine since you cannot predict every
possible outcome of the code you added. Also, piled up features and legacy code
can prove problematic after some time if they are not taken care of along the
way.

We could decide that optimization is needed besides of our experience is tools,
e.g. Lighthouse.

**Page Speed** online service is helpful to test performance relative to
average environment and not for our current that could be far more performant
and phisicaly close to the server.

Use an Incognito window when profiling code.
Analyze the optimized(production) version.

Chrome's Network Waterfall.

CPU/Network Throttling.
Recording Performance.

Analyze frames per second in the result, CPU and Network charts.

Find the bottleneck.

webpack-bundle-analyzer

**First contentful paint** metric measures the time from when the page starts
loading to when any part of the page's content is rendered on the screen. For
this metric, "content" refers to text, images (including background images),
`<svg>` elements, or non-white `<canvas>` elements.
The first contentful paint depends on network speed and file size — caching
essential files and reducing their complexity will improve the contentful paint
performance.

**First meaningful paint**(FMP is deprecated in Lighthouse 6.0) measures the
time it takes the browser to display the page's primary content (normally the
largest visible element). This is the point that the page becomes useful to the
user; they can see the layout and begin reading content.
First meaningful paint times can be improved similarly to first contentful
paint times; reducing files size, complexity, optimize the critical rendering
path.

**Largest Contentful Paint** is the metric that measures the time a website takes
to show the user the largest content on the screen, complete and ready for
interaction. What is measured is the largest image or block of context within
the user viewport. Anything that extends beyond the screen does not count.

**Speed index** is a measure of how fast the websites DOM gets rendered.
Speed index is not equivalent to load time since images haven't necessarily
finished downloading.

**First CPU idle** (also called **First Interactive**) measures the time until the
page is capable of handling the majority of user inputs in a “reasonable”
amount of time.

**Time to Interactive** measures the time until the user can meaningfully
interact with the majority of the site with delays of under 50ms. Unlike the
‘CPU idle’ metric, Time to Interactive (TTI) requires the First contentful
paint to have finished and most of the Javascript event listeners to have been
registered.

Lighthouse for audit.
Lighthouse analyzes web apps and web pages, collecting modern performance
metrics and insights on developer best practices.

Lighthouse measures:
- *Performance* — how fast is your website?
- *Accessibility* — how accessible is your website to others?
- *Best Practices* — are you following the web’s best practices?
- *SEO* — is your website SEO friendly?
- *Progressive Web App* — is your website a PWA?

You can set up Lighthouse to run in your continuous integration (CI) by
following the instructions on its GitHub repo. Then, you can set it up to show
up in GitHub’s pull request as a status check and block any future changes that
might jeopardize the performance of your website.
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

If we have not enough resources/time for now to improve our performance without
refactoring/redesign we could use a loaders and placeholders/skeletons
approach.

Tips for using the RAIL model:
1. Know your audience
2. Keep up with web development trends
3. Know when to upgrade
4. Prioritize your critical rendering path

<br>
<br>

## PRPL pattern
**PRPL** is an acronym for:
- **Push** (or preload) the most important resources: `rel="preload"` or
  `rel="prefetch"`
- **Render** the initial route as soon as possible: inlining, SSR (hydrate)
- **Pre-cache** remaining assets
- **Lazy load** other routes and non-critical assets

PRPL aims to facilitate a faster web experience by using Service Workers,
Background sync, Cache API, Priority hints, and pre-fetching.
Specifically, PRPL works for phones with a low network when the phone is
offline or in data-saver mode (PWAs).

[Pre-cache strategies](#service-workers)

*Lazy loading* optimizes resources consumption and response time by code
splitting and loading the desired bundle.
<br>
<br>

## Network optimizations
**Minification**(js, css, html) and **module bundling**.

Minification is the process of processing source-code to remove all unnecessary
characters without changing functionality.

Module bundling deals with taking different scripts and bundling them together.

Lazy loading of assets

Remove unused code from your dependencies(Tree Shaking)

Use the Critical CSS approach

Preload, prefetch 

Cache

HTTP/2

Content Delivery Network (CDN) to Reduce Latency:
Since many of the files unchanging and static, a CDN is a great way to enhance
bandwidth, speed up your delivery of assets, and reduce access latency. In a
CDN, different network nodes spread far apart from each other store copies of
data and work together to fulfill end-user content requests as they occur.

Compressing - gzip, brotli.
Brotli's advantage: with the same CPU load, it compresses 20–30% better than Gzip.
Brotli's disadvantage: it's relatively new and is supported worse than Gzip. 

Optimize Images:
- Choose an appropriate format(svg, jpg, png, webp and gif)
- decreasing dimensions
- Compression(svg - minify & simplify, jpeg - compression level)
- Use Progressive JPEG / Interlaced PNG

For **fonts**
— Specify the proper fallback font (and a generic font family)
— Use `font-display` to configure how the custom font is applied
<br>
<br>

## CPU bound operations optimizations
A program is **CPU bound** if it would go faster if the CPU were faster, i.e. it
spends the majority of its time simply using the CPU (doing calculations).

Use Asynchronous Code to Prevent Thread Blocking

Minimize DOM access

Store pointer references to in-browser objects

Batch your DOM changes

Event Delegation (Not all events bubble up, The child stops propagation)

Use the algorithms with the least computational complexity to solve the task
with the optimal data structures

Break Out of Loops Early

Define variables locally: **scope lookup** - with the increase in the number of
scopes in the scope chain, there’s also an increase in the amount of time taken
to access variables that are outside the current scope.

Memoization

Use Throttle and Debounce

Inline Caching: JS engine relies upon the observation that repeated calls to
the same method tend to occur on the same type of object.

Hidden Classes: Hidden classes are what the compiler uses under the hood to say
that these 2 objects have the same properties. If values are introduced in a
different order than it was set up in, the compiler can get confused and think
they don't have a shared hidden class, they are 2 different things, and will
slow down the computation. Also, the reason the delete keyword shouldn't be
used is because it would change the hidden class.

Use Web Workers to Run CPU Intensive Tasks in the Background
<br>
<br>

## Web Workers

Web Workers allow you to perform multi-threading in your Web applications.

Web Workers are scripts initiated from the JavaScript code in your application
and execute on a thread separate from that of your application. Any
communication between a Web Worker and your application occurs through events.

Inability to access the DOM.

You can't access your framework's features from a Web Worker because you don't
have access to its libraries; remember, they're loaded by your application and
the Web Worker sits by itself in an isolated script file, running in an
isolated context.

The window namespace is not accessible from a Web Worker but the concept of it
is, in a way. The global scope concept exists in a Web Worker by way of the
`self` object, although optional to use.

Security
- Restrictions with Local Access
- Same Origin Considerations

Use cases:
- Prefetching and/or caching data for later use
- Network requests and resulting data processing
- Code syntax highlighting or other real-time text formatting, spell checker,
  encoding/decoding a large string
- Complex mathematical calculations
- Analyzing or processing video or audio data
- Background I/O or polling of webservices
- Processing large arrays or huge JSON responses
- Image manipulation, filtering in `<canvas>`
- Calculations and data manipulation on local storage 
<br>
<br>

## Service Workers
**Service workers** essentially act as proxy servers that sit between web
applications, the browser, and the network (when available). They are intended,
among other things, to enable the creation of effective offline experiences,
intercept network requests and take appropriate action based on whether the
network is available, and update assets residing on the server. They will also
allow access to push notifications and background sync APIs.

A service worker is an event-driven worker registered against an origin and a
path. It takes the form of a JavaScript file that can control the web-page/site
that it is associated with, intercepting and modifying navigation and resource
requests, and caching resources in a very granular fashion to give you complete
control over how your app behaves in certain situations (the most obvious one
being when the network is not available).

A service worker is run in a worker context: it therefore has no DOM access,
and runs on a different thread to the main JavaScript. It is designed to be
fully async.

Browser support.

Service workers only run over HTTPS, for security reasons.

Lifecycle
- Download
- Install
- Activate

Pre-caching in service workers strategies:
- *Stale-while-revalidate*: checks for the response in the cache. If it is
  available, it is delivered, and the cache is revalidated. If it is not
  available, the service worker fetches the response from the network and
  caches it.
- *Cache first*: looks for a response in the cache first. If any response is
  found previously cached, it will return and serve the cache. If not, it will
  fetch the response from the network, serve it, and cache it for next time.
- *Network first*: tries to fetch the response from the network. If it
  succeeds, it will cache the response and return the response. If the network
  fails, it will fall back to the cache and serve the response there.
- *Cache only*: responds from the cache only. It does not fall back to the
  network.
- *Network only*: uses the network solely to fetch and serve a response. It
  does not fallback to any cache.

Advantages:
- make the website function offline,
- increase online performance by reducing network requests for certain assets,
- provide a customized offline fallback experience.

Service workers use cases:
- Background data synchronization.
- Responding to resource requests from other origins.
- Receiving centralized updates to expensive-to-calculate data such as
  geolocation or gyroscope, so multiple pages can make use of one set of data.
- Client-side compiling and dependency management of CoffeeScript, less,
  CJS/AMD modules, etc. for development purposes.
- Hooks for background services.
- Custom templating based on certain URL patterns.
- Performance enhancements, for example pre-fetching resources that the user is
  likely to need in the near future, such as the next few pictures in a photo
  album.
<br>
<br>

## Memory leaks detection
**Memory leaks** can be defined as memory that is not required by an
application anymore that for some reason is not returned to the operating
system or the pool of free memory.

The primary symptom of a memory leak is when the performance of an application
progressively worsens.

JavaScript is a garbage collected language. Garbage collected languages help
developers manage memory by periodically checking which previously allocated
pieces of memory can still be "reached" from other parts of the application.

Garbage collected languages reduce the problem of managing memory from "what
memory is still required?" to "what memory can still be reached from other
parts of the application?". The difference is subtle, but important: while only
the developer knows whether a piece of allocated memory will be required in the
future, unreachable memory can be algorithmically determined and marked for
return to the OS.

The main cause for leaks in garbage collected languages are **unwanted references**.

The Types of Common JavaScript Leaks
1. Accidental global variables: a reference to an undeclared variable creates a
   new variable inside the *global* object; an accidental global variable can
   be created is through `this`. As variable belongs to *global*(*window*)
   object it could be collected by GC. To prevent - `use strict`. If you must
   use a global variable to store lots of data, make sure to null it or
   reassign it after you are done with it. 

2. Forgotten timers or callbacks/event listeners: timers that make reference to
   nodes or data that is no longer required.

3. Out of DOM references (including inner and leaf nodes)

4. Closures: once a scope is created for closures that are in the same parent
   scope, that scope is shared.

Garbage Collector trade-off is nondeterminism (unpredictable when it happens):
when it starts it could slow the application performing.
GC starts from *window* object, and traverses the whole tree down to find
unreachable pointers. First step - mark to delete, second one - perform
deletion.

In JavaScript ES6, Map and Set were introduced with their “weaker” siblings.
This “weaker” counterpart known as WeakMap and WeakSet hold “weak” references
to objects. They enable unreferenced values to be garbage collected and thereby
prevent memory leaks.

Tools:
- Chrome Task Manager
- Pega JS Memory Leak Detector
- Chrome Develop Tools: Memory/Heap snapshots comparison

To perform:
1. Find out how much memory your page is currently using with the Chrome Task
   Manager.
2. Visualize memory usage over time with Timeline recordings(could get a simple
   overview for leaks, when see that memory is not collected by GC).
3. Identify detached DOM trees (a common cause of memory leaks) with Heap
   Snapshots.
4. Find out when new memory is being allocated in your JS heap with Allocation
   Timeline recordings.
<br>
<br>

## V8 hidden classes and inline caching techniques
**Hidden classes** are the academic term for generating similar shapes of
JavaScript code.
Javascript engines generate shapes of each object that you create. If you
create similar objects, they share the same shape (Hidden class, Map,
Structure, etc.).

Takeaways for hidden classes:
- Initialize all object members in constructor functions: Adding properties to
  an object after instantiation will force a hidden class change and slow down
  any methods that were optimized for the previous hidden class.
- Always initialize object members in the same order.

**Inline caching** is an optimization technique that relies upon the
observation that repeated calls to the same method tend to occur on the same
type of object. You can think of Inline Cache as a fast path (shortcut) to the
value/property.

Whenever a function is called, V8 looks up the hidden class for that specific
object. If the method on that object or an object with the same hidden class is
called multiple times, V8 caches the information where to find the object
property in memory and returns it instead of looking up the memory itself.

Takeaways for inline caching
- keep the type of parameters safe and don't mix them up (call with same type
  of objects).
- always initialize object members in the same order.
- code that executes the same method repeatedly will run faster than code that
  executes many different methods only once.

Avoid **sparse arrays** where keys are not incremental numbers.
<br>
<br>

## Event Loop, microtasks
JavaScript is a *single-threaded* programming language.

JavaScript engine executes a script from the top and works its way down
creating execution contexts and pushing and popping functions onto and off the
call stack.

The V8 does two major things:
- Heap memory allocation
- Call stack execution context

However, it's more precise to say that the JavaScript runtime can do one thing at a time.

The web browser also has other components, not just the JavaScript engine.
Events, timers, Ajax requests are all provided on the client-side by the
browsers and are often referred to as Web API. They are the ones that allow the
single-threaded JavaScript to be non-blocking, concurrent, and asynchronous.

There are three major sections to the execution workflow of any JavaScript
program, the **call stack**, the **web API**, and the **Task queue**.

When the Call Stack encounters a web API function, the process is immediately
handed over to the Web API, where it is being executed and freeing the Call
Stack to perform other operations during its execution.

Once the Web API finishes executing the task, it doesn't just push it back to
the Call Stack automatically. It goes to the Task Queue or Callback Queue.

A **queue** is a data structure that works on the First in First out principle.

The **event loop** is a constantly running process that monitors both the
callback queue and the call stack.

Once the Stack is clear, the event loop triggers and checks the Task Queue for
available callbacks. If there are any, it pushes it to the Call Stack, waits
for the Call Stack to be clear again, and repeats the same process.

Each 'thread' gets its own event loop, so each web worker gets its own, so it
can execute independently, whereas all windows on the same origin share an
event loop as they can synchronously communicate.

The **task** (**macrotask**) is code to be executed until completion. For each
turn of the event loop, one task is executed. A task can schedule other tasks
(asynchronous in nature).
Task sources are - DOM Manipulation, UI Events, History Traversal, Networking.

**Microtask** is code that needs to be executed after the currently executing task
is completed. If microtask's queue is not empty no macrotask would be performed
and we should be careful to not overflow the queue.
Microtask sources are - `Promise.resolve,` `Promise.reject,` `MutationObservers,`
`IntersectionObservers` etc.

<br>
[Back to top](#content)
<br>

# WEB APPLICATION DESIGN AND FRAMEWORK

## SPA vs MPA pros/cons
Websites that are built with single-page applications (**SPA**s) only consist of
one single page and it does not reload during its use. Only data is sent
back-and-forth, and the website executes everything within itself rather than
going through servers every time.

At the same time SPA can be slow due to client-side rendering. Before your
browser can render the page, it has to load bulky JS frameworks.  This could
take a while, especially for the large application. But after the first render,
SPAs become much faster than MPAs.  Fortunately, there are ways to speed up the
SPA initialization such as loading assets dynamically, minimizing the scripts,
etc.

Ideal for a company with a single product to get real-time experience without
page refresh.

Pros:

- Decoupled Backend and Frontend
- Sleek UX
- Speed
- Better suits for offline work
- Can be easely adopted to mobile app
- Super-simple to deploy: it's really just one index.html file, with a CSS
  bundle and a Javascript bundle

Cons: 

- SEO (In the last couple of years, Google has become much better at indexing
  JavaScript. Still, Google admits it sometimes can't properly index
  single-page applications. Not to mention that other search engines haven't
  yet achieved the same SPA-crawling prowess.)
- JavaScript Dependency
- Memory leaks 

Multi-page applications (**MPA**s) are complex websites. Such website reloads
the entire page whenever the user interacts with it. Each time that the data is
exchanged, the application makes a request from the server to display different
information in the browser.

The main reason why it differs so much from the single-page applications, MPAs
take time to execute the information exchanges, meaning that the user
experience can be harmed if the servers connect slowly or the internet
connection is poor.

Ideal for a large company that offers a wide variety of products, if you need a
lot of user interaction and technical features in your app, large e-commerce
stores and marketplaces like eBay, huge web portals that have a lot of content
(such as news portals) and require flawless SEO.

Pros: 

- Simple SEO
- Fast launch 
- Many existed boxed solutions
- Works without javascript
- Wide options for security configuration

Cons: 

- Slowness due to the full page reload
- Coupled Backend and Frontend
- Complex Development process
- Deployment and configuration could be complicated and depend on the boxed
  solution and technology stack

**Hybrid** - MPA, and SPA combined: each page has to be compiled and could
share some resources. Every page has own JS routing like wizards or
subcomponents. Data is loaded both during page load and AJAX.


<br>

## SSR vs CSR pros/cons
**CSR** - when the user opens a website, his browser makes a request to the
server, and the user gets a response with a single HTML file without any
content, loading screen, etc. It's a blank page until the browser fetches all
linked JavaScripts and lets the browser compile everything before rendering the
content.

If you building a SPA and you don't want to configure everything on the server
side like: i18n, router etc. you can just use create-react-app, angular-cli,
vue-cli, etc.

Pros:

- Fast render after initial load
- Faster navigation
- Lower server load
- Remarkable for web apps

Cons: 

- Slower initial load
- Unpredictable performance – you never know if your user will open and
  ‘compile’ your website on a mobile device with a very slow internet
  connection or not updated browser
- Client-side routing solutions can delay web crawling.
- SEO – if you not implemented correctly
- Initial req loads the page, CSS, layout, js,
- Some or all content is not included

**SSR** is a method to render a website, when the user opens your page, his
browser makes a request to the server, and the server generates ready to
provide HTML.

Suits for:

- mostly static sites (blog, portfolio, landing page), use frameworks like
  Gatsby, it's not SSR, but it pre-renders the website into HTML at the build
  time.
- a web app with care about SEO, easier social media optimization and faster
  render for user you should think about SSR and framework like next.js,
  nuxt.js, etc

Server-side device detection works by using the User-Agent string to uniquely
identify the client device type. By matching this against a database of device
capabilities, relevant details about the user’s device can be known, and can be
used to tailor an optimized response for that device.

 Pros:

- SEO friendly – SSR guarantees your pages are easily indexable by search engines
- Better performance for the user – User will see the content faster
- Social Media Optimization: When people try to post your link on Facebook,
  Twitter, etc. then a nice preview will show up with the page title,
  description, and image.
- Shared code with backend node
- User-machine is less busy

Cons: 

- TTFB (Time to first byte) is slower; your server has to spend some time to
  prepare HTML for your page instead of sending almost empty HTML doc with link
  to javascript
- The server will be busier, can execute fewer request per second
- HTML doc will be bigger
- The page is viewable sooner, but it's not interactive and the beginning, a
  user has to wait until React will be done executing
- Full page reload after routes change

<br>
## Micro-frontends vs monorepos
**Monorepository**: Instead of managing multiple repositories, you keep all
your isolated code parts inside one repository. Keep in mind the word
isolated—it means that monorepo has nothing in common with monolithic apps. You
can keep many kinds of logical apps inside one repo; for example, a website and
its iOS app.
The idea behind a monorepo is to store all code in a single version control
system (VCS) repository. The alternative, of course, is to store code split
into many different VCS repositories, usually on a service/application/library
basis.

If you are thinking about architecture, you will want to do two main things:
Separate concerns and avoid code dupes. To make this happen, you will probably
want to isolate large features into some packages and then use them via a
single entry point in your main app.
Instead of having a lot of repositories with their own configs, we will have
only one source of truth — the monorepo.

*Monorepo Advantages*:

- One source of truth — Instead of having a lot of repositories with their own
  configs, we can have a single configuration to manage all the projects,
  making it easier to manage
- Code reuse — If there is a common code or a dependency that has to be used in
  different projects, we can actually share them easily
- Transparency — It gives us visibility of code used in every project. We will
  be able to check all the code in a single place
- Easily refactor global features with atomic commits
- Simplified package publishing
- Easier dependency management: only one `package.json`. No need to re-install
  dependencies in each repo whenever you want to update your dependencies
- Re-use code with shared packages while still keeping them isolated

*Monorepo Disadvantages*:

- No way to restrict access only to some parts of the app
- Poor Git performance when working on large-scale projects
- Long build times — Since there is a lot of code in one place, the build time
  is much longer compared to building separate projects independently
- Open Source Vulnerability Prioritization and Licensing: Although monorepos
  can make it easier to manage open source dependencies, they may complicate
  the process of prioritizing vulnerability fixes and generating
  product-specific attribution reports. You’d need to integrate Software
  Composition Analysis (SCA) or open source management software with the build
  system to understand the files and dependencies used to build each product.

Tools:

- *Bazel* is Google’s monorepo-oriented build system
- *Yarn* is a JavaScript dependency management tool that supports monorepos
  through *workspaces*.
- *Lerna* is a tool for managing JavaScript projects with multiple packages,
  built on Yarn.

**Micro Frontends** are a way to split the monolith front-end codebase into
smaller, more manageable pieces. As a result, front-end teams can enjoy similar
benefits to those of microservices: maintainable codebases, autonomous teams,
independent releases, and incremental upgrades.

The idea behind Micro Frontends is to think about a website or web app **as a
composition of features** which are owned by **independent teams**. Each team
has a **distinct area of business** or **mission** it cares about and
specialises in. A team is **cross functional** and develops its features
**end-to-end**, from database to user interface.

Micro frontends are usually thought of as a composition of independent
frontends that happens at **runtime**, either on the server or on the
client-side.

Microfrontends are all about decoupling.

Core Ideas behind Micro Frontends

- *Be Technology Agnostic*: Each team should be able to choose and upgrade their
  stack without having to coordinate with other teams. Custom Elements are a
  great way to hide implementation details while providing a neutral interface
  to others.
- *Isolate Team Code*: Don't share a runtime, even if all teams use the same
  framework. Build independent apps that are self contained. Don't rely on
  shared state or global variables.
- *Establish Team Prefixes*: Agree on naming conventions where isolation is not
  possible yet. Namespace CSS, Events, Local Storage and Cookies to avoid
  collisions and clarify ownership.
- *Favor Native Browser Features over Custom APIs*: Use Browser Events for
  communication instead of building a global PubSub system. If you really have
  to build a cross team API, try keeping it as simple as possible.
- *Build a Resilient Site*: Your feature should be useful, even if JavaScript
  failed or hasn't executed yet. Use Universal Rendering and Progressive
  Enhancement to improve perceived performance.

MF provides:

- individual pieces of the frontend can be developed, tested, and deployed
  independently
- individual pieces of the frontend can be added, removed, or replaced without
  rebuilds
- the different pieces of the frontend may be created using different
  technologies

Microfrontends can be very relevant when one or more of the following bullet points are given:

- Multiple teams contribute to the frontend
- Individual parts should be activated, deactivated, or rolled out on specific
  users or groups
- External developers should be able to extend the UI
- The feature set of the UI is growing on a daily or weekly basis — without
  impacting the rest of the system
- Development speed should be a constant despite a growing application
- Different teams should be able to use their own tooling

**Integration approaches**
Generally there is a micro frontend for each page in the application, and there
is a single container application, which:
 - renders common page elements such as headers and footers
 - addresses cross-cutting concerns like authentication and navigation
 - brings the various micro frontends together onto the page, and tells each
   micro frontend when and where to render itself

1. **Server-side template composition**: rendering HTML on the server out of
   multiple templates or fragments. We can serve this file using Nginx,
   configuring the $PAGE variable by matching against the URL that is being
   requested. And we've split up our code in such a way that each piece
   represents a self-contained domain concept that can be delivered by an
   independent team. There could be a separate server responsible for
   rendering and serving each micro frontend, with one server out the front
   that makes requests to the others. With careful caching of responses, this
   could be done without impacting latency.
2. **Build-time integration**: to publish each micro frontend as a package, and
   have the container application include them all as library dependencies. It
   produces a single deployable Javascript bundle allowing us to
   de-duplicate common dependencies from our various applications. However,
   this approach means that we have to re-compile and release every single
   micro frontend in order to release a change to any individual part of the
   product. *We've seen enough pain caused by such a **lockstep release
   process** that we would recommend strongly against this kind of approach to
   micro frontends.* We should find a way to integrate our micro frontends at
   run-time, rather than at build-time.
3. **Run-time integration via iframes**: The easy isolation of iframes does
   tend to make them less flexible than other options. It can be difficult to
   build integrations between different parts of the application, so they make
   routing, history, and deep-linking more complicated, and they present some
   extra challenges to making your page fully responsive.
4. **Run-time integration via JavaScript**: the most flexible one, and the one
   that teams adopting most frequently. Each micro frontend is included onto
   the page using a `<script>` tag, and upon load exposes a global function as
   its entry-point. The container application then determines which micro
   frontend should be mounted, and calls the relevant function to tell a micro
   frontend when and where to render itself. Unlike with build-time
   integration, we can deploy each of the `bundle.js` files independently. And
   unlike with iframes, we have full flexibility to build integrations between
   our micro frontends however we like. We could extend the above code in many
   ways, for example to only download each JavaScript bundle as needed, or to
   pass data in and out when rendering a micro frontend.
5. **Run-time integration via Web Components**: One variation to the previous
   approach is for each micro frontend to define an HTML custom element for the
   container to instantiate, instead of defining a global function for the
   container to call.

Tools to Build Microfrontends

- Client-Side Frameworks: Piral, Open Components, qiankun, Luigi, Frint.js
- Server-Side Frameworks: Mosaic, PuzzleJs, Podium, Micromono
- Helper Libraries: Module Federation, Siteless, Single SPA, Postal.js,
  EventBus

**Styling**
Some choose to use a strict naming convention, such as BEM, to ensure selectors
only apply where intended. Others, preferring not to rely on developer
discipline alone, use a pre-processor such as SASS, whose selector nesting can
be used as a form of namespacing. A newer approach is to apply all styles
programatically with CSS modules or one of the various CSS-in-JS libraries,
which ensures that styles are directly applied only in the places the developer
intends. Or for a more platform-based approach, shadow DOM also offers style
isolation.

One of the most common questions regarding micro frontends is how to let them
talk to each other. In general, we recommend having them communicate as little
as possible, as it often reintroduces the sort of inappropriate coupling that
we're seeking to avoid in the first place.
That said, some level of cross-app communication is often needed. Custom events
allow micro frontends to communicate indirectly, which is a good way to
minimise direct coupling, though it does make it harder to determine and
enforce the contract that exists between micro frontends. Alternatively, the
React model of passing callbacks and data downwards (in this case downwards
from the container application to the micro frontends) is also a good solution
that makes the contract more explicit. A third alternative is to use the
address bar as a communication mechanism.

Testing is similar for monolithic frontends and micro frontends.
Integration testing of the various micro frontends with the container
application can be done using your preferred choice of functional/end-to-end
testing tool (such as Selenium or Cypress).

Pros:

- Incremental upgrades
- decoupled codebases
- Deploying new features at different rates for different parts of the
  application(Independent deployment)
- Autonomous teams:
    - Providing a way for different teams to own different parts of the
      application
    - Providing a way for teams to choose a set of technologies that suit the
      purpose of a microfrontend and the expertise of the team

Cons:

- Payload size: Independently-built JavaScript bundles can cause duplication of
  common dependencies, increasing the number of bytes we have to send over the
  network to our end users. For example, if every micro frontend includes its
  own copy of React, then we're forcing our customers to download React *n*
  times.
- Making a change across the entire application involves making changes to many
  microfrontends done by multiple teams
- Switching between teams and projects is difficult due to inconsistencies in
  dependencies, tooling, and standards between microfrontends
- Adding new microfrontends requires setting up a build process, testing, and
  deployment
- Sharing common functionality between different microfrontends requires a
  non-trivial solution

<br>

## PWA


<br>
[Back to top](#content)
<br>
--------------------





-------------------
**Serialization** means taking objects from the application code and converting
them into a format that can be used for another purpose, such as storing the
data to disk or streaming it.

**Deserialization** is just the opposite: converting serialized data back into
objects the application can use.



