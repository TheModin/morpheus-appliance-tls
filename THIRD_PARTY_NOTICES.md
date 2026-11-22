# Third-party notices

The plugin jar (`morpheus-appliance-tls-<version>-all.jar`) bundles these libraries. Each keeps its own license; see the
linked projects for the full license texts.

| Library | Used for | License |
|---|---|---|
| [acme4j](https://shredzone.org/maven/acme4j/) 3.4.0 | ACME client (account, orders, challenges) | Apache License 2.0 |
| [jose4j](https://bitbucket.org/b_c/jose4j/) (pulled in by acme4j) | JSON Web Signature for ACME | Apache License 2.0 |
| [Bouncy Castle](https://www.bouncycastle.org/) (pulled in by acme4j) | X.509 / PEM / key handling | Bouncy Castle License (MIT-style) |
| [SLF4J](https://www.slf4j.org/) API 1.7.26 | logging facade | MIT License |

Not bundled: the Morpheus plugin API and Groovy are supplied by the appliance at runtime (`provided` scope).

Build and test tooling only, not distributed: the Gradle wrapper (Apache License 2.0), Spock (Apache License 2.0), and the
Pebble ACME test server (MPL 2.0) used by the optional end-to-end test.

"Let's Encrypt" is a trademark of the Internet Security Research Group. This project is independent and not affiliated with
or endorsed by ISRG, HPE or Morpheus Data.
