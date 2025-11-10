# QuLog Center Sender

This is small Java utility to send syslog messages from Linux box to QNAP QuLog Center configured on NAS.

## Why?

Because QNAP QuLog Center is not fully compatible with RFC 5424 Syslog standard, the classic `logger`
utility from `util-linux` package cannot be used to send logs to remote syslogs. This utility is
designed to format and transmit messages in a format that the QNAP QuLog Center consumes.

## Prerequisites

Install [sdkman](https://sdkman.io/):

```
curl -s "https://get.sdkman.io" | bash
```

Install [JBang](https://sdkman.io/sdks/jbang/):

```
sdk install jbang
```

## Installation

This tool does not require installation. Just copy it somewhere and make sure it is executable.

```
chmod +x ./qulog
```

# Running

```
./qulog
```

## RFC 5424 Incompatibility

When investigating the way QNAP QuLog Center receives messages from remote devices, the following
RFC 5424 incompatibilities were identified:

* The `SD-ID` requirements defined in [Section 6.3.2.](https://datatracker.ietf.org/doc/html/rfc5424#section-6.3.2)
  are not met. The SD used by the QuLog Center is `qulog@event`, but the part after `@` character
  MUST be a private enterprise number as specified in
  (Section 7.2.2.)[https://datatracker.ietf.org/doc/html/rfc5424#section-7.2.2]. When trying to use
  `SD-ID` from QuLog Center, the `logger` utility refuses to accept data.
* RFC 5424 allows the `TIMESTAMP` to contain nanoseconds, see
  [Section 6.2.3.1](https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.3.1) but QuLog Center does not
  seem to accept them. All the ISO 8601 dates need to be truncated to seconds.

