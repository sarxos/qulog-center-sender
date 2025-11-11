# Java QuLog Center Sender Script

This is small Java utility to send syslog messages from Linux box to QuLog Center Log Receiver
configured on QNAP NAS.

## Why?

Since QNAP QuLog Center Log Receiver message format
is not fully compatible with RFC 5424 syslog standard, the classic `logger`
command from `util-linux` package cannot be used to send logs to remote QuLog Center Log Receiver.

The `qulog.java` script has been created to overcome these incompatibilities. By communicating
directly to the Log Receiver TCP socket, it is possible to send messages in the format
the Log Receiver expects.

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

This script does not require installation. Just copy it somewhere and make sure it is executable.

```
chmod +x ./qulog.java
```

# Usage

## Help

```
./qulog.java --help
```

# Send Test Message

Below will send a single test message to QuLog Center Log Receiver and exit.

```
./qulog.java test \
  -h 10.0.3.4
  -p 1514 \
  -s MyLinuxBox \
  "Test message from My Linux Box to QuLog Center Log Receiver"
```

Where:
* `-h` is the hostname or IP address of the QNAP NAS running QuLog Center Log Receiver.
* `-p` is the TCP port number of the Log Receiver (default is 1514).
* `-s` is the source name to appear in QuLog Center (in the left sidebar, together with MAC).

## Send Jornal LOgs Matching Criteria

Below will start reading journalctl logs in JSON format and forward them to the `qulog.java` script.
The script will use `./rules-sample.js` file to filter them, extract some necessary information, and 
send only matching logs to QuLog Center Log Receiver.

```
journalctl -o json -f | ./qulog.java journal \
  -h 10.0.3.4
  -p 1514 \
  -s MyLinuxBox
  -f ./rules-sample.js
```

Where:
* `-f` is the path to the JS file containing filtering and extraction rules.

### Rules File

The rules file is your plain old JavaScript file with a function to be executed for each journal log entry.

## Log Receive RFC 5424 Incompatibilities

When investigating the way QNAP QuLog Center receives messages from remote devices, the following
RFC 5424 incompatibilities were identified:

* The `SD-ID` requirements defined in [Section 6.3.2.](https://datatracker.ietf.org/doc/html/rfc5424#section-6.3.2)
  are not met. The SD used by the QuLog Center is `qulog@event`, but the part after `@` character
  MUST be a private enterprise number as specified in
  (Section 7.2.2.)[https://datatracker.ietf.org/doc/html/rfc5424#section-7.2.2]. When trying to use
  `SD-ID` from QuLog Center, the `logger` utility refuses to accept data.
* RFC 5424 allows the `TIMESTAMP` to contain nanoseconds, see
  [Section 6.2.3.1](https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.3.1) but QuLog Center does not
  seem to accept them. All the ISO 8601 times need to be truncated to seconds.

