///usr/bin/env jbang "$0" "$@" ; exit $?

// Below options are to disable all nasty warnings about unsafe memory access.

//RUNTIME_OPTIONS --sun-misc-unsafe-memory-access=allow
//RUNTIME_OPTIONS --enable-native-access=ALL-UNNAMED
//RUNTIME_OPTIONS --add-opens=java.base/java.lang=ALL-UNNAMED
//RUNTIME_OPTIONS -Dpolyglot.engine.WarnInterpreterOnly=false

// Dependencies are minimal:
// - picocli - to gave nice command line interface
// - graalvm polyglot - to run JS rules for journal processing
// - jackson-databind - to parse JSON journal entries

//DEPS info.picocli:picocli:4.6.3
//DEPS org.graalvm.polyglot:polyglot:25.0.1
//DEPS org.graalvm.polyglot:js:25.0.1@pom
//DEPS org.graalvm.js:js-language:25.0.1
//DEPS tools.jackson.core:jackson-databind:3.0.2

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.temporal.ChronoUnit.SECONDS;
import static java.util.Collections.emptyMap;
import static java.util.function.Predicate.not;
import static java.util.stream.Collectors.joining;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.stream.IntStream;
import java.util.zip.CRC32;

import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Source;
import org.graalvm.polyglot.Value;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.IDefaultValueProvider;
import picocli.CommandLine.IExecutionStrategy;
import picocli.CommandLine.ITypeConverter;
import picocli.CommandLine.Model.ArgSpec;
import picocli.CommandLine.Model.OptionSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;
import picocli.CommandLine.ParseResult;
import picocli.CommandLine.ScopeType;
import tools.jackson.databind.ObjectMapper;


/**
 * Utility to send logs to QuLog Center in QNAP NAS devices.
 *
 * @author Bartosz Firyn (sarxos)
 */
@Command(
	name = "qulog",
	version = "qulog 0.1",
	description = "Sends logs to QNAP NAS QuLog Center via TCP.",
	defaultValueProvider = ConfigFileDefaultValueProvider.class,
	mixinStandardHelpOptions = true,
	sortOptions = false,
	subcommands = {
		qulog.test.class,
		qulog.journal.class,
	})
class qulog implements Callable<Integer> {

	private static final IExecutionStrategy LAST_CMD = new CommandLine.RunLast();
	private static final DateTimeFormatter VERBOSE_DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

	/**
	 * Read system hostname from here.
	 */
	private static final File HOSTNAME_FILE = new File("/proc/sys/kernel/hostname");

	private static final String DEFAULT_LOG_RECEIVER_PORT = "1514";

	private static final String QL_SD_APP_ID_PREFIX = "QLSA-";
	private static final String QL_SD_CAT_ID_PREFIX = "QLSC-";

	private static final int SOCKET_TIMEOUT_MS = 3000;

	// CLI args

	@Option(
		order = 1,
		names = { "-s", "--source" },
		required = true,
		description = """
			A source name to display under the QuLog Service in
			the Sender Devices section. This name should be the
			primary grouping mechanism that can help us to find
			from which device logs are coming from. Please make
			sure the name is short but descriptive enough. This
			option is mandatory or the script will not run. The
			example source name: "Home LAN Server", "The Office
			Surveillance", "Minecraft Server", etc.%n""",
		paramLabel = "<name>",
		scope = ScopeType.INHERIT)
	private String optSourceName;

	@Option(
		order = 2,
		names = { "--mac" },
		description = """
			Optional MAC address of the source device. This can
			be useed when device has multiple interfaces. QuLog
			Center uses MAC address to uniquely identify device
			in the Sender Devices list. When multiple addresses
			are used with the same sender name, the devices are
			merged into one, which is not desired. When address
			is not provided, it is automatically detected based
			on the network interface used to connect to a QuLog
			Center Log Receiver. The format of the address must
			be XX:XX:XX:XX:XX:XX (hexadecimal) where X is a hex
			digit (0-9, A-F).%n""",
		paramLabel = "<mac>",
		scope = ScopeType.INHERIT)
	private String optMacAddress;

	@Option(
		order = 3,
		names = { "--hostname" },
		description = """
			Optional source hostname to use when sending syslog
			messages to the QuLog Center Log Receiver. When not
			provided, the local system hostname is used instead
			(read from /proc/sys/kernel/hostname file).%n""",
		paramLabel = "<hostname>",
		scope = ScopeType.INHERIT)
	private String optHostname;

	@Option(
		order = 4,
		names = { "-h", "--host" },
		required = true,
		description = """
			Remote address (can be domain or IP) that points to
			where syslog messages will be delivered. Important:
			the Log Receiver in QuLog Center must be configured
			to listen for incoming syslog messages on this host
			address. The transfer protocol in Log Receiver must
			be set to TCP. This option is mandatory.%n""",
		paramLabel = "<address>",
		scope = ScopeType.INHERIT)
	private String optHost;

	@Option(
		order = 5,
		names = { "-p", "--port" },
		defaultValue = DEFAULT_LOG_RECEIVER_PORT,
		description = """
			Remote port on the QNAP host where Log Receiver has
			been configured to listen for incoming traffic. The
			default port for QuLog Center Log Receiver is 1514.
			Provide port number only if a different port should
			be used. This option is optional. Log Receiver must
			be configured with TCP port as this script uses the
			TCP only as more reliable option over UDB. When the
			port is not provided, default of ${DEFAULT-VALUE} is used.%n""",
		paramLabel = "<port>",
		scope = ScopeType.INHERIT)
	private Integer optPort;

	@Option(
		order = 6,
		names = { "-v", "--verbose" },
		description = """
			---------------------------------------------------
			Verbose mode. When enabled, the script will print a
			lot of debug informations to STDOUT to troubleshoot
			the problem.%n""",
		scope = ScopeType.INHERIT)
	private boolean optVerbose;

	// internal stuff

	private InetSocketAddress quLogSecketAddress;

	private LogSource source;

	void main(final String... args) {

		final var cmd = new qulog();
		final var cli = new CommandLine(cmd);
		final var exitCode = cli
			.setExecutionStrategy(cmd::doInitBeforeExecution)
			.execute(args);

		System.exit(exitCode);
	}

	private int doInitBeforeExecution(final ParseResult args) {

		try {
			init();
		} catch (IOException e) {
			e.printStackTrace();
			return -1;
		}

		return LAST_CMD.execute(args);
	}

	private void init() throws IOException {
		this.quLogSecketAddress = getQuLogRemoteAddress(optHost, optPort);
		this.source = getLocalAddressesFor(optSourceName, quLogSecketAddress);
	}

	@Override
	public Integer call() throws Exception {
		System.out.println("Hello " + quLogSecketAddress);
		return 0;
	}

	@Command(
		name = "journal",
		header = "Filter and forward Journal logs to QuLog Center.",
		sortOptions = false,
		descriptionHeading = "%nDescription:%n%n",
		description = """
			Consume JSON-formatted Journal log entries from STDIN stream, push them to rules
			script to be filtered and categorized, and send filtered log entries with proper
			structured data to the QuLog Center Log Receiver. Log entries that did not match
			any rule are silently ignored. If the rules file is being modified while command
			is running working, the rules are being reloaded and applied to next log entries
			automatically. When a JSON entry from Journal output cannot be parsed due to any
			reason, it is silently skipped.
			--------------------------------------------------------------------------------%n""",
		defaultValueProvider = ConfigFileDefaultValueProvider.class)
	static class journal implements Runnable {

		private static final String LANG = "js";
		private static final ObjectMapper MAPPER = new ObjectMapper();
		private static final UserIdMapper USER_ID_MAPPER = new UserIdMapper();

		@ParentCommand
		private qulog parent;

		@Option(
			order = 10,
			names = { "-r", "--rules" },
			paramLabel = "<file-path>",
			required = true,
			description = """
				Path to JS file with filter function. This file can
				be in any directory as long as the path is correct.
				The JS file must define no-argument function called
				a 'filter'. This function will be invoked to filter
				every journal log entry from STDIN. It's mandatory.%n""")
		private Path rulesFilePath;

		@Option(
			order = 11,
			names = { "--user" },
			paramLabel = "<name>",
			description = """
				Optional user name to be used for every entry we do
				send to the Log Receiver. When this option is used,
				all the events received with QuLog Center will show
				this user name instead of the actual user name from
				the journal log entry. It has precedence over names
				derived from rules execution.%n""")
		private String optUserName;

		@Option(
			order = 12,
			names = { "--application" },
			paramLabel = "<name>",
			description = """
				Optional application name to use for every log that
				is being send to the Log Receiver. When this option
				is set, all the events received by the QuLog Center
				will be reported from this application name instead
				of an actual application from journal log entry. It
				has precedence over application names obtained from
				rules execution.%n""")
		private String optApplicationName;

		@Option(
			order = 13,
			names = { "--category" },
			paramLabel = "<name>",
			description = """
				Optional category name to use for every log entries
				sent to the Log Receiver. When this option is used,
				all the events received by the QuLog Center will be
				reported with this categoryname instead of the name
				from rules execution.%n""")
		private String optCategoryName;

		@Option(
			order = 14,
			names = { "--level" },
			paramLabel = "<level>",
			defaultValue = "INFO",
			description = """
				Optional log level to be used for all the logs that
				are being send to the Log Receiver. This option has
				a precedence over value returned by rules. Possible
				values are: ${COMPLETION-CANDIDATES}.%n""",
			converter = LogLevelConverter.class,
			completionCandidates = LogLevelCandidates.class)
		private LogLevel optLogLevel;

		private long rulesLastModifiedTime = -1;
		private Context context = newContext();

		@Override
		public void run() {

			var line = "";

			try (final var stdin = reader(System.in)) {
				while ((line = stdin.readLine()) != null) {
					process(line);
				}
			} catch (IOException e) {
				throw new RuntimeException(e);
			} finally {
				if (context != null) {
					context.close();
				}
			}
		}

		private void process(final String line) throws IOException {

			final var json = parse(line);
			final var message = getJornalLogMessage(json);

			if (message == null) {
				return;
			}

			reloadContextIfNedded();

			final var bindings = context.getBindings(LANG);

			bindings.putMember("$LOG", json);

			final var filter = bindings.getMember("filter");
			final var result = filter.execute();

			if (result.isNull()) {
				return; // no action
			}

			final var resultApplication = getApplication(json, result);
			final var resultCategory = getCategory(result);
			final var resultMessage = getMessage(message, result);

			final var address = parent.quLogSecketAddress;

			final var datetime = getEventDateTime(json);
			final var processName = getProcessName(json);
			final var processId = getProcessId(json);
			final var userName = getUserName(json, result);
			final var logLevel = getLogLevel(json, result);

			final var source = parent.source;
			final var application = new LogApplication(resultApplication, processName, processId);
			final var category = new LogCategory(resultCategory);
			final var messageId = UUID.randomUUID();

			final var sd = new LogStructuredData(source, application, category, userName, messageId);
			final var entry = new LogEntry(logLevel, datetime, source, application, sd, resultMessage, messageId);

			try {
				parent.send(entry, address);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		private void reloadContextIfNedded() throws IOException {

			final var currModificationTime = getRulesFileModificationTime();
			final var lastModificationTime = rulesLastModifiedTime;

			if (currModificationTime == lastModificationTime) {
				return;
			}

			rulesLastModifiedTime = currModificationTime;

			final var file = rulesFilePath.toFile();
			final var source = Source
				.newBuilder(LANG, file)
				.build();

			if (context != null) {
				context.close();
			}

			context = newContext();
			context.eval(source);

			parent.log(this, "Loaded rules file " + rulesFilePath);
		}

		private static String getMessage(final String journalMessage, final Value result) {
			return getMember(result, "message")
				.or(() -> getMember(result, "msg"))
				.or(() -> getMember(result, "m"))
				.map(String::trim)
				.filter(not(String::isEmpty))
				.orElse(journalMessage);
		}

		private static String getJornalLogMessage(final Map<String, Object> json) {
			return Optional.ofNullable(json)
				.map(map -> map.get("MESSAGE"))
				.map(Object::toString)
				.map(String::trim)
				.orElse(null);
		}

		private String getApplication(final Map<String, Object> json, final Value result) {
			return Optional.ofNullable(optApplicationName)
				.or(() -> getApplicationFromResult(result))
				.or(() -> getApplicationFromJournalSyslogIdentifier(json))
				.or(() -> getApplicationFromJournalComm(json))
				.orElse("Unknown");
		}

		private static Optional<String> getApplicationFromResult(final Value result) {
			return getMember(result, "application")
				.or(() -> getMember(result, "app"))
				.or(() -> getMember(result, "a"));
		}

		private static Optional<String> getApplicationFromJournalSyslogIdentifier(final Map<String, Object> json) {
			return Optional
				.ofNullable(json.get("SYSLOG_IDENTIFIER"))
				.map(Object::toString);
		}

		private static Optional<String> getApplicationFromJournalComm(final Map<String, Object> json) {
			return Optional
				.ofNullable(json.get("_COMM"))
				.map(Object::toString);
		}

		private String getCategory(final Value result) {
			return Optional.ofNullable(optCategoryName)
				.or(() -> getCategoryFromResult(result))
				.orElse("General Events");
		}

		private static Optional<String> getCategoryFromResult(final Value result) {
			return getMember(result, "category")
				.or(() -> getMember(result, "cat"))
				.or(() -> getMember(result, "c"));
		}

		private LogLevel getLogLevel(final Map<String, Object> json, final Value result) {
			return Optional.ofNullable(optLogLevel)
				.or(() -> getLogLevelFromResult(result))
				.or(() -> getLogLevelFromJournalPriority(json))
				.orElse(LogLevel.INFO);
		}

		private static Optional<LogLevel> getLogLevelFromResult(final Value result) {
			return getMember(result, "level")
				.or(() -> getMember(result, "lvl"))
				.or(() -> getMember(result, "l"))
				.map(String::toUpperCase)
				.map(LogLevel::valueOf);
		}

		private static Optional<LogLevel> getLogLevelFromJournalPriority(final Map<String, Object> json) {
			return Optional
				.ofNullable(json.get("PRIORITY"))
				.map(Object::toString)
				.map(Integer::parseInt)
				.map(prio -> switch (prio) {
					case 0, 1, 2, 3 -> LogLevel.ERROR;
					case 4, 5 -> LogLevel.WARNING;
					case 6, 7 -> LogLevel.INFO;
					default -> LogLevel.INFO;
				});
		}

		private static Optional<String> getMember(final Value value, final String member) {
			if (value.hasMember(member)) {
				return Optional
					.ofNullable(value.getMember(member))
					.filter(not(Value::isNull))
					.map(Value::asString)
					.filter(not(String::isEmpty));
			} else {
				return Optional.empty();
			}
		}

		private long getRulesFileModificationTime() throws IOException {
			return Files
				.getLastModifiedTime(rulesFilePath)
				.toMillis();
		}

		@SuppressWarnings("unchecked")
		private static Map<String, Object> parse(final String line) {
			try {
				return MAPPER.readValue(line, Map.class);
			} catch (Exception e) {
				return null; // silently ignore all parsing errors
			}
		}

		private static Context newContext() {
			return Context
				.newBuilder()
				.allowAllAccess(true)
				.build();
		}

		private static String getProcessName(final Map<String, Object> json) {
			return Optional
				.ofNullable(json.get("_COMM"))
				.map(Object::toString)
				.orElse("unknown");
		}

		private static long getProcessId(final Map<String, Object> json) {
			return Optional
				.ofNullable(json.get("_PID"))
				.map(Object::toString)
				.map(Long::parseLong)
				.orElse(0L);
		}

		private String getUserName(final Map<String, Object> json, final Value result) {
			return Optional.ofNullable(optUserName)
				.or(() -> getUserNameFromResult(result))
				.or(() -> getUserNameFromUserId(json))
				.or(() -> getUserNamFromUid(json))
				.orElse("unknown");
		}

		private static Optional<String> getUserNameFromResult(final Value result) {
			return getMember(result, "user")
				.or(() -> getMember(result, "usr"))
				.or(() -> getMember(result, "u"));
		}

		private static Optional<String> getUserNameFromUserId(final Map<String, Object> json) {
			return Optional
				.ofNullable(json.get("USER_ID"))
				.map(Object::toString);
		}

		private static Optional<String> getUserNamFromUid(final Map<String, Object> json) {
			return Optional
				.ofNullable(json.get("_UID"))
				.map(Object::toString)
				.map(Integer::parseInt)
				.map(USER_ID_MAPPER::getUserName);
		}
	}

	@Command(
		name = "test",
		sortOptions = false,
		header = "Send test log entry to QuLog Center.",
		description = "Send test log entry to QuLog Center.")
	static class test implements Runnable {

		@ParentCommand
		private qulog parent;

		@Option(
			order = 10,
			names = { "-a", "--application" },
			required = true,
			paramLabel = "<name>",
			description = """
				Application name the log comes from, e.g. "Drupal",
				"Portainer", "systemd", etc.""")
		private String optApplicationName;

		@Option(
			order = 11,
			names = { "-n", "--process-name" },
			required = true,
			paramLabel = "<name>",
			description = """
				Process name the log comes from, e.g. "drupal.php",
				"portainer.sh", "systemd", etc.""")
		private String optProcessName;

		@Option(
			order = 12,
			names = { "-c", "--category" },
			required = true,
			paramLabel = "<name>",
			description = """
				Name of the event group or category, e.g. "Sudo
				Events", "Firewall Events", etc.""")
		private String optCategoryName;

		@Option(
			order = 13,
			names = { "-l", "--level" },
			defaultValue = "INFO",
			description = "Log level: ${COMPLETION-CANDIDATES}.",
			paramLabel = "<level>",
			converter = LogLevelConverter.class,
			completionCandidates = LogLevelCandidates.class)
		private LogLevel optLogLevel;

		@Parameters(index = "0", description = "Log message to send")
		private String parMessage;

		@Override
		public void run() {

			final var address = parent.quLogSecketAddress;

			final var level = optLogLevel;
			final var datetime = getEventDateTime();
			final var source = parent.source;
			final var application = new LogApplication(optApplicationName, optProcessName);
			final var category = new LogCategory(optCategoryName);
			final var messageId = UUID.randomUUID();
			final var user = System.getProperty("user.name");

			final var sd = new LogStructuredData(source, application, category, user, messageId);
			final var entry = new LogEntry(level, datetime, source, application, sd, parMessage, messageId);

			try {
				parent.send(entry, address);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}

			parent.log(this, "Sending log entry: " + entry);
			parent.log(this, "From: " + source.name() + " " + source.hostname() + "/" + source.ip() + " (" + source.mac() + ")");
			parent.log(this, "To: " + parent.quLogSecketAddress);
		}
	}

	static class UserIdMapper {

		private final Map<Integer, String> uidToUserMap = new HashMap<>();

		public String getUserName(final int uid) {
			return uidToUserMap.computeIfAbsent(uid, this::lookupUserName);
		}

		private String lookupUserName(final int uid) {

			// Run process 'id -un {user-id}' to get user name by ID.

			final var pb = new ProcessBuilder("id", "-un", Integer.toString(uid));
			pb.redirectErrorStream(true);

			try {
				final var process = pb.start();
				try (final var reader = reader(process.getInputStream())) {
					final var line = reader.readLine();
					process.waitFor();
					return line != null ? line.trim() : "unknown";
				}
			} catch (IOException | InterruptedException e) {
				return "unknown";
			}
		}
	}

	static BufferedReader reader(final InputStream is) {
		return new BufferedReader(new InputStreamReader(is, UTF_8));
	}

	void send(final LogEntry entry, final InetSocketAddress address) throws IOException {

		final var payload = entry.toString();
		final var data = payload.getBytes(UTF_8);

		log(this, "Sending syslog payload: " + payload);

		try (final var socket = new Socket()) {

			socket.connect(address, SOCKET_TIMEOUT_MS);

			try (final var out = socket.getOutputStream()) {
				out.write(data);
				out.flush();
			}
		}
	}

	private LogSource getLocalAddressesFor(final String name, final InetSocketAddress remote) throws IOException {

		try (final var socket = new Socket()) {

			socket.connect(remote);

			final var local = socket.getLocalAddress();
			final var ip = getLocalIpAddressFrom(local);

			final var hostname = Optional
				.ofNullable(optHostname)
				.orElse(getLocalHostname());

			final var mac = Optional
				.ofNullable(optMacAddress)
				.orElse(getLocalMacAddressFrom(local));

			return new LogSource(name, ip, mac, hostname);
		}
	}

	static InetSocketAddress getQuLogRemoteAddress(final String host, final int port) {
		return new InetSocketAddress(host, port);
	}

	static String getLocalIpAddressFrom(final InetAddress local) throws IOException {
		return local.getHostAddress();
	}

	static String getLocalMacAddressFrom(final InetAddress local) throws SocketException {

		final var iface = NetworkInterface.getByInetAddress(local); // eth0, wlan0, etc
		final var mac = iface.getHardwareAddress();

		return IntStream
			.range(0, mac.length)
			.mapToObj(i -> String.format("%02X", mac[i]))
			.collect(joining(":"));
	}

	static String getLocalHostname() throws FileNotFoundException, IOException {
		try (final var reader = new BufferedReader(new FileReader(HOSTNAME_FILE))) {
			return reader.readLine(); // only line in file
		}
	}

	static String getShortId(final String string) {

		final var crc = new CRC32();

		crc.update(string.getBytes());

		final var value = crc.getValue();
		final var base36 = Long.toString(value, 36);

		return base36.length() > 10 ? base36.substring(0, 10) : base36;
	}

	static OffsetDateTime getEventDateTime(final Map<String, Object> json) {

		// The realtime timestamp from journal is in microseconds epoch time. We need to
		// convert it to seconds epoch time.

		final var micros = Optional
			.ofNullable(json.get("__REALTIME_TIMESTAMP"))
			.map(Object::toString)
			.map(Long::parseLong)
			.orElseGet(System::currentTimeMillis);

		final long seconds = micros / 1_000_000;

		final var now = OffsetDateTime.now();
		final var instant = Instant.ofEpochSecond(seconds);
		final var time = OffsetDateTime.ofInstant(instant, now.getOffset());
		final var truncated = time.truncatedTo(SECONDS);

		// We need truncated time without nanos as QuLog Center does not accept them. Here
		// we do not set nanos at all, but let's truncate just in case if we decide to add
		// nanos later on.

		return truncated;
	}

	void log(final Object caller, final String message) {

		if (!optVerbose) {
			return;
		}

		final var date = VERBOSE_DATE_FORMAT.format(LocalDateTime.now());
		final var clazz = caller.getClass().getSimpleName();

		System.out.println(date + " [" + clazz + "] " + message);
	}

	static OffsetDateTime getEventDateTime() {
		return getEventDateTime(emptyMap());
	}

	record LogSource(
		String name,
		String ip,
		String mac,
		String hostname) {

		LogSource {
			mac = mac.toLowerCase();
		}
	}

	record LogApplication(
		String name,
		String id,
		String procName,
		long procId) {

		LogApplication(final String name, final String procName) {
			this(name, procName, ProcessHandle.current().pid());
		}

		LogApplication(final String name, final String procName, final long procId) {
			this(name, QL_SD_APP_ID_PREFIX + getShortId(name), procName, procId);
		}
	}

	record LogCategory(
		String name,
		String id) {

		LogCategory(final String name) {
			this(name, QL_SD_CAT_ID_PREFIX + getShortId(name));
		}
	}

	/**
	 * Structured Data (SD) in Syslog message as per RFC 5424 and QuLog Center requirements. Note
	 * that the SD ID is always "qulog@event" and it's not compliant with RFC 5424 Section 6.3.2.
	 * which requires that SD ID contains a valid enterprise number after "@". QuLog Center seems to
	 * ignore this requirement and uses "event" instead of o valid number.
	 * 
	 * @see https://datatracker.ietf.org/doc/html/rfc5424#section-6.3
	 */
	record LogStructuredData(
		LogSource source,
		LogApplication application,
		LogCategory category,
		String user,
		UUID messageId) {

		@Override
		public String toString() {

			final var structure = """
				[qulog@event \
				ip="{ip}" mac="{mac}" \
				user="{user}" \
				source="{source_name}" \
				computer="{hostname}" \
				application="{app_name}" \
				application_id="{app_id}" \
				category="{cat_name}" \
				category_id="{cat_id}" \
				message_id="{msg_id}" \
				extra_data="" \
				client_id="" \
				client_app="" \
				client_agent=""]""";

			return structure
				.replace("{ip}", source.ip())
				.replace("{mac}", source.mac())
				.replace("{user}", user)
				.replace("{source_name}", source.name())
				.replace("{hostname}", source.hostname())
				.replace("{app_name}", application.name())
				.replace("{app_id}", application.id())
				.replace("{cat_name}", category.name())
				.replace("{cat_id}", category.id())
				.replace("{msg_id}", messageId.toString());
		}
	}

	record LogEntry(
		int pri,
		int version,
		OffsetDateTime datetime,
		String hostname,
		String applicationName,
		String processName,
		long processId,
		String message,
		UUID messageId,
		LogStructuredData sd) {

		static final int VERSION = 1;

		LogEntry(
			final LogLevel level,
			final OffsetDateTime datetime,
			final LogSource local,
			final LogApplication app,
			final LogStructuredData sd,
			final String msg,
			final UUID msgId) {

			this(level.pri, VERSION, trunc(datetime), local.hostname(), app.name(),
				app.procName(),
				app.procId(), msg, msgId, sd);
		}

		/**
		 * RFC 5424 allows the timestamp to contain nanoseconds but QuLog Center does not seem to
		 * accept them. Therefore we truncate the datetime to seconds.
		 *
		 * @param datetime the original datetime
		 * @return truncated datetime without nanos
		 */
		private static OffsetDateTime trunc(final OffsetDateTime datetime) {
			return datetime.truncatedTo(SECONDS);
		}

		@Override
		public String toString() {

			final var structure = """
				<{pri}>{version} \
				{timestamp} \
				{hostname} \
				{proc_name} \
				{proc_id} \
				{msg_id} \
				{sd} \
				{message}\n""";

			return structure
				.replace("{pri}", Integer.toString(pri))
				.replace("{version}", Integer.toString(version))
				.replace("{timestamp}", datetime.toString())
				.replace("{hostname}", hostname)
				.replace("{proc_name}", processName)
				.replace("{proc_id}", Long.toString(processId))
				.replace("{msg_id}", messageId.toString())
				.replace("{sd}", sd.toString())
				.replace("{message}", message);
		}
	}

	static class LogLevelConverter implements ITypeConverter<LogLevel> {

		@Override
		public LogLevel convert(final String value) {
			return Optional.ofNullable(value)
				.map(String::trim)
				.map(String::toUpperCase)
				.map(LogLevel::valueOf)
				.orElseThrow(() -> new IllegalArgumentException("Invalid log level: " + value));
		}
	}

	/**
	 * The log facility numerical codes as per RFC 5424. The facility code ranges between 0 and 23
	 * but, unfortunately, QuLog Center Log Receiver seems to support only the "user-level" messages
	 * facility. All log entries with a different facility code are silently discarded and will not
	 * appear in QuLog Center.
	 * 
	 * @see https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1
	 */
	enum LogFacility {

		USER_LEVEL(1);

		final int code;

		LogFacility(final int code) {
			this.code = code;
		}
	}

	/**
	 * The log severity levels as per RFC 5424. The severity code ranges from 0 (Emergency) to 7
	 * (Debug). Unfortunately, QuLog Center Log Receiver seems to support only Informational (6),
	 * Warning (4) and Error (3) levels. All log entries with a different severity level are
	 * silently discarded and will not appear in QuLog Center.
	 * 
	 * @see https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1
	 */
	enum LogSeverity {

		INFORMATIONAL(6),
		WARNING(4),
		ERROR(3);

		final int code;

		LogSeverity(final int code) {
			this.code = code;
		}
	}

	/**
	 * Internal log levels combining facility and severity as per RFC 5424. This is used to compute
	 * the final PRI value in the syslog message.
	 * 
	 * @see https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1
	 */
	enum LogLevel {

		INFO(LogFacility.USER_LEVEL, LogSeverity.INFORMATIONAL),
		WARNING(LogFacility.USER_LEVEL, LogSeverity.WARNING),
		ERROR(LogFacility.USER_LEVEL, LogSeverity.ERROR);

		final int pri;

		LogLevel(final LogFacility facility, final LogSeverity severity) {
			final var fac = facility.code;
			final var sev = severity.code;
			this.pri = fac * 8 + sev;
		}
	}

	/**
	 * Used by picocli to list log level candidates in CLI.
	 */
	@SuppressWarnings("serial")
	static class LogLevelCandidates extends ArrayList<String> {
		LogLevelCandidates() {
			super(Arrays
				.stream(LogLevel.values())
				.map(Enum::name)
				.toList());
		}
	}
}

class ConfigFileDefaultValueProvider implements IDefaultValueProvider {

	private static final String CONFIG_ENV_VAR = "QULOG_CONFIG";
	private static final String DEFAULT_CONFIG_PATH = "/etc/qulog/qulog.cfg";

	private final Properties props = new Properties();

	ConfigFileDefaultValueProvider() {

		final var path = System
			.getenv()
			.getOrDefault(CONFIG_ENV_VAR, DEFAULT_CONFIG_PATH);

		try (final var fis = new FileInputStream(path)) {
			props.load(fis);
		} catch (IOException ignored) {
			// ignore
		}
	}

	@Override
	public String defaultValue(final ArgSpec arg) {

		final var key = getKey(arg).replace("--", "");

		final var value = Optional
			.ofNullable(props.getProperty(key))
			.map(String::trim)
			.orElse(null);

		return value;
	}

	private String getKey(final ArgSpec arg) {
		if (arg instanceof OptionSpec option) {
			return option.longestName();
		} else {
			return arg.paramLabel();
		}
	}
}
