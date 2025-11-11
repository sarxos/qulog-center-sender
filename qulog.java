///usr/bin/env jbang "$0" "$@" ; exit $?

/**
 * This script is an utility that can be used to forward logs from the
 * joutnalctl to QuLog center running on QNAP NAS.
 * 
 * Usage example:
 * 
 * ./qulog.java test \
 *   -s MySource -h qulog.my-nas.local \
 *   -a MyApp -n myapp.sh -c "General Category" -l INFO "This is a test log message"
 */

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
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.stream.IntStream;
import java.util.zip.CRC32;

import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Source;
import org.graalvm.polyglot.Value;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.IExecutionStrategy;
import picocli.CommandLine.ITypeConverter;
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
	mixinStandardHelpOptions = true,
	subcommands = {
		qulog.Test.class,
		qulog.Journal.class,
	})
class qulog implements Callable<Integer> {

	private static final IExecutionStrategy LAST_CMD = new CommandLine.RunLast();
	private static final LogLevelConverter LOG_LEVEL_CONVERTER = new LogLevelConverter();

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
		names = { "-s", "--source" },
		required = true,
		description = "Source name to display in QuLog Center.",
		paramLabel = "<name>",
		scope = ScopeType.INHERIT)
	private String optSourceName;

	@Option(
		names = { "--source-mac-address" },
		description = "Source MAC address to display in QuLog Center.",
		paramLabel = "<mac-address>",
		scope = ScopeType.INHERIT)
	private String optMacAddress;

	@Option(
		names = { "--source-hostname" },
		description = "Source hostname to display in QuLog Center.",
		paramLabel = "<hostname>",
		scope = ScopeType.INHERIT)
	private String optHostname;

	@Option(
		names = { "-h", "--host" },
		required = true,
		description = """
			Remote address (domain or IP) where QuLog Center
			Log Receiver is configured to listen for incoming
			RFC 5424 syslog messages.""",
		paramLabel = "<address>",
		scope = ScopeType.INHERIT)
	private String optHost;

	@Option(
		names = { "-P", "--port" },
		defaultValue = DEFAULT_LOG_RECEIVER_PORT,
		description = """
			NUmber of the TCP port where QuLog Center Log
			Receiver is listening for incoming RFC 5424 syslog
			messages (default ${DEFAULT-VALUE} if not provided) otherwise.""",
		paramLabel = "<port>",
		scope = ScopeType.INHERIT)
	private Integer optPort;

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
		description = """
			Processes JSON-formatted events from journald with supplied rules
			file and sends events that match specific criteria to the remote
			QuLog Center.""")
	static class Journal implements Runnable {

		private static final String LANG = "js";
		private static final ObjectMapper MAPPER = new ObjectMapper();
		private static final UserIdMapper USER_ID_MAPPER = new UserIdMapper();

		@ParentCommand
		private qulog parent;

		@Option(
			names = { "-r", "--rules" },
			description = "Path to rules file.",
			required = true,
			paramLabel = "<file>")
		private Path rulesFilePath;

		private long rulesLastModifiedTime = -1;

		@Override
		public void run() {

			var line = "";

			try (
				final var context = newContext();
				final var stdin = reader(System.in)) {

				while ((line = stdin.readLine()) != null) {
					process(line, context);
				}

			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		@SuppressWarnings("serial")
		private static class NoApplicationRuleResponseException extends RuntimeException {
			public NoApplicationRuleResponseException() {
				super("Resulting log entry is missing 'application' member");
			}
		}

		@SuppressWarnings("serial")
		private static class NoMessageException extends RuntimeException {
			public NoMessageException() {
				super("Journal log entry is missing 'MESSAGE' field");
			}
		}

		private void process(final String line, final Context context) throws IOException {

			final var json = parse(line);

			if (json == null) {
				return;
			}

			reloadContextIfNedded(context);

			final var message = getJornalLogMessage(json);
			final var bindings = context.getBindings(LANG);

			bindings.putMember("$LOG", json);

			final var filter = bindings.getMember("filter");
			final var result = filter.execute();

			if (result.isNull()) {
				return; // no action
			}

			final var resultApp = getMember(result, "application").orElseThrow(NoApplicationRuleResponseException::new);
			final var resultCategory = getMember(result, "category").orElse("General Category");
			final var resultLevel = getMember(result, "level")
				.map(LOG_LEVEL_CONVERTER::convert)
				.orElse(LogLevel.INFO);

			final var address = parent.quLogSecketAddress;

			final var datetime = getEventDateTime(json);
			final var processName = getProcessName(json);
			final var processId = getProcessId(json);
			final var userName = getUserName(json);

			final var level = resultLevel;
			final var source = parent.source;
			final var application = new LogApplication(resultApp, processName, processId);
			final var category = new LogCategory(resultCategory);
			final var messageId = UUID.randomUUID();

			final var sd = new LogStructuredData(source, application, category, userName, messageId);
			final var entry = new LogEntry(level, datetime, source, application, sd, message, messageId);

			try {
				sendLogEntry(entry, address);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		private void reloadContextIfNedded(final Context context) throws IOException {

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

			context.eval(source);

			System.out.println("Reloaded rules file: " + rulesFilePath);
		}

		private String getJornalLogMessage(final Map<String, Object> json) {
			return Optional
				.ofNullable(json.get("MESSAGE"))
				.map(Object::toString)
				.orElseThrow(NoMessageException::new);
		}

		private Optional<String> getMember(final Value value, final String member) {

			if (!value.hasMember(member)) {
				return Optional.empty();
			}

			return Optional
				.ofNullable(value.getMember(member))
				.map(Value::asString)
				.filter(not(Objects::isNull))
				.filter(not(String::isEmpty));
		}

		private long getRulesFileModificationTime() throws IOException {
			return Files
				.getLastModifiedTime(rulesFilePath)
				.toMillis();
		}

		@SuppressWarnings("unchecked")
		private Map<String, Object> parse(final String line) {
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

		static String getProcessName(final Map<String, Object> json) {
			return Optional
				.ofNullable(json.get("_COMM"))
				.map(Object::toString)
				.orElse("unknown");
		}

		static long getProcessId(final Map<String, Object> json) {
			return Optional
				.ofNullable(json.get("_PID"))
				.map(Object::toString)
				.map(Long::parseLong)
				.orElse(0L);
		}

		static String getUserName(final Map<String, Object> json) throws SocketException {
			return Optional
				.ofNullable(json.get("_UID"))
				.filter(not(Objects::isNull))
				.map(Object::toString)
				.map(Integer::parseInt)
				.map(USER_ID_MAPPER::getUserName)
				.orElse("unknown");
		}
	}

	@Command(
		name = "test",
		description = "Send test log entry to QuLog Center.")
	static class Test implements Runnable {

		@ParentCommand
		private qulog parent;

		@Option(
			names = { "-a", "--application" },
			required = true,
			paramLabel = "<name>",
			description = """
				Application name the log comes from, e.g. "Drupal",
				"Portainer", "systemd", etc.""")
		private String optApplicationName;

		@Option(
			names = { "-n", "--process-name" },
			required = true,
			paramLabel = "<name>",
			description = """
				Process name the log comes from, e.g. "drupal.php",
				"portainer.sh", "systemd", etc.""")
		private String optProcessName;

		@Option(
			names = { "-c", "--category" },
			required = true,
			paramLabel = "<name>",
			description = """
				Name of the event group or category, e.g. "Sudo
				Events", "Firewall Events", etc.""")
		private String optCategoryName;

		@Option(
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
				sendLogEntry(entry, address);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}

			System.out.println("Sending log entry: " + entry);
			System.out.println("From: " + source.name() + " " + source.hostname() + "/" + source.ip() + " (" + source.mac() + ")");
			System.out.println("To: " + parent.quLogSecketAddress);
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

	static void sendLogEntry(final LogEntry entry, final InetSocketAddress address) throws IOException {

		final var payload = entry.toString();

		System.out.println("Payload: " + payload);

		final var data = payload.getBytes(UTF_8);

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
