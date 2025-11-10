///usr/bin/env jbang "$0" "$@" ; exit $?

//RUNTIME_OPTIONS --sun-misc-unsafe-memory-access=allow
//RUNTIME_OPTIONS --enable-native-access=ALL-UNNAMED
//RUNTIME_OPTIONS --add-opens=java.base/java.lang=ALL-UNNAMED
//RUNTIME_OPTIONS -Dpolyglot.engine.WarnInterpreterOnly=false

//DEPS info.picocli:picocli:4.6.3
//DEPS org.graalvm.polyglot:polyglot:25.0.1
//DEPS org.graalvm.polyglot:js:25.0.1@pom
//DEPS org.graalvm.js:js-language:25.0.1
//DEPS tools.jackson.core:jackson-databind:3.0.2

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.temporal.ChronoUnit.SECONDS;
import static java.util.function.Predicate.not;
import static java.util.stream.Collectors.joining;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.stream.IntStream;
import java.util.zip.CRC32;

import org.graalvm.polyglot.Context;
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

	private static final File FILE_HOSTNAME = new File("/proc/sys/kernel/hostname");

	private static final String DEFAULT_QULOG_PORT = "1514";

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
		defaultValue = DEFAULT_QULOG_PORT,
		description = """
			NUmber of the TCP port where QuLog Center Log
			Receiver is listening for incoming RFC 5424 syslog
			messages (default ${DEFAULT-VALUE} if not provided) otherwise.""",
		paramLabel = "<port>",
		scope = ScopeType.INHERIT)
	private Integer optPort;

	// internal stuff

	private InetSocketAddress quLogSecketAddress;

	private Source source;

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

		private static final String RULES_LANG = "js";
		private static final ObjectMapper MAPPER = new ObjectMapper();

		@ParentCommand
		private qulog parent;

		@Option(
			names = { "-r", "--rules" },
			description = "Path to rules file.",
			required = true,
			paramLabel = "<file>")
		private Path rulesFilePath;

		private String rulesCode = "";
		private long rulesLastModifiedTime = -1;

		@Override
		public void run() {

			var line = "";

			try (
				final var context = createRulesContext();
				final var reader = new BufferedReader(new InputStreamReader(System.in));) {

				while ((line = reader.readLine()) != null) {
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
				System.out.println("Skipping invalid journal entry: " + line);
				return;
			}

			final var message = Optional
				.ofNullable(json.get("MESSAGE"))
				.map(Object::toString)
				.orElseThrow(NoMessageException::new);

			final var modTime = Files
				.getLastModifiedTime(rulesFilePath)
				.toMillis();

			if (modTime != rulesLastModifiedTime) {

				rulesCode = Files.readString(rulesFilePath);
				rulesLastModifiedTime = modTime;

				context.eval(org.graalvm.polyglot.Source.newBuilder(
					"js", rulesCode,
					rulesFilePath.getFileName().toString())
					.build());

				System.out.println("Loaded updated rules file: " + rulesFilePath);
			}

			context
				.getBindings(RULES_LANG)
				.putMember("$LOG", json);

			Value rules = context.getBindings("js").getMember("rules");

			final var result = rules.execute();

			if (result == null || !result.hasMembers()) {
				return; // no action
			}

			final var resultApp = getMember(result, "application").orElseThrow(NoApplicationRuleResponseException::new);
			final var resultCategory = getMember(result, "category").orElse("General Category");
			final var resultLevel = getMember(result, "level")
				.map(LOG_LEVEL_CONVERTER::convert)
				.orElse(LogLevel.INFO);

			final var address = parent.quLogSecketAddress;

			final var level = resultLevel;
			final var datetime = getDateTime();
			final var source = parent.source;
			final var application = new Application(resultApp, "someprocess");
			final var category = new Category(resultCategory);
			final var messageId = UUID.randomUUID();
			final var user = System.getProperty("user.name");

			final var sd = new StructuredData(source, application, category, user, messageId);
			final var entry = new LogEntry(level, datetime, source, application, sd, message, messageId);

			try {
				sendLogEntry(entry, address);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		private Optional<String> getMember(final Value value, final String member) {

			return Optional
				.ofNullable(value.getMember(member))
				.map(Value::asString)
				.filter(not(Objects::isNull))
				.filter(not(String::isEmpty));
		}

		@SuppressWarnings("unchecked")
		private Map<String, Object> parse(final String line) {
			try {
				return MAPPER.readValue(line, Map.class);
			} catch (Exception e) {
				return null; // silently ignore all parsing errors
			}
		}

		private static Context createRulesContext() {
			return Context
				.newBuilder()
				.allowAllAccess(true)
				.build();
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
		String message;

		@Override
		public void run() {

			final var address = parent.quLogSecketAddress;

			final var level = optLogLevel;
			final var datetime = getDateTime();
			final var source = parent.source;
			final var application = new Application(optApplicationName, optProcessName);
			final var category = new Category(optCategoryName);
			final var messageId = UUID.randomUUID();
			final var user = System.getProperty("user.name");

			final var sd = new StructuredData(source, application, category, user, messageId);
			final var entry = new LogEntry(level, datetime, source, application, sd, message, messageId);

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

	private static void sendLogEntry(final LogEntry entry, final InetSocketAddress address) throws IOException {

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

	private static InetSocketAddress getQuLogRemoteAddress(final String host, final int port) {
		return new InetSocketAddress(host, port);
	}

	private Source getLocalAddressesFor(final String name, final InetSocketAddress remote) throws IOException {

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

			return new Source(name, ip, mac, hostname);
		}
	}

	private static String getLocalIpAddressFrom(final InetAddress local) throws IOException {
		return local.getHostAddress();
	}

	private static String getLocalMacAddressFrom(final InetAddress local) throws SocketException {

		final var iface = NetworkInterface.getByInetAddress(local); // eth0, wlan0, etc
		final var mac = iface.getHardwareAddress();

		return IntStream
			.range(0, mac.length)
			.mapToObj(i -> String.format("%02X", mac[i]))
			.collect(joining(":"));
	}

	private static String getLocalHostname() throws FileNotFoundException, IOException {
		try (final var reader = new BufferedReader(new FileReader(FILE_HOSTNAME))) {
			return reader.readLine(); // only line in file
		}
	}

	private static String getShortId(final String string) {

		final var crc = new CRC32();

		crc.update(string.getBytes());

		final var value = crc.getValue();
		final var base36 = Long.toString(value, 36);

		return base36.length() > 10 ? base36.substring(0, 10) : base36;
	}

	private static OffsetDateTime getDateTime() {

		final var now = OffsetDateTime.now();
		final var truncated = now.truncatedTo(SECONDS);

		// We need truncated time without nanos as QuLog Center does not accept them.

		return truncated;
	}

	record Source(
		String name,
		String ip,
		String mac,
		String hostname) {

		Source {
			mac = mac.toLowerCase();
		}
	}

	record Application(
		String name,
		String id,
		String procName,
		long procId) {

		Application(final String name, final String procName) {
			this(name, procName, ProcessHandle.current().pid());
		}

		Application(final String name, final String procName, final long procId) {
			this(name, QL_SD_APP_ID_PREFIX + getShortId(name), procName, procId);
		}
	}

	record Category(
		String name,
		String id) {

		Category(final String name) {
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
	record StructuredData(
		Source source,
		Application application,
		Category category,
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
		StructuredData sd) {

		static final int VERSION = 1;

		LogEntry(
			final LogLevel level,
			final OffsetDateTime datetime,
			final Source local,
			final Application app,
			final StructuredData sd,
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

	enum Facility {

		USER_LEVEL(1);

		final int code;

		Facility(final int code) {
			this.code = code;
		}
	}

	enum Severity {

		INFORMATIONAL(6),
		WARNING(4),
		ERROR(3);

		final int code;

		Severity(final int code) {
			this.code = code;
		}
	}

	enum LogLevel {

		INFO(Facility.USER_LEVEL, Severity.INFORMATIONAL),
		WARNING(Facility.USER_LEVEL, Severity.WARNING),
		ERROR(Facility.USER_LEVEL, Severity.ERROR);

		final int pri;

		LogLevel(final Facility facility, final Severity severity) {
			final var fac = facility.code;
			final var sev = severity.code;
			this.pri = fac * 8 + sev;
		}
	}

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
