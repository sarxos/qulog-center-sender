
const CAT_USER_ACCESS = "User Access";
const CAT_SECURITY = "Security";
const CAT_SERVICES = "Services";
const CAT_MEMORY = "Memory";

const INFO = "info";
const WARNING = "warning";
const ERROR = "error";

/**
 * Filtering function to categorize logs.
 */
function filter() {

  // user login and logout events

  if (isUserLogin($LOG)) {
    return {
      application: "Login Daemon",
      category: CAT_USER_ACCESS,
      level: INFO,
      message: "User " + $LOG.USER_ID + " logged in.",
    };
  }

  if (isUserLogout($LOG)) {
    return {
      application: "Login Daemon",
      category: CAT_USER_ACCESS,
      level: INFO,
      message: "User " + $LOG.USER_ID + " logged out.",
    };
  }

  // start and stop of nginx proxy manager

  if (isNPMComposeStartup($LOG)) {
    return {
      application: "Nginx Proxy Manager",
      category: CAT_SERVICES,
      level: INFO,
      message: "Nginx Proxy Manager started.",
    };
  }

  if (isNPMComposeShutdown($LOG)) {
    return {
      application: "Nginx Proxy Manager",
      category: CAT_SERVICES,
      level: INFO,
      message: "Nginx Proxy Manager stopped.",
    };
  }

  if (isNPMComposeStartupFailure($LOG)) {
    return {
      application: "Nginx Proxy Manager",
      category: CAT_SERVICES,
      level: ERROR,
      message: "Nginx Proxy Manager startup failed!",
    };
  }

  // sudo command usage

  if (isSudo($LOG)) {
    const sudo = parseSudoMessage($LOG.MESSAGE);
    const failure = !!sudo.failure;
    const result = {
      application: "Sudo",
      category: CAT_USER_ACCESS,
    };
    return {
      ...result,
      level: failure ? ERROR : WARNING,
      message: failure
        ? `User ${sudo.caller} failed to execute command as ${sudo.user}: ${sudo.cmd} (reason: ${sudo.failure})`
        : `User ${sudo.caller} executed command as ${sudo.user}: ${sudo.cmd}`,
    };
  }

  // ssh failed login attempts

  if (isSSHFailedEvent($LOG)) {
    return {
      application: "SSH",
      category: CAT_SECURITY,
      level: ERROR,
    };
  }

  // Just for tests.

  // if ($LOG._COMM == "earlyoom") {
  //   return {
  //     application: "Early OOM",
  //     category: CAT_MEMORY,
  //     level: "warning",
  //     message: "OOM mem stats: " + $LOG.MESSAGE,
  //   };
  // }

  return null;
}

// some utility functions

// "MESSAGE" : "New session 1 of user test."
function isUserLogin(log) {
  return isLogindEvent(log) && log.MESSAGE.startsWith("New session");
}

// "MESSAGE" : "Session 2 logged out. Waiting for processes to exit."
function isUserLogout(log) {
  return isLogindEvent(log) && log.MESSAGE.startsWith("Removed session");
}

/**
 * Is log created by systemd-logind.
 */
function isLogindEvent(log) {
  return log &&
    log._COMM == 'systemd-logind' && 
    log.USER_ID;
}

// "MESSAGE" : "Finished npm-compose.service - Rootless Docker Compose for Nginx Proxy Manager.",
function isNPMComposeStartup(log) {
  return isNPMComposeEvent(log) &&
    log.JOB_TYPE == "start" && 
    log.MESSAGE.startsWith("Finished npm-compose.service");
}

function isNPMComposeStartupFailure(log) {
  return isNPMComposeEvent(log) &&
    log.JOB_TYPE == "start" && 
    log.MESSAGE.startsWith("Failed to start npm-compose.service");
}

// "MESSAGE" : "Stopped npm-compose.service - Rootless Docker Compose for Nginx Proxy Manager.",
function isNPMComposeShutdown(log) {
  return isNPMComposeEvent(log) &&
    log.JOB_TYPE == "stop" &&
    log.MESSAGE.startsWith("Stopped npm-compose.service");
}

/**
 * Is log created by npm-compose.service.
 */
function isNPMComposeEvent(log) {
  return log &&
    log._COMM == 'systemd' &&
    log.USER_UNIT == 'npm-compose.service';
}

/**
 * Is log created by sudo command invocation.
 */
function isSudo(log) {
  return log &&
    log._COMM == 'sudo' &&
    log._CMDLINE &&
    log.MESSAGE &&
    log.MESSAGE.includes("TTY") &&
    log.MESSAGE.includes("PWD") &&
    log.MESSAGE.includes("USER") &&
    log.MESSAGE.includes("COMMAND");
}

/**
 * Extracts details from sudo MESSAGE field.
 */
function parseSudoMessage(message) {
  const s = message.trim();
  const regex = /^(\S+)\s*:\s*(?:([^;]+?)\s*;\s*)?TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.+)$/;
  const [ , caller, failure, tty, pwd, user, cmd ] = s.match(regex);
  return { 
    caller, // by whom sudo was called
    failure, // reason for sudo failure 
    tty, // on which terminal
    pwd, // in which directory
    user, // which user sudo switched to
    cmd // what command was executed
  };
}

/**
 * Is log created by ssh service.
 */
function isSSHEvent(log) {
  return log &&
    log._COMM == 'sshd-session' &&
    log._SYSTEMD_UNIT == 'ssh.service';
}

/**
 * Is it SSH failed login attempt.
 */
function isSSHFailedEvent(log) {
  return isSSHEvent(log) && (
    log.MESSAGE.startsWith("Invalid user") ||
    log.MESSAGE.startsWith("Failed password") ||
    log.MESSAGE.startsWith("Failed publickey"));
}
