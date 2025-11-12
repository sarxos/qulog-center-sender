
const CAT_USER_ACCESS = "User Access";
const CAT_SERVICES = "Services";
const CAT_MEMORY = "Memory";
 
/**
 * Filtering function to categorize logs.
 */
function filter() {

  // use login and logout events.

  if (isUserLogin($LOG)) {
    return {
      app: "Login Daemon",
      cat: CAT_USER_ACCESS,
      lvl: "info",
      msg: "User " + $LOG.USER_ID + " logged in."
    };
  }

  if (isUserLogout($LOG)) {
    return {
      app: "Login Daemon",
      cat: CAT_USER_ACCESS,
      lvl: "info",
      msg: "User " + $LOG.USER_ID + " logged out."
    };
  }

  // Start and stop of Nginx Proxy Manager via Docker Compose.

  if (isNPMComposeStartup($LOG)) {
    return {
      application: "Nginx Proxy Manager",
      category: CAT_SERVICES,
      level: "info",
      message: "Nginx Proxy Manager started."
    };
  }

  if (isNPMComposeShutdown($LOG)) {
    return {
      application: "Nginx Proxy Manager",
      category: CAT_SERVICES,
      level: "info",
      message: "Nginx Proxy Manager stopped."
    };
  }

  if (isNPMComposeStartupFailure($LOG)) {
    return {
      application: "Nginx Proxy Manager",
      category: CAT_SERVICES,
      level: "error",
      message: "Nginx Proxy Manager startup failed!"
    };
  }

  // Just for tests.

  if ($LOG._COMM == "earlyoom") {
    return {
      application: "Early OOM",
      category: CAT_MEMORY,
      level: "warning",
      message: "OOM mem stats: " + $LOG.MESSAGE
    };
  }

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