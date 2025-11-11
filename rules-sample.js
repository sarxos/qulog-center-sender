function filter() {

  if ($LOG.MESSAGE && $LOG.MESSAGE.includes("npm-compose.service")) {
    return {
      application: "Nginx Proxy Manager",
      category: "Docker Compose"
    };
  }

  if ($LOG._COMM == "earlyoom") {
    return {
      application: "Early OOM",
      category: "Memory Management"
    };
  }

  return null;
}