import { createRelayApp } from "./app.js";
import { loadRelayConfig } from "./config.js";

const config = await loadRelayConfig(process.env);
const app = await createRelayApp(config);

let shuttingDown = false;

async function shutdown(signal: string) {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;
  app.log.info({ signal }, "shutting down relay");
  try {
    await app.close();
  } catch (error) {
    app.log.error({ error, signal }, "relay shutdown failed");
    process.exitCode = 1;
  }
}

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    void shutdown(signal);
  });
}

try {
  await app.listen({
    host: config.host,
    port: config.port,
  });
} catch (error) {
  app.log.error(error);
  process.exitCode = 1;
}
