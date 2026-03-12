import { anyApi, cronJobs } from "convex/server";

const crons = cronJobs();

crons.interval(
  "prune expired relay state",
  { minutes: 5 },
  anyApi.relay.cleanup.pruneExpiredStateInternal,
  {},
);

export default crons;
