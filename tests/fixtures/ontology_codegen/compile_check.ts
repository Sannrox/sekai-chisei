import { ScopedOntologyClient } from "./scoped_client.v1.ts";

const client = new ScopedOntologyClient();
client.ticket("op-1", { title: "urgent" });
client.assign("op-2", { assignee: "ada" });
client.countOpen("op-3", { status: "open" });
client.assignedTo("op-4", {});
