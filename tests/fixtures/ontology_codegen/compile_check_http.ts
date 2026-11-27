import { ScopedOntologyClient } from "./scoped_http_client.v1.ts";

const client = new ScopedOntologyClient({
  baseUrl: "http://127.0.0.1:1",
  authorization: "Bearer test",
});

void client.evaluateTicketSet(
  {
    propertyFilters: [{ key: "title", op: "eq", value: "urgent" }],
    traversal: { relation: "AssignedTo" },
  },
  "op-1",
);
void client.submitAssign({ assignee: "ada" }, "op-2");

void client.evaluateTicketSet(
  {
    propertyFilters: [
      // @ts-expect-error unknown property is not in the pinned revision
      { key: "not-a-property", op: "eq", value: "x" },
    ],
  },
  "op-3",
);

void client.submitAssign(
  {
    assignee: "ada",
    // @ts-expect-error unknown Action parameter is not in the pinned revision
    extra: true,
  },
  "op-4",
);

void client.evaluateTicketSet(
  {
    traversal: {
      // @ts-expect-error unknown link is not in the pinned revision
      relation: "NotALink",
    },
  },
  "op-5",
);
