// name/email nest under "profile" to demonstrate that the column-name overlay redacts by bare leaf
// key regardless of nesting depth (see internal/wire/mongo/bson.go) — profile.email is redacted by
// the same "email" overlay rule that redacts a top-level email field. "order.total" has no overlay
// rule and is left untouched, showing non-PII nested fields pass through as-is.
db = db.getSiblingDB("appdb");
db.customers.drop();
db.customers.insertMany([
  {
    _id: 1, employee_id: "EMP-4471", ssn: "123-45-6789",
    profile: { name: "Alice Smith", email: "alice@example.com" },
    order: { total: 42 },
  },
  {
    _id: 2, employee_id: "EMP-8823", ssn: "987-65-4321",
    profile: { name: "Bob Jones", email: "bob@example.com" },
    order: { total: 17 },
  },
]);
