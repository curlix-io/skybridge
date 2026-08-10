// Seeds one document with a BSON datetime field ("dob") the stub control plane has a confirmed
// full_redact label for, plus a plain string field ("name") as an unaffected control — proving
// docs/PATH_LABEL_IDENTITY_GAPS_DESIGN.md's Gap B Mongo fix redacts a typed (non-string) field
// through a real skybridge-agent, not just a unit test.
db = db.getSiblingDB("appdb");
db.users.drop();
db.users.insertOne({
  _id: 1,
  name: "Alice Smith",
  dob: new Date("1990-05-14T00:00:00Z"),
});
