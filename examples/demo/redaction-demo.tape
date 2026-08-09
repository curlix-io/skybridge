# VHS tape for the Skybridge redaction demo (https://github.com/charmbracelet/vhs).
# Regenerate with:
#   vhs examples/demo/redaction-demo.tape
# Requires the demo stack's prerequisites (Docker, psql, mysql client, mongosh) and Go, same as
# examples/demo/demo-commands.sh. Types out each real command live instead of piping a script
# through silently, so the recording shows exactly what a user would type.

Output examples/demo/redaction-demo.gif

Require go
Require docker

Set Shell "bash"
Set FontSize 15
Set Width 1200
Set Height 720
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 30ms

Hide
Type "source examples/demo/vhs-setup.sh"
Enter
Sleep 500ms
Show

# ---- 0a. Start the stack ----
Type "./examples/demo/run-demo.sh up"
Enter
Sleep 45s

# ---- 0b. See the agent's configuration options ----
Type "go run ./cmd/skybridge-agent --help"
Enter
Sleep 3s

# ---- 1-2. Postgres: raw vs. column-overlay masked ----
Type "sql localhost:15433   # raw"
Enter
Sleep 2s
Type "sql localhost:15432   # masked — email/ssn redacted by the column overlay"
Enter
Sleep 2s

# ---- 3. Postgres: excluded columns pass through ----
Type `psql -P pager=off "postgres://postgres:demo@localhost:15432/appdb" -c "select employee_id, name from customers;"`
Enter
Sleep 2s

# ---- 4. Postgres: free text, content-detection catches the phone number ----
Type `psql -P pager=off "postgres://postgres:demo@localhost:15432/appdb" -c "select notes from customers where id = 1;"`
Enter
Sleep 3s

# ---- 5-7. MySQL: raw, masked, excluded columns ----
Type "mysql_q x 13307   # raw"
Enter
Sleep 2s
Type "mysql_masked x 13306   # masked — note --ssl-mode=DISABLED (see comment in demo-lib.sh)"
Enter
Sleep 2s

# ---- 8-9. MongoDB: raw vs. masked, nested profile.email included ----
Type "mongo localhost:27019   # raw"
Enter
Sleep 2s
Type "mongo localhost:27020   # masked — profile.email redacted despite being nested"
Enter
Sleep 2s

# ---- 10. Custom overlay file ----
Type "cat examples/demo/custom-overlay.yaml"
Enter
Sleep 2s
Type `start_agent "SKYBRIDGE_DB_TYPE=postgres SKYBRIDGE_UPSTREAM=localhost:15433 SKYBRIDGE_LISTEN=:15436 SKYBRIDGE_PII_OVERLAY_FILE=$(pwd)/examples/demo/custom-overlay.yaml" && wait_ready 15436`
Enter
Sleep 3s
Type `psql -P pager=off "postgres://postgres:demo@localhost:15436/appdb" -c "select employee_id, name, email from customers;"   # 'name' now redacted too`
Enter
Sleep 3s

# ---- 11. JSON blob in a text column ----
Type `psql -P pager=off "postgres://postgres:demo@localhost:15433/appdb" -c "select id, metadata from customers where id = 3;"   # raw`
Enter
Sleep 2s
Type `psql -P pager=off "postgres://postgres:demo@localhost:15432/appdb" -c "select id, metadata from customers where id = 3;"   # masked — Presidio catches the phone number inside the JSON string`
Enter
Sleep 3s

# ---- 13. Partial-mask anonymizer ----
Type `export SKYBRIDGE_MASK_ANONYMIZERS='{"PHONE_NUMBER":{"type":"mask","masking_char":"*","chars_to_mask":6,"from_end":true}}'`
Enter
Sleep 500ms
Type `start_agent "SKYBRIDGE_DB_TYPE=postgres SKYBRIDGE_UPSTREAM=localhost:15433 SKYBRIDGE_LISTEN=:15437 SKYBRIDGE_MASK_ANALYZE_URL=http://localhost:13000/analyze SKYBRIDGE_MASK_ANONYMIZE_URL=http://localhost:13001/anonymize" && wait_ready 15437`
Enter
Sleep 3s
Type `psql -P pager=off "postgres://postgres:demo@localhost:15437/appdb" -c "select notes from customers where id = 1;"   # partial mask instead of a full [redacted]`
Enter
Sleep 3s

# ---- Tear down ----
Type "cleanup_extra_agents && ./examples/demo/run-demo.sh down"
Enter
Sleep 10s
