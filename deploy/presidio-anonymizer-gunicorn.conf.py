"""Gunicorn config for the Presidio Anonymizer container — verbatim values from hoop.dev's documented
Helm chart defaults (https://hoop.dev/docs/setup/deployment/presidio). The anonymizer holds no ML
model and does pure string substitution, so it's far cheaper than the analyzer; preload_app has no
real effect here since there's no model to share via copy-on-write, but hoop's chart keeps the same
Gunicorn template across both services for config parity, and we do the same.
"""

bind = "0.0.0.0:3000"
workers = 2
threads = 4
timeout = 120
keepalive = 65
preload_app = True
worker_class = "gthread"
loglevel = "debug"
