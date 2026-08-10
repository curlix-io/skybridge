"""Gunicorn config for the Presidio Analyzer container: preload the spaCy model once in the master
process (workers then inherit it via copy-on-write instead of each loading their own ~750MB copy),
and size workers/threads for the analyzer's synchronous, CPU-bound-per-request inference. workers=2
pairs with this container's `cpu: 1024m` request in docker-compose.yml — a common sizing rule of
thumb for this kind of synchronous inference workload is one worker per whole CPU core requested —
each worker fully saturates one core for the duration of an inference call, so raise both together
if you give the container more CPU.
"""

bind = "0.0.0.0:3000"
workers = 2
threads = 4
timeout = 120
keepalive = 65
preload_app = True
worker_class = "gthread"
loglevel = "debug"
