"""Benchmark target: an OS command injection (CWE-78) and a clean variant."""

import os
import subprocess


def ping(request):
    # VULN (CWE-78): unsanitised host flows into a shell.
    host = request.args["host"]
    os.system("ping -c 1 " + host)


def ping_safe(request):
    # CLEAN: argument vector, no shell.
    host = request.args["host"]
    subprocess.run(["ping", "-c", "1", host], shell=False, check=False)
