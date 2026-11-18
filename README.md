# CVE-2026-114938 (Java4Shell) — Ubuntu and Docker JVM Audit

`audit-java4shell-v1.4.sh` is a **read-only, best-effort inventory and exposure assessment** for CVE-2026-114938 on Ubuntu/Linux servers. It checks detected host JVMs and the JVMs it can reach in **running Docker containers**, then reports whether their runtime versions and CPU capabilities suggest exposure.

It is intended for security operations, server inventory, and triage. **It is not an exploit test or a comprehensive vulnerability scanner.** A clean result only covers the JVMs and locations actually inspected.

## Requirements

- Ubuntu 20.04, 22.04, 24.04 or newer (also usable on other Linux systems with the required utilities).
- Bash 4 or newer; `/proc`; common GNU tools including `readlink`, `stat`, `find`, `awk`, `sed`, `sort`, `timeout`, `date` and `hostname`.
- `pgrep` (from `procps`) for running-Java-process discovery.
- **Run with root privileges** to inspect JVM executables owned by other users and access Docker. Non-root execution is permitted for partial troubleshooting but explicitly records a `REVIEW` finding and cannot produce a clean exit status.
- Docker CLI **optional**. If installed, its daemon must be reachable to inspect running containers. The script does not install Docker or require it for host-only checks.
- Container-based detection is best-effort: for full discovery the container should have `sh` and a runnable Java executable; shell-less images receive additional direct-path probes.

## Quick start

Copy `audit-java4shell-v1.4.sh` to the server and run:

```bash
chmod +x audit-java4shell-v1.4.sh
sudo ./audit-java4shell-v1.4.sh
```

To check only the host (skip Docker):

```bash
sudo ./audit-java4shell-v1.4.sh --no-docker
```

To see supported options:

```bash
./audit-java4shell-v1.4.sh --help
```

To save a dated report **and preserve the script's exit status**:

```bash
sudo bash -o pipefail -c './audit-java4shell-v1.4.sh | tee "java4shell-$(hostname -s)-$(date -u +%F).txt"'
```

The saved report can contain hostnames, container names, image names, usernames, and JVM paths. Handle it according to your operational-data retention policy.

## What is checked

| Area | How it is assessed |
| --- | --- |
| Host information | OS name, architecture, and CPU flags exposed to the OS |
| CPU prerequisites | `avx512f`, `avx512bw`, `avx512vbmi`, and `bmi2` (from the first CPU record) |
| Running host JVMs | Processes named `java`; resolves `/proc/<PID>/exe`, invokes `-version`, and identifies the process owner |
| Other host JVMs | Default `java`, optional `JAVA_HOME`, and common JDK directories including `/usr/lib/jvm`, `/opt`, and `/usr/local` |
| JVM vendor/version | Parses the Java version output and attempts to identify Oracle, OpenJDK, Corretto, Temurin, Zulu, Liberica, and others |
| Running Docker containers | Lists running containers, searches common JVM paths from inside each container, and probes `java -version` |
| Shell-less containers | Tries a limited set of likely Java executable paths; otherwise flags the container for review |
| Stopped Docker containers | Counts exited containers, but does **not** scan or start them |
| Unused Docker images | Does **not** scan them |

Each runtime is reported with its context/location, executable path, version, identified distribution, and assessment. Host discovery uses a short-lived private temporary file to collect executable paths and accurately detect `find` permission errors; the file is deleted at exit. An unreadable directory is reported as `REVIEW` rather than causing an uncaught audit error. The script **does not print full process arguments, environment variables, or application configuration values**.

**Note:** This audit invokes Java executables with `-version`, including within running containers. Use it only on systems and container images you trust; it does not execute an exploit payload, but a nonstandard or malicious `java` executable could behave unexpectedly.

## Understanding the findings

| Result text | Meaning / action |
| --- | --- |
| `NOT AFFECTED` | The identified runtime falls outside the script's reported affected range (for example, standard Java 11). |
| `NOT IN REPORTED AFFECTED RANGE` | Runtime major version is below the version range encoded by the script. |
| `NOT EXPOSED` | Required CPU features are not exposed in the **current** execution environment. Reassess after CPU, VM, or host migration. |
| `POTENTIAL RISK` | Runtime appears to be in an affected version range and the required CPU features are exposed; investigate/remediate promptly. |
| `REVIEW VENDOR FIX` | Version meets a reference fixed baseline but the distribution/build's actual patched status still requires vendor confirmation. |
| `REVIEW` | Java version, CPU capabilities, vendor-specific case, or container discovery could not be conclusively assessed. |

The script uses the following **reference** fixed version thresholds for applicable Java majors: Java 17 `17.0.21.1`, Java 21 `21.0.13.1`, Java 25 `25.0.5.1`, and Java 27 `27.0.1.1`. These are comparison baselines used by the script, **not a guarantee of a vendor-specific fix**. Vendors and Linux distributions may use backports or different build numbers.

Java 8 performance builds are a special case: the script reviews or flags suspected Oracle performance builds separately rather than treating every Java 8 build as equivalent. Detection from `java -version` is not guaranteed; verify unusual vendor builds manually.

### Overall result and exit codes

The summary prints counts of safe/not-currently-exposed checks, potential risks, review items, and inspected Docker containers.

| Exit code | Overall result | Suggested automation policy |
| --- | --- | --- |
| `0` | `NO CURRENT CVE EXPOSURE IDENTIFIED in the assessed scope` | Record result; remember scan limitations. |
| `1` | `POTENTIAL EXPOSURE` | Fail the security gate and investigate. |
| `2` | `INCOMPLETE / VENDOR VERIFICATION NEEDED` | Do **not** mark clean; complete manual investigation. |

If both potential-risk and review findings exist, the script exits **1** (risk takes precedence). **Do not interpret exit code 0 as proof that all Java software and images on the machine are vulnerability-free.**

Example, preserving the exit code while printing the report:

```bash
sudo ./audit-java4shell-v1.4.sh
rc=$?
case "$rc" in
  0) echo 'No current exposure identified in assessed scope' ;;
  1) echo 'Potential exposure found — investigate urgently' ;;
  2) echo 'Audit incomplete — manual review required' ;;
esac
```

## Fixed in v1.4: installed-JVM inventory errors

When `find` cannot read part of `/opt` or another search directory (especially when run without `sudo`), v1.3 could print `AUDIT ERROR near line 285` from its process-substitution error trap. Version 1.4 detects the `find` exit status in the parent process, reports `REVIEW: could not completely inventory ...`, continues checking all other discovered JVMs, and returns exit code `2` unless a potential risk takes precedence. Running without root privileges also produces an explicit `REVIEW` finding.

## Docker-owned Java processes in the host process table

Docker JVMs also appear in the host's process table. Executing their `/proc/<PID>/exe` directly on the host can fail to load container-only libraries such as `libjli.so`. Version 1.4 uses PID-only `docker top` output for local Docker containers to associate those processes with containers **without reading JVM command arguments**. It then checks the runtime from inside the container using `docker exec`. A deferred process is only considered covered if its JVM executable path was successfully checked in that same container. If association or verification is unsuccessful, the result remains `REVIEW` rather than silently becoming clean.

## Docker behavior and important caveats

- Docker is inspected only if the Docker CLI exists, Docker is reachable, and `--no-docker` was not selected.
- The script runs `docker exec` for discovery and Java version checks in **already-running** containers. It does not start, stop, or modify containers intentionally.
- A container without a shell or without Java at the probed paths may be unverified; **absence of detection does not prove absence of Java**.
- Multi-stage or minimal images, custom JVM paths, shaded/native applications, and application-bundled runtimes can escape discovery.
- The host CPU flags are used for local Docker containers. For Docker contexts that may be remote, CPU capability is marked unknown rather than assuming the local CPU applies.
- It does not assess Kubernetes workloads, containerd/Podman instances, stopped containers, or unused images.
- A container with no Java detected in checked paths is counted separately; this does not guarantee a complete inventory.

For authoritative coverage, supplement this script with an image/package inventory, SBOM or container vulnerability scan, plus vendor advisories for the exact JVM distributions in use.

## Host coverage limitations

- Searches **common paths**, not the entire filesystem.
- Running-process discovery checks executables named `java` via `pgrep -x java`; renamed JVM executables and embedded runtimes may be missed.
- Does not scan files inside JARs or detect every bundled, native, or dormant runtime.
- CPU flag logic reads the **first** `/proc/cpuinfo` flags entry; heterogeneous hardware and virtualized/remote environments require separate assessment.
- Java versions alone do not establish the presence or absence of vendor backported security fixes.
- No active exploit test, network probe, remediation, patch installation, or service restart is performed.

## Recommended triage workflow

1. Run on each Ubuntu server as root, including Docker checks where applicable.
2. Save the dated report for the security change/audit record.
3. For `POTENTIAL RISK`, identify the exact JVM distribution, release, build, and whether the vulnerable code path is reachable; apply the vendor's fix or an appropriate mitigation.
4. For `REVIEW`, investigate undiscovered/bundled runtimes, vendor build details, inaccessible containers, and unknown CPU capabilities.
5. Re-run after patches, host/VM migrations, JVM changes, or significant container-image updates.

## Security and operational notes

This utility deliberately avoids printing sensitive Java `-D` properties, process command lines, Docker environment variables, or passwords. **Do not replace its safe commands with `ps -ef` or `docker inspect` dumps when sharing findings**, because such output can expose secrets. Report metadata (such as image names and paths) should still be treated as internal infrastructure information.

The script makes no changes to installed software and does not restart services. It does execute short Java version probes (`java -version`) and Docker commands, subject to timeouts. Run with appropriate authorization and operational controls.

## Files

```text
audit-java4shell-v1.4.sh    Bash scanner
README-audit-java4shell-v1.4.md    This guide
```

## Scope of the conclusion

A passing audit means **no current exposure was identified among the JVMs successfully examined under the checked runtime and CPU conditions**. It does **not** certify the server, Java applications, or all container images as free of CVE-2026-114938 or other vulnerabilities.
