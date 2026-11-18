#!/usr/bin/env bash
# CVE-2026-114938 / Java4Shell conservative Ubuntu + Docker inventory
# Full script v1.4 - keep the entire file, not only the last section.
# Read-only. Does not print Java arguments, process environments, or Docker env.
# Requires: Bash 4+, GNU coreutils, /proc. Docker CLI optional.
# 0 = no currently identified risk / checks complete
# 1 = potentially affected runtime on a CPU exposing required features
# 2 = one or more checks incomplete / vendor patch needs review

set -Eeuo pipefail
# Unexpected execution errors must never produce a misleading clean audit.
trap 'status=$?; printf "AUDIT ERROR near line %s (status %s). Result is INCOMPLETE.\n" "$LINENO" "$status" >&2; exit 2' ERR
# Host discovery uses a private temporary inventory file so find(1) failures
# can be detected reliably (unlike process substitution with an ERR trap).
SCAN_TEMP=''
cleanup_scan_temp() {
    if [[ -n "$SCAN_TEMP" ]]; then
        rm -f -- "$SCAN_TEMP"
    fi
}
trap cleanup_scan_temp EXIT
export LC_ALL=C

CVE='CVE-2026-114938'
SAFE=0
RISK=0
REVIEW=0
NO_JAVA=0
HOST_FOUND=0
CONTAINER_FOUND=0
CPU='UNKNOWN'
ARCH="$(uname -m 2>/dev/null || printf 'unknown')"
declare -A SEEN_HOST_JAVA=()
# Identify Docker-owned host PIDs before host JVM probing to avoid running a
# container-linked /proc/PID/exe in the host's incompatible library namespace.
declare -A DOCKER_HOST_PID_OWNER=()
declare -A DEFERRED_DOCKER_JAVA_PID=()
declare -A DEFERRED_DOCKER_JAVA_PATH=()
declare -A VERIFIED_DOCKER_JAVA_PATH=()

usage() {
    cat <<'EOF'
Usage: sudo bash audit-java4shell.sh [--no-docker] [--help]

Inventory running host JVMs, default/installed JVMs, and running Docker
containers. Does not start/stop containers, restart Java, install packages,
or execute a vulnerability payload. Stopped containers and unused images are
listed by count but not scanned.

Report contains no JVM command-line arguments or environment variables.
Exit codes: 0 = no identified risk (in assessed scope),
            1 = potentially affected JVM and requisite CPU features,
            2 = incomplete checks or patch confirmation needed.
EOF
}

CHECK_DOCKER=1
while (($#)); do
    case "$1" in
        --no-docker) CHECK_DOCKER=0 ;;
        --help|-h) usage; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

say() { printf '%s\n' "$*"; }
section() { printf '\n=== %s ===\n' "$*"; }

# Extract numeric Java version, e.g. 17.0.21.0.3, 21.0.13.1, 8.0.452.
version_numeric() {
    local v="$1"
    if [[ "$v" =~ ^1\.8\.0_([0-9]+) ]]; then
        printf '8.0.%s' "${BASH_REMATCH[1]}"
    elif [[ "$v" =~ ^([0-9]+([.][0-9]+)*) ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    else
        printf ''
    fi
}

version_ge() {
    # Compare numeric dot-separated versions with GNU sort -V.
    [[ "$1" == "$2" ]] && return 0
    [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n 1)" == "$1" ]]
}

# Output is captured but NEVER printed, because JVM startup settings may
# disclose secrets. Only the first quoted version is extracted.
parse_jvm() {
    local raw="$1"
    JVM_VERSION="$(printf '%s\n' "$raw" | sed -nE 's/.*version "([^"]+)".*/\1/p' | head -n 1)"
    JVM_VERSION_NUM="$(version_numeric "$JVM_VERSION")"
    JVM_VENDOR='Unidentified'
    local lower="${raw,,}"
    case "$lower" in
        *corretto*) JVM_VENDOR='Amazon Corretto' ;;
        *temurin*|*adoptium*) JVM_VENDOR='Eclipse Temurin' ;;
        *zulu*|*azul*) JVM_VENDOR='Azul Zulu' ;;
        *liberica*) JVM_VENDOR='BellSoft Liberica' ;;
        *sapmachine*) JVM_VENDOR='SAP SapMachine' ;;
        *graalvm*) JVM_VENDOR='GraalVM' ;;
        *microsoft*) JVM_VENDOR='Microsoft OpenJDK' ;;
        *red\ hat*) JVM_VENDOR='Red Hat OpenJDK' ;;
        *java\(tm\)*|*oracle*) JVM_VENDOR='Oracle Java' ;;
        *openjdk*) JVM_VENDOR='OpenJDK (vendor unconfirmed)' ;;
    esac
    JVM_PERF=0
    if [[ "$lower" == *perf* ]]; then JVM_PERF=1; fi
}

assess_jvm() {
    local v="$JVM_VERSION_NUM" major threshold=''
    if [[ -z "$v" ]]; then
        ASSESS='REVIEW: Java version could not be parsed'
        ((REVIEW+=1))
        return
    fi
    major="${v%%.*}"
    if (( major == 8 )); then
        # Oracle 8 performance builds are a documented special case.
        if (( JVM_PERF )); then
            if version_ge "$v" '8.0.513'; then
                ASSESS='REVIEW: Java 8 performance build; confirm vendor fix'
                ((REVIEW+=1))
            elif [[ "$CPU" == 'YES' ]]; then
                ASSESS='POTENTIAL RISK: Java 8 performance build'
                ((RISK+=1))
            elif [[ "$CPU" == 'NO' ]]; then
                ASSESS='NOT EXPOSED: required CPU features unavailable'
                ((SAFE+=1))
            else
                ASSESS='REVIEW: Java 8 performance build; CPU unknown'
                ((REVIEW+=1))
            fi
            return
        fi
        # Java -version may not always reveal Oracle's special performance
        # builds. Keep the relevant Oracle 8 update in manual review even
        # when its version string does not explicitly contain "perf".
        if [[ "$JVM_VENDOR" == 'Oracle Java' ]] &&
           version_ge "$v" '8.0.511' && ! version_ge "$v" '8.0.513'; then
            ASSESS='REVIEW: Oracle Java 8u511/512; rule out performance build'
            ((REVIEW+=1))
            return
        fi
        ASSESS='NOT AFFECTED: standard Java 8 (check Oracle perf builds separately)'
        ((SAFE+=1))
        return
    fi
    if (( major == 11 )); then
        ASSESS='NOT AFFECTED: Java 11'
        ((SAFE+=1))
        return
    fi
    if (( major < 17 )); then
        ASSESS='NOT IN REPORTED AFFECTED RANGE: Java major below 17'
        ((SAFE+=1))
        return
    fi
    if (( major == 17 )) && ! version_ge "$v" '17.0.6'; then
        ASSESS='NOT AFFECTED: Java 17 earlier than 17.0.6'
        ((SAFE+=1))
        return
    fi

    # These are Oracle/upstream reference patch levels. Other vendors,
    # Linux distributors, and bundled JDKs may use different build numbers.
    case "$major" in
        17) threshold='17.0.21.1' ;;
        21) threshold='21.0.13.1' ;;
        25) threshold='25.0.5.1' ;;
        27) threshold='27.0.1.1' ;;
    esac

    if [[ "$CPU" == 'NO' ]]; then
        ASSESS='NOT EXPOSED on current CPU (recheck after host/VM migration)'
        ((SAFE+=1))
    elif [[ "$CPU" == 'UNKNOWN' ]]; then
        ASSESS='REVIEW: CPU capability could not be established'
        ((REVIEW+=1))
    elif [[ -z "$threshold" ]]; then
        ASSESS='REVIEW: Java release not covered by reference patch table'
        ((REVIEW+=1))
    elif version_ge "$v" "$threshold"; then
        ASSESS='REVIEW VENDOR FIX: version >= upstream fixed baseline; verify vendor/build'
        ((REVIEW+=1))
    else
        ASSESS='POTENTIAL RISK: affected version + required CPU features'
        ((RISK+=1))
    fi
}

report_java() {
    local context="$1" raw="$2" path="$3"
    parse_jvm "$raw"
    # Distinguish a genuine runtime that cannot be started from an unparsed
    # version; do not report it as safe.
    assess_jvm
    printf '%-15s %s\n' 'Location:' "$context"
    printf '%-15s %s\n' 'Java path:' "$path"
    printf '%-15s %s\n' 'Java version:' "${JVM_VERSION:-unknown}"
    printf '%-15s %s\n' 'Distribution:' "$JVM_VENDOR"
    printf '%-15s %s\n\n' 'Assessment:' "$ASSESS"
}

# Read the first CPU's exposed capabilities, which is sufficient for typical
# homogeneous hosts. Different CPU flags in heterogeneous nodes require review.
if [[ "$ARCH" == 'x86_64' ]] && [[ -r /proc/cpuinfo ]]; then
    CPU="$(awk -F: '/^flags[ \t]*:/ {
        f=" " $2 " ";
        if (index(f," avx512f ") && index(f," avx512bw ") &&
            (index(f," avx512vbmi ") || index(f," avx512_vbmi ")) &&
            index(f," bmi2 ")) print "YES";
        else print "NO";
        found=1; exit
    } END { if (!found) print "UNKNOWN" }' /proc/cpuinfo)"
elif [[ "$ARCH" != 'x86_64' ]]; then
    CPU='NO'
fi

section 'Java4Shell / CVE-2026-114938 read-only inventory'
say "Time (UTC): $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
say "Hostname: $(hostname -f 2>/dev/null || hostname)"
if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    say "OS: ${PRETTY_NAME:-${NAME:-Linux}}"
fi
say "Architecture: $ARCH"
say "Exposed CPU flags required (avx512f, avx512bw, avx512vbmi, bmi2): $CPU"
say 'Scope: host running Java + known installed Java paths + running Docker containers'
say 'No process argument lists, environment variables or application data are printed.'
if (( EUID != 0 )); then
    say 'REVIEW: audit is not running as root; some process and filesystem checks may be inaccessible. Rerun using sudo.'
    ((REVIEW+=1))
fi

# Build a local Docker PID index using PID-only docker top output; do not use
# docker top's default full-command view because it can disclose JVM secrets.
# Remote Docker contexts are deliberately excluded from host PID matching.
if (( CHECK_DOCKER )) && command -v docker >/dev/null 2>&1 &&
   docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; then
    docker_local=1
    [[ -z "${DOCKER_HOST:-}" || "${DOCKER_HOST}" == unix://* ]] || docker_local=0
    docker_endpoint="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)"
    [[ -z "$docker_endpoint" || "$docker_endpoint" == unix://* ]] || docker_local=0
    if (( docker_local )); then
        docker_pid_cids="$(docker ps --format '{{.ID}}' 2>/dev/null || true)"
        while IFS= read -r indexed_cid; do
            [[ -n "$indexed_cid" ]] || continue
            docker_pids="$(docker top "$indexed_cid" -eo pid 2>/dev/null || true)"
            while IFS= read -r indexed_pid; do
                [[ "$indexed_pid" =~ ^[0-9]+$ ]] || continue
                DOCKER_HOST_PID_OWNER["$indexed_pid"]="$indexed_cid"
            done <<< "$docker_pids"
        done <<< "$docker_pid_cids"
    fi
fi

section 'Host: running Java processes'
if command -v pgrep >/dev/null 2>&1; then
    mapfile -t PIDS < <(pgrep -x java 2>/dev/null || true)
else
    PIDS=()
    say 'WARNING: pgrep unavailable; running processes could not be enumerated.'
    ((REVIEW+=1))
fi
if ((${#PIDS[@]}==0)); then say 'No running processes named java detected.'; fi
for pid in "${PIDS[@]}"; do
    [[ -r "/proc/$pid/exe" ]] || { say "PID $pid: executable not accessible; review"; ((REVIEW+=1)); continue; }
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
    [[ -n "$exe" ]] || { say "PID $pid: executable path unknown; review"; ((REVIEW+=1)); continue; }
    owner="$(stat -c '%U' "/proc/$pid" 2>/dev/null || printf unknown)"
    if [[ -n "${DOCKER_HOST_PID_OWNER[$pid]:-}" ]]; then
        # Docker exposes container Java processes in the host process table,
        # but calling /proc/PID/exe from the host may fail (e.g. libjli.so).
        # Defer the check until inside Docker and verify the *same* Java path.
        cid="${DOCKER_HOST_PID_OWNER[$pid]}"
        DEFERRED_DOCKER_JAVA_PID["$pid"]="$cid"
        DEFERRED_DOCKER_JAVA_PATH["$pid"]="$exe"
        say "Host PID $pid (user $owner): Docker-owned JVM; checking with docker exec in $cid."
        continue
    fi
    raw="$(timeout 10s "/proc/$pid/exe" -version 2>&1 || true)"
    report_java "Host PID $pid (user $owner)" "$raw" "$exe"
    ((HOST_FOUND+=1))
    real="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
    [[ -z "$real" ]] || SEEN_HOST_JAVA["$real"]=1
done

section 'Host: other installed/default Java executables'
# Avoid scanning entire disks. Include standard Ubuntu and common /opt paths.
CANDIDATES=()
if command -v java >/dev/null 2>&1; then
    CANDIDATES+=("$(command -v java)")
fi
if [[ -n "${JAVA_HOME:-}" ]]; then CANDIDATES+=("$JAVA_HOME/bin/java"); fi
SCAN_TEMP="$(mktemp "${TMPDIR:-/tmp}/java4shell-discovery.XXXXXXXX")"
for root in /usr/lib/jvm /opt /usr/local/java /usr/local/lib/jvm /usr/local/jvm; do
    [[ -d "$root" ]] || continue
    # Read partial results when possible, but treat denied directories / I/O
    # errors as REVIEW rather than silently assuming the inventory is complete.
    if ! find "$root" -maxdepth 6 \( -type f -o -type l \) \
            -name java -path '*/bin/java' -print0 > "$SCAN_TEMP" 2>/dev/null; then
        say "REVIEW: could not completely inventory Java executables under $root (permission or filesystem error)."
        ((REVIEW+=1))
    fi
    while IFS= read -r -d '' candidate; do
        CANDIDATES+=("$candidate")
    done < "$SCAN_TEMP"
done
for candidate in "${CANDIDATES[@]}"; do
    [[ -x "$candidate" ]] || continue
    real="$(readlink -f "$candidate" 2>/dev/null || true)"
    [[ -n "$real" ]] || continue
    [[ -n "${SEEN_HOST_JAVA[$real]:-}" ]] && continue
    SEEN_HOST_JAVA["$real"]=1
    raw="$(timeout 10s "$candidate" -version 2>&1 || true)"
    report_java 'Host installed' "$raw" "$real"
    ((HOST_FOUND+=1))
done
if ((HOST_FOUND==0)); then say 'No host Java runtime detected in checked locations.'; fi

section 'Docker: running containers'
if (( ! CHECK_DOCKER )); then
    say 'Skipped by --no-docker (not included in assessment).'
elif ! command -v docker >/dev/null 2>&1; then
    if [[ -S /var/run/docker.sock || -S /run/docker.sock ]]; then
        say 'REVIEW: Docker socket exists but Docker CLI is unavailable; containers NOT scanned.'
        ((REVIEW+=1))
    else
        say 'Docker CLI/socket not detected; no Docker containers scanned.'
    fi
elif ! docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; then
    say 'WARNING: Docker daemon is inaccessible (permissions or service); containers NOT scanned.'
    ((REVIEW+=1))
else
    # Docker can point to a remote host. If so, do NOT use local CPU flags.
    DOCKER_CPU="$CPU"
    if [[ -n "${DOCKER_HOST:-}" && "${DOCKER_HOST}" != unix://* ]]; then
        DOCKER_CPU='UNKNOWN'
        say 'WARNING: DOCKER_HOST may be remote; container CPU classified UNKNOWN.'
    else
        endpoint="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)"
        if [[ -n "$endpoint" && "$endpoint" != unix://* ]]; then
            DOCKER_CPU='UNKNOWN'
            say 'WARNING: Docker context endpoint may be remote; container CPU classified UNKNOWN.'
        fi
    fi
    # Fetch lists before mapfile so a failed docker ps cannot be mistaken
    # for an empty (safe) container inventory.
    if ! running_ids="$(docker ps --format '{{.ID}}' 2>/dev/null)"; then
        say 'REVIEW: docker ps failed; running containers were NOT enumerated.'
        ((REVIEW+=1))
        running_ids=''
    fi
    if ! stopped_ids="$(docker ps -a --filter 'status=exited' --format '{{.ID}}' 2>/dev/null)"; then
        say 'REVIEW: docker ps -a failed; stopped containers could not be counted.'
        ((REVIEW+=1))
        stopped_ids=''
    fi
    CONTAINERS=()
    STOPPED=()
    [[ -z "$running_ids" ]] || mapfile -t CONTAINERS <<< "$running_ids"
    [[ -z "$stopped_ids" ]] || mapfile -t STOPPED <<< "$stopped_ids"
    if ((${#CONTAINERS[@]}==0)); then say 'No running Docker containers.'; fi
    for cid in "${CONTAINERS[@]}"; do
        ((CONTAINER_FOUND+=1))
        container_name="$(docker inspect -f '{{.Name}}' "$cid" 2>/dev/null || printf unknown)"
        container_image="$(docker inspect -f '{{.Config.Image}}' "$cid" 2>/dev/null || printf unknown)"
        printf '\nContainer: %s | ID: %s | image: %s\n' "$container_name" "$cid" "$container_image"
        # Try shell-based discovery across common JRE/JDK paths. This executes
        # only version checks; no access to container args or env data.
        if paths="$(docker exec "$cid" sh -c '
            for p in "$(command -v java 2>/dev/null)" \
                     /usr/bin/java /usr/local/bin/java \
                     /opt/java/openjdk/bin/java /opt/java/bin/java \
                     /usr/lib/jvm/*/bin/java /opt/*/bin/java \
                     /opt/*/*/bin/java /app/*/bin/java /app/*/*/bin/java \
                     /usr/local/openjdk-*/bin/java /usr/local/*/bin/java; do
                [ -n "$p" ] && [ -x "$p" ] && printf "%s\n" "$p"
            done
            if command -v find >/dev/null 2>&1; then
                for d in /usr/lib/jvm /opt /usr/local /app; do
                    [ -d "$d" ] || continue
                    find "$d" -maxdepth 6 \( -type f -o -type l \) \
                         -name java -path "*/bin/java" -print 2>/dev/null
                done
            fi
        ' 2>/dev/null)"; then
            shell_status=0
        else
            shell_status=$?
        fi
        if ((shell_status==0)); then
            if [[ -z "$paths" ]]; then
                say 'No Java detected via PATH / common paths (custom/bundled paths not ruled out).'
                ((NO_JAVA+=1))
                continue
            fi
            while IFS= read -r path; do
                [[ -n "$path" ]] || continue
                raw="$(timeout 15s docker exec "$cid" "$path" -version 2>&1 || true)"
                CPU_SAVE="$CPU"; CPU="$DOCKER_CPU"
                report_java "Docker $cid" "$raw" "$path"
                if [[ -n "${JVM_VERSION:-}" ]]; then
                    VERIFIED_DOCKER_JAVA_PATH["$cid|$path"]=1
                fi
                CPU="$CPU_SAVE"
            done < <(printf '%s\n' "$paths" | awk '!seen[$0]++')
        else
            # Distroless images often have no shell. Attempt common paths
            # directly; if none work, leave the container as UNVERIFIED.
            verified=0
            for path in java /usr/bin/java /opt/java/openjdk/bin/java /opt/java/bin/java /usr/local/openjdk-17/bin/java /usr/local/openjdk-21/bin/java /usr/local/openjdk-25/bin/java; do
                raw="$(timeout 15s docker exec "$cid" "$path" -version 2>&1 || true)"
                if [[ "$raw" == *'version "'* ]]; then
                    CPU_SAVE="$CPU"; CPU="$DOCKER_CPU"
                    report_java "Docker $cid" "$raw" "$path"
                    if [[ -n "${JVM_VERSION:-}" ]]; then
                        VERIFIED_DOCKER_JAVA_PATH["$cid|$path"]=1
                    fi
                    CPU="$CPU_SAVE"
                    verified=1
                    break
                fi
            done
            if (( ! verified )); then
                say 'REVIEW: container shell unavailable; JVM cannot be determined safely.'
                ((REVIEW+=1))
            fi
        fi
    done
    say "Stopped containers (not scanned or started): ${#STOPPED[@]}"
    say 'Unused local images are not examined; no container was started/stopped.'
fi

# A deferred host PID is covered only if its exact executable path was
# successfully version-probed inside the corresponding Docker container.
# This prevents incomplete Docker scans from incorrectly returning exit 0.
for deferred_pid in "${!DEFERRED_DOCKER_JAVA_PID[@]}"; do
    deferred_cid="${DEFERRED_DOCKER_JAVA_PID[$deferred_pid]}"
    deferred_path="${DEFERRED_DOCKER_JAVA_PATH[$deferred_pid]}"
    if [[ -z "${VERIFIED_DOCKER_JAVA_PATH[$deferred_cid|$deferred_path]:-}" ]]; then
        say "REVIEW: Docker-owned host PID $deferred_pid was not verified at its JVM path ($deferred_path) inside container $deferred_cid."
        ((REVIEW+=1))
    fi
done

section 'Summary'
say "Not affected / not currently CPU-exposed checks: $SAFE"
say "Potentially affected JVM checks: $RISK"
say "Checks requiring review: $REVIEW"
say "Running Docker containers inspected: $CONTAINER_FOUND"
say "Running Docker containers with no Java detected: $NO_JAVA"
if (( RISK > 0 )); then
    say 'OVERALL: POTENTIAL EXPOSURE - verify vendor patches and prioritize remediation.'
    exit 1
elif (( REVIEW > 0 )); then
    say 'OVERALL: INCOMPLETE / VENDOR VERIFICATION NEEDED - do not mark server clean.'
    exit 2
else
    say 'OVERALL: NO CURRENT CVE EXPOSURE IDENTIFIED in the assessed scope.'
    exit 0
fi
