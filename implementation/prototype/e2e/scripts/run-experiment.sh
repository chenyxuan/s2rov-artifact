#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
E2E_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
CONFIG_DIR="${E2E_DIR}/config"
AGENT="${E2E_DIR}/src/s2rov_agent.py"
NETWORK="s2rov-e2e"
VOLUME="s2rov-e2e-krill-data"
FRR_IMAGE="quay.io/frrouting/frr:10.6.1"
RECOVERY_TRIALS=${RECOVERY_TRIALS:-30}
FRR_RECOVERY_TRIALS=${FRR_RECOVERY_TRIALS:-30}
UPDATE_TRIALS=${UPDATE_TRIALS:-30}
OUTAGE_HOLD_SECONDS=${OUTAGE_HOLD_SECONDS:-15}
SCALE_TRIALS=${SCALE_TRIALS:-10}
SCALE_LEVELS=${SCALE_LEVELS:-"0 64 256 1024"}
CONTAINER_PREFIX="s2rov-e2e-"
KRILL="${CONTAINER_PREFIX}krill"
ROUTINATOR="${CONTAINER_PREFIX}routinator"
COLLECTOR="${CONTAINER_PREFIX}collector"
PEERS=(
    "172.31.0.11"
    "172.31.0.12"
    "172.31.0.13"
    "172.31.0.14"
    "172.31.0.15"
    "172.31.0.16"
    "172.31.0.17"
)
CONTAINERS=(
    "${KRILL}"
    "${ROUTINATOR}"
    "${COLLECTOR}"
    "${CONTAINER_PREFIX}holder"
    "${CONTAINER_PREFIX}customer"
    "${CONTAINER_PREFIX}delegate"
    "${CONTAINER_PREFIX}public-attacker"
    "${CONTAINER_PREFIX}aggregate-attacker"
    "${CONTAINER_PREFIX}private-origin"
    "${CONTAINER_PREFIX}unrelated"
)

log() {
    printf '[e2e] %s\n' "$*"
}

cleanup_containers() {
    for name in "${CONTAINERS[@]}"; do
        if docker container inspect "${name}" >/dev/null 2>&1; then
            docker rm -f "${name}" >/dev/null
        fi
    done
    if docker network inspect "${NETWORK}" >/dev/null 2>&1; then
        docker network rm "${NETWORK}" >/dev/null
    fi
}

clean_lab_state() {
    cleanup_containers
    if docker volume inspect "${VOLUME}" >/dev/null 2>&1; then
        docker volume rm "${VOLUME}" >/dev/null
    fi
}

ensure_images() {
    bash "${SCRIPT_DIR}/build-images.sh"
    if ! docker image inspect "${FRR_IMAGE}" >/dev/null 2>&1; then
        docker pull "${FRR_IMAGE}"
    fi
}

wait_krill() {
    for _ in $(seq 1 120); do
        if docker exec "${KRILL}" krillc health >/dev/null 2>&1; then
            return
        fi
        sleep 1
    done
    docker logs "${KRILL}" >&2
    echo "Krill did not become healthy" >&2
    exit 1
}

wait_routinator() {
    for _ in $(seq 1 120); do
        if docker exec "${ROUTINATOR}" \
            curl -fsS http://127.0.0.1:3333/status >/dev/null 2>&1; then
            return
        fi
        sleep 1
    done
    docker logs "${ROUTINATOR}" >&2
    echo "Routinator did not become healthy" >&2
    exit 1
}

wait_routinator_pattern() {
    pattern=$1
    for _ in $(seq 1 90); do
        document=$(docker exec "${ROUTINATOR}" \
            curl -fsS http://127.0.0.1:3333/json 2>/dev/null || true)
        if grep -q "${pattern}" <<< "${document}"; then
            return
        fi
        sleep 1
    done
    docker exec "${ROUTINATOR}" curl -fsS http://127.0.0.1:3333/json >&2
    echo "Routinator payload did not match: ${pattern}" >&2
    exit 1
}

wait_routinator_absent() {
    pattern=$1
    for _ in $(seq 1 90); do
        document=$(docker exec "${ROUTINATOR}" \
            curl -fsS http://127.0.0.1:3333/json 2>/dev/null || true)
        if ! grep -q "${pattern}" <<< "${document}"; then
            return
        fi
        sleep 1
    done
    echo "Routinator payload still contains: ${pattern}" >&2
    exit 1
}

wait_bgp() {
    for _ in $(seq 1 120); do
        summary=$(docker exec "${COLLECTOR}" \
            vtysh -c "show bgp ipv4 unicast summary json" 2>/dev/null || true)
        count=$(printf '%s' "${summary}" | python3 -c '
import json, sys
try:
    value = json.load(sys.stdin)
except Exception:
    print(0)
    raise SystemExit
def walk(item):
    if isinstance(item, dict):
        total = int(item.get("state") == "Established")
        total += int(item.get("peerState") == "Established")
        return total + sum(walk(v) for v in item.values())
    if isinstance(item, list):
        return sum(walk(v) for v in item)
    return 0
print(walk(value))
')
        if [ "${count}" -ge 7 ]; then
            return
        fi
        sleep 1
    done
    docker exec "${COLLECTOR}" vtysh -c "show bgp ipv4 unicast summary" >&2
    echo "not all BGP sessions became Established" >&2
    exit 1
}

wait_rtr_prefix() {
    for _ in $(seq 1 90); do
        if docker exec "${COLLECTOR}" \
            vtysh -c "show rpki prefix-table json" 2>/dev/null \
            | grep -q '"prefix":"10.0.0.0"'; then
            return
        fi
        sleep 1
    done
    docker exec "${COLLECTOR}" vtysh -c "show rpki cache-connection" >&2 || true
    docker logs "${COLLECTOR}" >&2
    echo "FRR did not receive the baseline VRP over RTR" >&2
    exit 1
}

wait_all_routes() {
    local route_output=$1
    for _ in $(seq 1 120); do
        docker exec "${COLLECTOR}" \
            vtysh -c "show bgp ipv4 unicast json" > "${route_output}"
        if python3 "${AGENT}" check-observed \
            --routes "${route_output}" \
            --cases "${CONFIG_DIR}/cases.json" \
            --fail-on-missing >/dev/null 2>&1; then
            return
        fi
        sleep 1
    done
    docker exec "${COLLECTOR}" \
        vtysh -c "show bgp ipv4 unicast" >&2 || true
    echo "not all controlled routes became observable" >&2
    exit 1
}

wait_customer_preference() {
    expected=$1
    for _ in $(seq 1 900); do
        if docker exec "${COLLECTOR}" \
            vtysh -c "show bgp ipv4 unicast 10.0.1.0/24 json" 2>/dev/null \
            | jq -e --argjson expected "${expected}" \
                '.paths[]? | select(.aspath.string == "8075" and .locPrf == $expected)' \
                >/dev/null; then
            return
        fi
        sleep 0.1
    done
    docker exec "${COLLECTOR}" \
        vtysh -c "show bgp ipv4 unicast 10.0.1.0/24" >&2 || true
    echo "customer route did not reach local preference ${expected}" >&2
    exit 1
}

run_frr() {
    name=$1
    address=$2
    config=$3
    docker run -d \
        --name "${CONTAINER_PREFIX}${name}" \
        --hostname "${name}" \
        --network "${NETWORK}" \
        --ip "${address}" \
        --cap-add NET_ADMIN \
        --cap-add NET_RAW \
        --cap-add SYS_ADMIN \
        --sysctl net.ipv4.ip_forward=1 \
        -v "${CONFIG_DIR}/frr/daemons:/etc/frr/daemons:ro" \
        -v "${CONFIG_DIR}/frr/vtysh.conf:/etc/frr/vtysh.conf:ro" \
        -v "${CONFIG_DIR}/frr/${config}:/etc/frr/frr.conf:ro" \
        "${FRR_IMAGE}" >/dev/null
}

start_lab() {
    token=$1
    docker network create --subnet 172.31.0.0/24 "${NETWORK}" >/dev/null
    docker volume create "${VOLUME}" >/dev/null

    docker run -d \
        --name "${KRILL}" \
        --hostname krill \
        --network "${NETWORK}" \
        --ip 172.31.0.2 \
        -e "KRILL_CLI_TOKEN=${token}" \
        -v "${VOLUME}:<home>/data" \
        -v "${CONFIG_DIR}/krill/nginx.conf:/etc/nginx/sites-enabled/testbed:ro" \
        -v "${CONFIG_DIR}/krill/krill.conf.template:/opt/s2rov/krill.conf.template:ro" \
        -v "${SCRIPT_DIR}/krill-entrypoint.sh:/opt/s2rov/krill-entrypoint.sh:ro" \
        stripe-testbed:latest \
        bash /opt/s2rov/krill-entrypoint.sh >/dev/null
    wait_krill

    docker run -d \
        --name "${ROUTINATOR}" \
        --hostname routinator \
        --network "${NETWORK}" \
        --ip 172.31.0.3 \
        -v "${SCRIPT_DIR}/routinator-entrypoint.sh:/opt/s2rov/routinator-entrypoint.sh:ro" \
        stripe-routinator:latest \
        bash /opt/s2rov/routinator-entrypoint.sh >/dev/null
    wait_routinator

    run_frr collector 172.31.0.10 collector.conf
    run_frr holder 172.31.0.11 holder.conf
    run_frr customer 172.31.0.12 customer.conf
    run_frr delegate 172.31.0.13 delegate.conf
    run_frr public-attacker 172.31.0.14 public-attacker.conf
    run_frr aggregate-attacker 172.31.0.15 aggregate-attacker.conf
    run_frr private-origin 172.31.0.16 private-origin.conf
    run_frr unrelated 172.31.0.17 unrelated.conf
    wait_bgp
}

capture_frr() {
    destination=$1
    mkdir -p "${destination}/received" "${destination}/details"
    docker exec "${COLLECTOR}" \
        vtysh -c "show bgp ipv4 unicast summary json" \
        > "${destination}/bgp-summary.json"
    docker exec "${COLLECTOR}" \
        vtysh -c "show bgp ipv4 unicast json" \
        > "${destination}/bgp-rib.json"
    docker exec "${COLLECTOR}" \
        vtysh -c "show rpki cache-connection json" \
        > "${destination}/rpki-cache.json" || true
    docker exec "${COLLECTOR}" \
        vtysh -c "show rpki prefix-table json" \
        > "${destination}/rpki-prefix-table.json" || true
    for peer in "${PEERS[@]}"; do
        docker exec "${COLLECTOR}" \
            vtysh -c "show bgp ipv4 unicast neighbors ${peer} received-routes json" \
            > "${destination}/received/${peer}.json" || true
    done
    for prefix in \
        "10.0.0.0/16" \
        "10.0.1.0/24" \
        "10.0.2.0/24" \
        "10.0.3.0/24" \
        "10.0.4.0/24" \
        "192.0.2.0/24"; do
        filename=${prefix//\//_}
        docker exec "${COLLECTOR}" \
            vtysh -c "show bgp ipv4 unicast ${prefix} json" \
            > "${destination}/details/${filename}.json" || true
    done
}

capture_routinator() {
    destination=$1
    docker exec "${ROUTINATOR}" \
        curl -fsS http://127.0.0.1:3333/json > "${destination}/routinator-vrps.json"
    docker exec "${ROUTINATOR}" \
        curl -fsS http://127.0.0.1:3333/api/v1/status \
        > "${destination}/routinator-status.json"
}

apply_vty_file() {
    source=$1
    docker exec -i "${COLLECTOR}" vtysh < "${source}" >/dev/null
    docker exec "${COLLECTOR}" \
        vtysh -c "clear bgp ipv4 unicast * soft in" >/dev/null
}

refresh_da_policy() {
    vrps=$1
    destination=$2
    expected_state=$3
    expected_preference=$4
    mkdir -p "${destination}"

    python3 "${AGENT}" evaluate \
        --vrps "${vrps}" \
        --cases "${CONFIG_DIR}/cases.json" \
        --output "${destination}/decisions.json" \
        --policy-output "${destination}/frr-policy.vty"

    actual_state=$(jq -r \
        '.[] | select(.name == "listed_customer") | .state' \
        "${destination}/decisions.json")
    if [ "${actual_state}" != "${expected_state}" ]; then
        echo "customer state ${actual_state}, expected ${expected_state}" >&2
        exit 1
    fi
    if ! jq -e \
        'all(.[]; .name == "listed_customer" or .pass == true)' \
        "${destination}/decisions.json" >/dev/null; then
        jq '.[] | select(.name != "listed_customer" and .pass != true)' \
            "${destination}/decisions.json" >&2
        echo "an unchanged route left its expected semantic state" >&2
        exit 1
    fi

    apply_vty_file "${destination}/frr-policy.vty"
    wait_customer_preference "${expected_preference}"
    docker exec "${COLLECTOR}" \
        vtysh -c "show bgp ipv4 unicast json" \
        > "${destination}/bgp-rib.json"
    python3 "${AGENT}" check-enforced \
        --routes "${destination}/bgp-rib.json" \
        --decisions "${destination}/decisions.json" \
        --output "${destination}/enforcement.json" \
        --fail-on-mismatch
}

elapsed_ms() {
    start=$1
    end=$2
    python3 -c "print(round((${end} - ${start}) / 1000000, 3))"
}

background_prefix() {
    local index=$1
    local offset=$((index * 64))
    local second=$((18 + offset / 65536))
    local third=$(((offset / 256) % 256))
    local fourth=$((offset % 256))
    printf '198.%s.%s.%s/26' "${second}" "${third}" "${fourth}"
}

validated_background_count() {
    docker exec "${ROUTINATOR}" \
        curl -fsS http://127.0.0.1:3333/json 2>/dev/null \
        | jq '[.roas[]? | select(.prefix | test("^198\\.(18|19)\\."))] | length'
}

wait_background_count() {
    local expected=$1
    for _ in $(seq 1 480); do
        local actual
        actual=$(validated_background_count || printf '%s' -1)
        if [ "${actual}" = "${expected}" ]; then
            return
        fi
        sleep 0.25
    done
    echo "validated background count did not reach ${expected}" >&2
    exit 1
}

update_background_range() {
    local operation=$1
    local first=$2
    local last=$3
    if [ "${last}" -lt "${first}" ]; then
        return
    fi
    local args=()
    local index
    for index in $(seq "${first}" "${last}"); do
        args+=("--${operation}" "$(background_prefix "${index}") => 65010")
    done
    docker exec "${KRILL}" krillc roas update -c testbed "${args[@]}" >/dev/null
}

remove_existing_background() {
    local prefixes=()
    while IFS= read -r prefix; do
        [ -n "${prefix}" ] && prefixes+=("${prefix}")
    done < <(
        docker exec "${KRILL}" krillc roas list -c testbed 2>/dev/null \
            | awk '$1 ~ /^198\.(18|19)\./ {print $1}' \
            | sed -E 's#(/[0-9]+)-[0-9]+$#\1#'
    )
    if [ "${#prefixes[@]}" -eq 0 ]; then
        return
    fi
    local args=()
    local prefix
    for prefix in "${prefixes[@]}"; do
        args+=(--remove "${prefix} => 65010")
    done
    docker exec "${KRILL}" krillc roas update -c testbed "${args[@]}" >/dev/null
    wait_background_count 0
}

require_live_scale_lab() {
    local name
    for name in "${KRILL}" "${ROUTINATOR}" "${COLLECTOR}"; do
        if [ "$(docker inspect -f '{{.State.Running}}' "${name}" 2>/dev/null || true)" != "true" ]; then
            echo "${name} is not running; run 'make experiment' before 'make scale'" >&2
            exit 1
        fi
    done
    wait_routinator_pattern '"inclusivity": "inclusive"'
    wait_routinator_pattern '"prefix": "10.0.1.0/24"'
    wait_bgp
}

cleanup_scale_lab() {
    set +e
    if [ "$(docker inspect -f '{{.State.Running}}' "${KRILL}" 2>/dev/null)" = "true" ]; then
        roa_list=$(docker exec "${KRILL}" krillc roas list -c testbed 2>/dev/null || true)
        if ! grep -q '^10\.0\.1\.0/24' <<< "${roa_list}"; then
            docker exec "${KRILL}" krillc roas update -c testbed \
                --add "10.0.1.0/24 => 8075" >/dev/null 2>&1
        fi
        remove_existing_background
    fi
}

run_scale_experiment() {
    require_live_scale_lab
    remove_existing_background
    trap cleanup_scale_lab EXIT

    local run_id
    run_id=$(date -u +%Y%m%dT%H%M%SZ)
    local output="${E2E_DIR}/outputs/scale-${run_id}"
    mkdir -p "${output}"
    ln -sfn "scale-${run_id}" "${E2E_DIR}/outputs/latest-scale"
    local samples="${output}/policy-scale-samples.csv"
    local payloads="${output}/policy-scale-payloads.csv"
    printf 'background_stripes,total_validated_entries,trial,transition,milliseconds\n' \
        > "${samples}"
    printf 'background_stripes,total_validated_entries,json_bytes,setup_ms\n' \
        > "${payloads}"

    {
        docker exec "${KRILL}" krill --version
        docker exec "${ROUTINATOR}" routinator --version
        docker exec "${COLLECTOR}" /usr/lib/frr/bgpd --version | head -1
        docker version --format 'Docker {{.Server.Version}}'
    } > "${output}/environment.txt"
    (
        cd "${E2E_DIR}"
        find \
            scripts/run-experiment.sh \
            src/s2rov_agent.py \
            src/summarize.py \
            config/cases.json \
            config/frr \
            config/krill/krill.conf.template \
            -type f -print0 \
            | LC_ALL=C sort -z \
            | xargs -0 sha256sum
    ) > "${output}/source.sha256"
    git -C "${E2E_DIR}" status --short -- . \
        > "${output}/git-status.txt"

    local current=0
    local level
    for level in ${SCALE_LEVELS}; do
        if [ "${level}" -lt "${current}" ]; then
            echo "SCALE_LEVELS must be nondecreasing" >&2
            exit 1
        fi
        local setup_start_ns setup_end_ns setup_ms
        setup_start_ns=$(date +%s%N)
        if [ "${level}" -gt "${current}" ]; then
            update_background_range add "${current}" "$((level - 1))"
            wait_background_count "${level}"
        fi
        setup_end_ns=$(date +%s%N)
        setup_ms=$(elapsed_ms "${setup_start_ns}" "${setup_end_ns}")

        local level_dir="${output}/background-${level}"
        mkdir -p "${level_dir}"
        docker exec "${ROUTINATOR}" curl -fsS http://127.0.0.1:3333/json \
            > "${level_dir}/validated-policy.json"
        local total_entries json_bytes
        total_entries=$(jq '.roas | length' "${level_dir}/validated-policy.json")
        json_bytes=$(wc -c < "${level_dir}/validated-policy.json")
        printf '%s,%s,%s,%s\n' \
            "${level}" "${total_entries}" "${json_bytes}" "${setup_ms}" \
            >> "${payloads}"

        log "testing ${SCALE_TRIALS} update cycles with ${level} additional closed Stripes"
        local trial
        for trial in $(seq 1 "${SCALE_TRIALS}"); do
            local trial_dir
            trial_dir=$(printf '%s/trial-%02d' "${level_dir}" "${trial}")
            mkdir -p "${trial_dir}/remove" "${trial_dir}/restore"

            local start_ns end_ns transition_ms
            start_ns=$(date +%s%N)
            docker exec "${KRILL}" krillc roas update -c testbed \
                --remove "10.0.1.0/24 => 8075" >/dev/null
            wait_routinator_absent '"prefix": "10.0.1.0/24"'
            docker exec "${ROUTINATOR}" curl -fsS http://127.0.0.1:3333/json \
                > "${trial_dir}/remove/routinator-vrps.json"
            refresh_da_policy \
                "${trial_dir}/remove/routinator-vrps.json" \
                "${trial_dir}/remove" Delegated 200
            end_ns=$(date +%s%N)
            transition_ms=$(elapsed_ms "${start_ns}" "${end_ns}")
            printf '%s,%s,%s,remove,%s\n' \
                "${level}" "${total_entries}" "${trial}" "${transition_ms}" \
                >> "${samples}"

            start_ns=$(date +%s%N)
            docker exec "${KRILL}" krillc roas update -c testbed \
                --add "10.0.1.0/24 => 8075" >/dev/null
            wait_routinator_pattern '"prefix": "10.0.1.0/24"'
            docker exec "${ROUTINATOR}" curl -fsS http://127.0.0.1:3333/json \
                > "${trial_dir}/restore/routinator-vrps.json"
            refresh_da_policy \
                "${trial_dir}/restore/routinator-vrps.json" \
                "${trial_dir}/restore" Explicit 300
            end_ns=$(date +%s%N)
            transition_ms=$(elapsed_ms "${start_ns}" "${end_ns}")
            printf '%s,%s,%s,restore,%s\n' \
                "${level}" "${total_entries}" "${trial}" "${transition_ms}" \
                >> "${samples}"
        done
        current=${level}
    done

    remove_existing_background
    python3 "${E2E_DIR}/src/summarize_scale.py" \
        --run-dir "${output}" \
        --output "${output}/summary.json"
    trap - EXIT
    log "scale experiment complete: ${output}"
}

run_experiment() {
    ensure_images
    clean_lab_state

    run_id=$(date -u +%Y%m%dT%H%M%SZ)
    output="${E2E_DIR}/outputs/run-${run_id}"
    mkdir -p "${output}/baseline" "${output}/da" "${output}/updates"
    ln -sfn "run-${run_id}" "${E2E_DIR}/outputs/latest"
    metrics="${output}/timings.csv"
    printf 'metric,milliseconds\n' > "${metrics}"
    recovery_samples="${output}/recovery-samples.csv"
    frr_recovery_samples="${output}/frr-recovery-samples.csv"
    update_samples="${output}/override-update-samples.csv"
    printf 'trial,milliseconds\n' > "${recovery_samples}"
    printf 'trial,milliseconds\n' > "${frr_recovery_samples}"
    printf 'trial,remove_ms,restore_ms\n' > "${update_samples}"

    token=$(openssl rand -hex 24)
    log "starting isolated Krill, Routinator, and eight-node FRR topology"
    start_lab "${token}"
    {
        docker exec "${KRILL}" krill --version
        docker exec "${ROUTINATOR}" routinator --version
        docker exec "${COLLECTOR}" /usr/lib/frr/bgpd --version | head -1
        docker version --format 'Docker {{.Server.Version}}'
    } > "${output}/environment.txt"

    log "publishing the conventional holder ROA with maxLength 24"
    start_ns=$(date +%s%N)
    docker exec "${KRILL}" krillc roas update -c testbed \
        --add "10.0.0.0/16-24 => 64501" >/dev/null
    wait_routinator_pattern '"prefix": "10.0.0.0/16"'
    rp_ns=$(date +%s%N)
    wait_rtr_prefix
    frr_ns=$(date +%s%N)
    printf 'baseline_krill_to_routinator,%s\n' \
        "$(elapsed_ms "${start_ns}" "${rp_ns}")" >> "${metrics}"
    printf 'baseline_krill_to_frr,%s\n' \
        "$(elapsed_ms "${start_ns}" "${frr_ns}")" >> "${metrics}"
    docker exec "${COLLECTOR}" \
        vtysh -c "clear bgp ipv4 unicast * soft in" >/dev/null
    sleep 3

    capture_routinator "${output}/baseline"
    capture_frr "${output}/baseline"
    python3 "${AGENT}" evaluate \
        --vrps "${output}/baseline/routinator-vrps.json" \
        --cases "${CONFIG_DIR}/cases.json" \
        --mode baseline \
        --output "${output}/baseline/decisions.json" \
        --fail-on-mismatch
    python3 "${AGENT}" check-enforced \
        --routes "${output}/baseline/bgp-rib.json" \
        --decisions "${output}/baseline/decisions.json" \
        --output "${output}/baseline/enforcement.json" \
        --fail-on-mismatch

    log "switching to the experimental open Stripe plus a closed customer Stripe"
    da_start_ns=$(date +%s%N)
    docker exec "${KRILL}" krillc roas update -c testbed \
        --remove "10.0.0.0/16-24 => 64501" \
        --add "10.0.0.0/16, 16-24 => 64501 inclusive" \
        --add "10.0.1.0/24 => 8075" >/dev/null
    wait_routinator_pattern '"inclusivity": "inclusive"'
    wait_routinator_pattern '"prefix": "10.0.1.0/24"'
    da_rp_ns=$(date +%s%N)
    printf 'da_krill_to_routinator,%s\n' \
        "$(elapsed_ms "${da_start_ns}" "${da_rp_ns}")" >> "${metrics}"

    capture_routinator "${output}/da"
    docker exec "${COLLECTOR}" \
        vtysh -c "show rpki cache-connection json" \
        > "${output}/da/standard-rtr-extension-compatibility.json" || true

    apply_vty_file "${CONFIG_DIR}/frr/accept-all.vty"
    sleep 3
    docker exec "${COLLECTOR}" \
        vtysh -c "show bgp ipv4 unicast json" \
        > "${output}/da/observed-routes.json"
    python3 "${AGENT}" check-observed \
        --routes "${output}/da/observed-routes.json" \
        --cases "${CONFIG_DIR}/cases.json" \
        --output "${output}/da/observed-check.json" \
        --fail-on-missing

    policy_start_ns=$(date +%s%N)
    python3 "${AGENT}" evaluate \
        --vrps "${output}/da/routinator-vrps.json" \
        --cases "${CONFIG_DIR}/cases.json" \
        --output "${output}/da/decisions.json" \
        --policy-output "${output}/da/frr-policy.vty" \
        --fail-on-mismatch
    apply_vty_file "${output}/da/frr-policy.vty"
    wait_customer_preference 300
    policy_end_ns=$(date +%s%N)
    printf 'da_evaluate_and_frr_enforce,%s\n' \
        "$(elapsed_ms "${policy_start_ns}" "${policy_end_ns}")" >> "${metrics}"

    capture_frr "${output}/da/final"
    python3 "${AGENT}" check-enforced \
        --routes "${output}/da/final/bgp-rib.json" \
        --decisions "${output}/da/decisions.json" \
        --output "${output}/da/enforcement.json" \
        --fail-on-mismatch

    log "holding installed S2-ROV policy during a ${OUTAGE_HOLD_SECONDS}s relying-party outage"
    mkdir -p "${output}/failures/routinator-outage"
    docker exec "${COLLECTOR}" \
        vtysh -c "show bgp ipv4 unicast json" \
        > "${output}/failures/routinator-outage/before.json"
    docker stop "${ROUTINATOR}" >/dev/null
    sleep "${OUTAGE_HOLD_SECONDS}"
    wait_customer_preference 300
    docker exec "${COLLECTOR}" \
        vtysh -c "show bgp ipv4 unicast json" \
        > "${output}/failures/routinator-outage/during.json"
    python3 "${AGENT}" check-enforced \
        --routes "${output}/failures/routinator-outage/during.json" \
        --decisions "${output}/da/decisions.json" \
        --output "${output}/failures/routinator-outage/enforcement.json" \
        --fail-on-mismatch
    jq -n \
        --argjson hold_seconds "${OUTAGE_HOLD_SECONDS}" \
        '{hold_seconds: $hold_seconds, policy_retained: true}' \
        > "${output}/failures/routinator-outage/result.json"
    docker start "${ROUTINATOR}" >/dev/null
    wait_routinator
    wait_routinator_pattern '"inclusivity": "inclusive"'
    wait_routinator_pattern '"prefix": "10.0.1.0/24"'
    capture_routinator "${output}/failures/routinator-outage"
    refresh_da_policy \
        "${output}/failures/routinator-outage/routinator-vrps.json" \
        "${output}/failures/routinator-outage/recovered" \
        Explicit 300

    log "restarting Routinator ${RECOVERY_TRIALS} times and verifying S2-ROV policy recovery in FRR"
    for trial in $(seq 1 "${RECOVERY_TRIALS}"); do
        trial_dir=$(printf '%s/failures/routinator-restart/trial-%02d' \
            "${output}" "${trial}")
        mkdir -p "${trial_dir}"
        restart_ns=$(date +%s%N)
        docker restart "${ROUTINATOR}" >/dev/null
        wait_routinator
        wait_routinator_pattern '"inclusivity": "inclusive"'
        wait_routinator_pattern '"prefix": "10.0.1.0/24"'
        docker exec "${ROUTINATOR}" \
            curl -fsS http://127.0.0.1:3333/json \
            > "${trial_dir}/routinator-vrps.json"
        refresh_da_policy \
            "${trial_dir}/routinator-vrps.json" \
            "${trial_dir}/recovered" \
            Explicit 300
        recovered_ns=$(date +%s%N)
        printf '%s,%s\n' "${trial}" \
            "$(elapsed_ms "${restart_ns}" "${recovered_ns}")" \
            >> "${recovery_samples}"
    done

    log "testing end-to-end longest-prefix override for ${UPDATE_TRIALS} remove/restore cycles"
    for trial in $(seq 1 "${UPDATE_TRIALS}"); do
        trial_dir=$(printf '%s/updates/trial-%02d' "${output}" "${trial}")
        mkdir -p "${trial_dir}/remove" "${trial_dir}/restore"
        remove_start_ns=$(date +%s%N)
        docker exec "${KRILL}" krillc roas update -c testbed \
            --remove "10.0.1.0/24 => 8075" >/dev/null
        wait_routinator_absent '"prefix": "10.0.1.0/24"'
        docker exec "${ROUTINATOR}" \
            curl -fsS http://127.0.0.1:3333/json \
            > "${trial_dir}/remove/routinator-vrps.json"
        refresh_da_policy \
            "${trial_dir}/remove/routinator-vrps.json" \
            "${trial_dir}/remove" \
            Delegated 200
        remove_end_ns=$(date +%s%N)
        remove_ms=$(elapsed_ms "${remove_start_ns}" "${remove_end_ns}")

        add_start_ns=$(date +%s%N)
        docker exec "${KRILL}" krillc roas update -c testbed \
            --add "10.0.1.0/24 => 8075" >/dev/null
        wait_routinator_pattern '"prefix": "10.0.1.0/24"'
        docker exec "${ROUTINATOR}" \
            curl -fsS http://127.0.0.1:3333/json \
            > "${trial_dir}/restore/routinator-vrps.json"
        refresh_da_policy \
            "${trial_dir}/restore/routinator-vrps.json" \
            "${trial_dir}/restore" \
            Explicit 300
        add_end_ns=$(date +%s%N)
        restore_ms=$(elapsed_ms "${add_start_ns}" "${add_end_ns}")
        printf '%s,%s,%s\n' \
            "${trial}" "${remove_ms}" "${restore_ms}" >> "${update_samples}"
    done

    first_trial_dir=$(printf '%s/updates/trial-%02d' "${output}" 1)
    last_trial_dir=$(printf '%s/updates/trial-%02d' \
        "${output}" "${UPDATE_TRIALS}")
    cp "${first_trial_dir}/remove/decisions.json" \
        "${output}/updates/without-closed-stripe.json"
    cp "${last_trial_dir}/restore/routinator-vrps.json" \
        "${output}/updates/restored-vrps.json"
    cp "${last_trial_dir}/restore/decisions.json" \
        "${output}/updates/restored-decisions.json"

    log "restarting FRR ${FRR_RECOVERY_TRIALS} times and restoring live S2-ROV enforcement"
    for trial in $(seq 1 "${FRR_RECOVERY_TRIALS}"); do
        trial_dir=$(printf '%s/failures/frr-restart/trial-%02d' \
            "${output}" "${trial}")
        mkdir -p "${trial_dir}"
        restart_ns=$(date +%s%N)
        docker restart "${COLLECTOR}" >/dev/null
        wait_bgp
        apply_vty_file "${CONFIG_DIR}/frr/accept-all.vty"
        wait_all_routes "${trial_dir}/observed-routes.json"
        refresh_da_policy \
            "${output}/updates/restored-vrps.json" \
            "${trial_dir}/recovered" \
            Explicit 300
        recovered_ns=$(date +%s%N)
        printf '%s,%s\n' "${trial}" \
            "$(elapsed_ms "${restart_ns}" "${recovered_ns}")" \
            >> "${frr_recovery_samples}"
    done

    python3 "${E2E_DIR}/src/summarize.py" \
        --run-dir "${output}" \
        --output "${output}/summary.json"
    log "experiment complete: ${output}"
}

case "${1:-experiment}" in
    experiment)
        run_experiment
        ;;
    scale)
        run_scale_experiment
        ;;
    down)
        cleanup_containers
        ;;
    clean)
        clean_lab_state
        ;;
    status)
        docker ps -a --filter "name=${CONTAINER_PREFIX}" \
            --format '{{.Names}}\t{{.Status}}\t{{.Image}}'
        ;;
    *)
        echo "usage: $0 [experiment|scale|status|down|clean]" >&2
        exit 2
        ;;
esac
