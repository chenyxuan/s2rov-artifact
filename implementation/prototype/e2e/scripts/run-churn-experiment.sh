#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
E2E_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
CONFIG_DIR="${E2E_DIR}/config"
CHURN_CONFIG="${CONFIG_DIR}/churn"
AGENT="${E2E_DIR}/src/s2rov_agent.py"
SUMMARIZER="${E2E_DIR}/src/summarize_churn.py"

NETWORK="s2rov-churn"
VOLUME="s2rov-churn-krill-data"
BGP_AF=${BGP_AF:-ipv4}
PREFIX="10.0.10.0/24"
PREFIX_ADDRESS="10.0.10.0"
OPEN_PREFIX="10.0.0.0/16"
OPEN_POLICY="10.0.0.0/16, 16-24 => 64501 inclusive"
FRR_IMAGE="quay.io/frrouting/frr:10.6.1"
CHURN_TRIALS=${CHURN_TRIALS:-30}
POLL_SECONDS=${CHURN_POLL_SECONDS:-0.05}
CONTAINER_PREFIX="s2rov-churn-"
KRILL="${CONTAINER_PREFIX}krill"
ROUTINATOR="${CONTAINER_PREFIX}routinator"
COLLECTOR="${CONTAINER_PREFIX}collector"
ORIGIN_A_CONTAINER="${CONTAINER_PREFIX}origin-a"
ORIGIN_B_CONTAINER="${CONTAINER_PREFIX}origin-b"
CONTAINERS=(
    "${KRILL}"
    "${ROUTINATOR}"
    "${COLLECTOR}"
    "${ORIGIN_A_CONTAINER}"
    "${ORIGIN_B_CONTAINER}"
)

OUTPUT=""
EVENTS=""
TRIAL_CSV=""
CURRENT_ORIGIN=8075
POLICY_MODE="none"
POLICY_ORIGIN=0
DA_POLICY_DIGEST=""
SETUP_SIGNED_TRANSACTIONS=0
SETUP_ENTRY_CHANGES=0
GLOBAL_ORDER=0
EXACT_TRIAL=0
DA_TRIAL=0
MONOTONIC_CLOCK_PID=""
MONOTONIC_CLOCK_IN=""
MONOTONIC_CLOCK_OUT=""

log() {
    printf '[churn] %s\n' "$*"
}

elapsed_ms() {
    local start=$1
    local end=$2
    awk -v start="${start}" -v end="${end}" \
        'BEGIN { printf "%.3f", (end - start) / 1000000 }'
}

start_monotonic_clock() {
    if [ -n "${MONOTONIC_CLOCK_PID}" ]; then
        return 0
    fi
    coproc S2ROV_MONOTONIC_CLOCK {
        python3 -u -c 'import sys, time
for _ in sys.stdin:
    print(time.monotonic_ns(), flush=True)'
    }
    MONOTONIC_CLOCK_OUT=${S2ROV_MONOTONIC_CLOCK[0]}
    MONOTONIC_CLOCK_IN=${S2ROV_MONOTONIC_CLOCK[1]}
    MONOTONIC_CLOCK_PID=${S2ROV_MONOTONIC_CLOCK_PID}
}

monotonic_ns() {
    local value
    if [ -z "${MONOTONIC_CLOCK_PID}" ]; then
        echo "monotonic clock is not running" >&2
        return 1
    fi
    printf '\n' >&"${MONOTONIC_CLOCK_IN}"
    IFS= read -r value <&"${MONOTONIC_CLOCK_OUT}"
    printf '%s' "${value}"
}

stop_monotonic_clock() {
    if [ -n "${MONOTONIC_CLOCK_IN}" ]; then
        exec {MONOTONIC_CLOCK_IN}>&- || true
    fi
    if [ -n "${MONOTONIC_CLOCK_OUT}" ]; then
        exec {MONOTONIC_CLOCK_OUT}<&- || true
    fi
    if [ -n "${MONOTONIC_CLOCK_PID}" ]; then
        wait "${MONOTONIC_CLOCK_PID}" 2>/dev/null || true
    fi
    MONOTONIC_CLOCK_PID=""
    MONOTONIC_CLOCK_IN=""
    MONOTONIC_CLOCK_OUT=""
}

event() {
    local lane=$1
    local trial=$2
    local name=$3
    local monotonic_timestamp_ns=$4
    jq -cn \
        --arg lane "${lane}" \
        --argjson trial "${trial}" \
        --arg event "${name}" \
        --argjson monotonic_ns "${monotonic_timestamp_ns}" \
        --arg utc "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" \
        '{lane:$lane,trial:$trial,event:$event,monotonic_ns:$monotonic_ns,utc:$utc}' \
        >> "${EVENTS}"
}

cleanup_containers() {
    local name
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

capture_logs() {
    [ -n "${OUTPUT}" ] || return 0
    mkdir -p "${OUTPUT}/diagnostics"
    local name
    for name in "${CONTAINERS[@]}"; do
        if docker container inspect "${name}" >/dev/null 2>&1; then
            docker logs "${name}" > "${OUTPUT}/diagnostics/${name}.log" 2>&1 || true
        fi
    done
}

on_exit() {
    local status=$?
    if [ "${status}" -ne 0 ] && [ -n "${OUTPUT}" ]; then
        capture_logs
        printf 'failed_at=%s\nexit_status=%s\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${status}" \
            > "${OUTPUT}/FAILED"
        log "experiment failed; partial evidence retained in ${OUTPUT}"
    fi
    stop_monotonic_clock
}
trap on_exit EXIT

ensure_images() {
    bash "${SCRIPT_DIR}/build-images.sh"
    if ! docker image inspect "${FRR_IMAGE}" >/dev/null 2>&1; then
        docker pull "${FRR_IMAGE}"
    fi
}

wait_krill() {
    local attempt
    for attempt in $(seq 1 120); do
        if docker exec "${KRILL}" krillc health >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    docker logs "${KRILL}" >&2
    echo "Krill did not become healthy" >&2
    return 1
}

wait_routinator() {
    local attempt
    for attempt in $(seq 1 120); do
        if docker exec "${ROUTINATOR}" \
            curl -fsS http://127.0.0.1:3333/status >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    docker logs "${ROUTINATOR}" >&2
    echo "Routinator did not become healthy" >&2
    return 1
}

wait_bgp_sessions() {
    local attempt count document
    for attempt in $(seq 1 120); do
        document=$(docker exec "${COLLECTOR}" \
            vtysh -c "show bgp ${BGP_AF} unicast summary json" \
            2>/dev/null || true)
        count=$(jq -r \
            '[.. | objects | select(.state? == "Established" or .peerState? == "Established")] | length' \
            <<< "${document}" 2>/dev/null || printf '0')
        count=${count:-0}
        if [ "${count}" -ge 2 ]; then
            return 0
        fi
        sleep 1
    done
    docker exec "${COLLECTOR}" \
        vtysh -c "show bgp ${BGP_AF} unicast summary" >&2
    echo "origin BGP sessions did not become Established" >&2
    return 1
}

run_frr() {
    local name=$1
    local address=$2
    local config=$3
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
        -v "${CHURN_CONFIG}/frr/${config}:/etc/frr/frr.conf:ro" \
        "${FRR_IMAGE}" >/dev/null
}

start_lab() {
    local token=$1
    docker network create --subnet 172.30.50.0/24 "${NETWORK}" >/dev/null
    docker volume create "${VOLUME}" >/dev/null

    docker run -d \
        --name "${KRILL}" \
        --hostname krill \
        --network "${NETWORK}" \
        --ip 172.30.50.2 \
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
        --ip 172.30.50.3 \
        -v "${SCRIPT_DIR}/routinator-entrypoint.sh:/opt/s2rov/routinator-entrypoint.sh:ro" \
        stripe-routinator:latest \
        bash /opt/s2rov/routinator-entrypoint.sh >/dev/null
    wait_routinator

    run_frr collector 172.30.50.10 collector.conf
    run_frr origin-a 172.30.50.11 origin-a.conf
    run_frr origin-b 172.30.50.12 origin-b.conf
    wait_bgp_sessions
}

origin_container() {
    case "$1" in
        8075) printf '%s' "${ORIGIN_A_CONTAINER}" ;;
        18403) printf '%s' "${ORIGIN_B_CONTAINER}" ;;
        *) echo "unsupported churn origin: $1" >&2; return 1 ;;
    esac
}

origin_peer() {
    case "$1" in
        8075) printf '172.30.50.11' ;;
        18403) printf '172.30.50.12' ;;
        *) echo "unsupported churn origin: $1" >&2; return 1 ;;
    esac
}

other_origin() {
    case "$1" in
        8075) printf '18403' ;;
        18403) printf '8075' ;;
        *) echo "unsupported churn origin: $1" >&2; return 1 ;;
    esac
}

set_origin_announcement() {
    local origin=$1
    local enabled=$2
    local container
    container=$(origin_container "${origin}")
    local command="network ${PREFIX}"
    if [ "${enabled}" = "false" ]; then
        command="no network ${PREFIX}"
    fi
    docker exec "${container}" vtysh \
        -c "configure terminal" \
        -c "router bgp ${origin}" \
        -c "address-family ${BGP_AF} unicast" \
        -c "${command}" \
        -c "end" >/dev/null
}

capture_rib() {
    local output=$1
    docker exec "${COLLECTOR}" \
        vtysh -c "show bgp ${BGP_AF} unicast ${PREFIX} json" > "${output}"
}

capture_received() {
    local origin=$1
    local output=$2
    local peer
    peer=$(origin_peer "${origin}")
    docker exec "${COLLECTOR}" \
        vtysh -c "show bgp ${BGP_AF} unicast neighbors ${peer} received-routes json" \
        > "${output}"
}

capture_routinator() {
    local output=$1
    docker exec "${ROUTINATOR}" \
        curl -fsS http://127.0.0.1:3333/json > "${output}"
}

wait_route_absent() {
    local output=$1
    local attempt document
    for attempt in $(seq 1 2400); do
        document=$(docker exec "${COLLECTOR}" \
            vtysh -c "show bgp ${BGP_AF} unicast ${PREFIX} json" \
            2>/dev/null || true)
        if ! jq -e '.paths[]?' <<< "${document}" >/dev/null 2>&1; then
            printf '%s\n' "${document}" > "${output}"
            return 0
        fi
        sleep "${POLL_SECONDS}"
    done
    echo "${PREFIX} did not leave the collector Loc-RIB" >&2
    return 1
}

wait_received_origin() {
    local origin=$1
    local output=$2
    local peer attempt document
    peer=$(origin_peer "${origin}")
    for attempt in $(seq 1 2400); do
        document=$(docker exec "${COLLECTOR}" \
            vtysh -c "show bgp ${BGP_AF} unicast neighbors ${peer} received-routes json" \
            2>/dev/null || true)
        if jq -e \
            --arg prefix "${PREFIX}" \
            --argjson origin "${origin}" \
            '.receivedRoutes[$prefix]? | .path | split(" ") | map(select(length > 0)) | last | tonumber == $origin' \
            <<< "${document}" >/dev/null 2>&1; then
            printf '%s\n' "${document}" > "${output}"
            return 0
        fi
        sleep "${POLL_SECONDS}"
    done
    echo "AS${origin} route did not appear in the collector Adj-RIB-In" >&2
    return 1
}

wait_route_present() {
    local origin=$1
    local preference=$2
    local community=$3
    local output=$4
    local attempt document
    for attempt in $(seq 1 3600); do
        document=$(docker exec "${COLLECTOR}" \
            vtysh -c "show bgp ${BGP_AF} unicast ${PREFIX} json" \
            2>/dev/null || true)
        if jq -e \
            --argjson origin "${origin}" \
            --argjson preference "${preference}" \
            --arg community "${community}" \
            '.paths[]? | select(
                (.aspath.string | split(" ") | map(select(length > 0)) | last | tonumber) == $origin
                and .locPrf == $preference
                and ((.community.string // "") | contains($community))
            )' <<< "${document}" >/dev/null 2>&1; then
            printf '%s\n' "${document}" > "${output}"
            return 0
        fi
        sleep "${POLL_SECONDS}"
    done
    docker exec "${COLLECTOR}" \
        vtysh -c "show bgp ${BGP_AF} unicast ${PREFIX}" >&2 || true
    echo "AS${origin} did not reach preference ${preference} and community ${community}" >&2
    return 1
}

assert_route_absent() {
    local output=$1
    capture_rib "${output}"
    if jq -e '.paths[]?' "${output}" >/dev/null 2>&1; then
        echo "route unexpectedly entered the Loc-RIB before authorization" >&2
        return 1
    fi
}

wait_exact_routinator() {
    local new_origin=$1
    local old_origin=$2
    local output=$3
    local attempt document
    for attempt in $(seq 1 1800); do
        document=$(docker exec "${ROUTINATOR}" \
            curl -fsS http://127.0.0.1:3333/json 2>/dev/null || true)
        if jq -e \
            --arg prefix "${PREFIX}" \
            --argjson new "${new_origin}" \
            --argjson old "${old_origin}" '
                def asnum: tostring | sub("^AS"; "") | tonumber;
                (any(.roas[]?; .prefix == $prefix and (.asn | asnum) == $new and .inclusivity == null))
                and (all(.roas[]?; .prefix != $prefix or (.asn | asnum) != $old))
            ' <<< "${document}" >/dev/null 2>&1; then
            printf '%s\n' "${document}" > "${output}"
            return 0
        fi
        sleep 0.1
    done
    echo "Routinator did not validate exact ${PREFIX} => AS${new_origin}" >&2
    return 1
}

wait_open_routinator() {
    local output=$1
    local attempt document
    for attempt in $(seq 1 1800); do
        document=$(docker exec "${ROUTINATOR}" \
            curl -fsS http://127.0.0.1:3333/json 2>/dev/null || true)
        if jq -e '
            any(.roas[]?;
                .prefix == "10.0.0.0/16"
                and .asn == "AS64501"
                and .minLength == 16
                and .maxLength == 24
                and .inclusivity == "inclusive")
        ' <<< "${document}" >/dev/null 2>&1; then
            printf '%s\n' "${document}" > "${output}"
            return 0
        fi
        sleep 0.1
    done
    echo "Routinator did not validate the open policy" >&2
    return 1
}

wait_rtr_exact() {
    local origin=$1
    local output=$2
    local attempt document
    for attempt in $(seq 1 1800); do
        document=$(docker exec "${COLLECTOR}" \
            vtysh -c "show rpki prefix-table json" 2>/dev/null || true)
        if jq -e \
            --arg prefix "${PREFIX_ADDRESS}" \
            --argjson origin "${origin}" '
                any(.prefixes[]?;
                    .prefix == $prefix
                    and .prefixLenMin == 24
                    and .prefixLenMax == 24
                    and .asn == $origin)
            ' <<< "${document}" >/dev/null 2>&1; then
            printf '%s\n' "${document}" > "${output}"
            return 0
        fi
        sleep 0.1
    done
    docker exec "${COLLECTOR}" vtysh -c "show rpki cache-connection" >&2 || true
    echo "FRR did not receive exact AS${origin} VRP over RTR" >&2
    return 1
}

apply_vty_file() {
    local source=$1
    docker exec -i "${COLLECTOR}" vtysh < "${source}" >/dev/null
    docker exec "${COLLECTOR}" \
        vtysh -c "clear bgp ${BGP_AF} unicast * soft in" >/dev/null
}

policy_digest() {
    local source=$1
    jq -cS \
        --arg prefix "${PREFIX}" \
        --arg open_prefix "${OPEN_PREFIX}" \
        '[.roas[]? | select(
            .prefix == $prefix or .prefix == $open_prefix
        )]' "${source}" | sha256sum | awk '{print $1}'
}

write_case() {
    local origin=$1
    local expected=$2
    local output=$3
    local peer
    peer=$(origin_peer "${origin}")
    jq -n \
        --arg peer "${peer}" \
        --arg prefix "${PREFIX}" \
        --argjson origin "${origin}" \
        --arg expected "${expected}" \
        '[{
            name:"active_origin",
            peer:$peer,
            prefix:$prefix,
            origin:$origin,
            expected_baseline:$expected,
            expected_da:$expected
        }]' > "${output}"
}

evaluate_one() {
    local mode=$1
    local vrps=$2
    local cases=$3
    local output=$4
    python3 "${AGENT}" evaluate \
        --vrps "${vrps}" \
        --cases "${cases}" \
        --mode "${mode}" \
        --output "${output}" \
        --fail-on-mismatch
}

setup_exact_lane() {
    local directory=$1
    local reset_collector=false
    mkdir -p "${directory}"
    log "installing exact child authorization for AS${CURRENT_ORIGIN}"
    if [ "${POLICY_MODE}" = "none" ]; then
        docker exec "${KRILL}" krillc roas update -c testbed \
            --add "${PREFIX} => ${CURRENT_ORIGIN}" >/dev/null
        SETUP_ENTRY_CHANGES=$((SETUP_ENTRY_CHANGES + 1))
    elif [ "${POLICY_MODE}" = "da" ]; then
        reset_collector=true
        docker exec "${KRILL}" krillc roas update -c testbed \
            --remove "${OPEN_POLICY}" \
            --add "${PREFIX} => ${CURRENT_ORIGIN}" >/dev/null
        SETUP_ENTRY_CHANGES=$((SETUP_ENTRY_CHANGES + 2))
    else
        echo "unexpected exact-lane setup from ${POLICY_MODE}" >&2
        return 1
    fi
    SETUP_SIGNED_TRANSACTIONS=$((SETUP_SIGNED_TRANSACTIONS + 1))
    POLICY_MODE="exact"
    POLICY_ORIGIN=${CURRENT_ORIGIN}
    wait_exact_routinator "${CURRENT_ORIGIN}" 0 \
        "${directory}/routinator-vrps.json"
    if [ "${reset_collector}" = "true" ]; then
        # Stock FRR closes an RTR session after seeing the experimental flag.
        # Recreate its cache session between lanes so the following exact block
        # starts from a clean standards-only snapshot.  This setup cost is not
        # included in any handoff observation.
        docker restart "${COLLECTOR}" >/dev/null
        wait_bgp_sessions
    fi
    wait_rtr_exact "${CURRENT_ORIGIN}" "${directory}/frr-rtr-prefix-table.json"
    apply_vty_file "${CHURN_CONFIG}/frr/exact-policy.vty"
    wait_route_present "${CURRENT_ORIGIN}" 300 "65000:10" \
        "${directory}/active-rib.json"
    docker exec "${KRILL}" krillc roas list -c testbed \
        > "${directory}/krill-roas.txt"
}

setup_da_lane() {
    local directory=$1
    mkdir -p "${directory}"
    log "installing one open policy; per-handoff policy updates stop here"
    if [ "${POLICY_MODE}" != "exact" ]; then
        echo "S2-ROV setup requires an exact-policy predecessor" >&2
        return 1
    fi
    docker exec "${KRILL}" krillc roas update -c testbed \
        --remove "${PREFIX} => ${POLICY_ORIGIN}" \
        --add "${OPEN_POLICY}" >/dev/null
    SETUP_SIGNED_TRANSACTIONS=$((SETUP_SIGNED_TRANSACTIONS + 1))
    SETUP_ENTRY_CHANGES=$((SETUP_ENTRY_CHANGES + 2))
    POLICY_MODE="da"
    POLICY_ORIGIN=64501
    wait_open_routinator "${directory}/routinator-vrps.json"
    python3 "${AGENT}" evaluate \
        --vrps "${directory}/routinator-vrps.json" \
        --cases "${CHURN_CONFIG}/cases.json" \
        --output "${directory}/decisions.json" \
        --policy-output "${directory}/frr-policy.vty" \
        --fail-on-mismatch
    apply_vty_file "${directory}/frr-policy.vty"
    wait_route_present "${CURRENT_ORIGIN}" 200 "65000:20" \
        "${directory}/active-rib.json"
    DA_POLICY_DIGEST=$(policy_digest "${directory}/routinator-vrps.json")
    docker exec "${KRILL}" krillc roas list -c testbed \
        > "${directory}/krill-roas.txt"
}

append_trial() {
    local global_order=$1
    local lane=$2
    local lane_trial=$3
    local block=$4
    local block_trial=$5
    local from_origin=$6
    local to_origin=$7
    local updates=$8
    local changes=$9
    shift 9
    local invalid_ms=$1
    local unavailable_ms=$2
    local end_to_end_ms=$3
    local bgp_ms=$4
    local authorization_ms=$5
    local final_state=$6
    local final_preference=$7
    local digest=$8
    local rp_ms=$9
    shift 9
    local rtr_ms=$1
    local enforcement_ms=$2
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,accept,%s,%s,%s,true\n' \
        "${global_order}" "${lane}" "${lane_trial}" "${block}" "${block_trial}" \
        "${from_origin}" "${to_origin}" "${updates}" "${changes}" \
        "${invalid_ms}" "${unavailable_ms}" "${end_to_end_ms}" "${bgp_ms}" \
        "${authorization_ms}" "${rp_ms}" "${rtr_ms}" "${enforcement_ms}" \
        "${final_state}" "${final_preference}" \
        "${to_origin}" "${digest}" >> "${TRIAL_CSV}"
}

write_trial_metadata() {
    local directory=$1
    local lane=$2
    local trial=$3
    local block=$4
    local from_origin=$5
    local to_origin=$6
    local invalid_ms=$7
    local unavailable_ms=$8
    local end_to_end_ms=$9
    shift 9
    local final_state=$1
    local final_preference=$2
    local updates=$3
    local digest=$4
    local rp_ms=$5
    local rtr_ms=$6
    local enforcement_ms=$7
    jq -n \
        --arg lane "${lane}" \
        --argjson trial "${trial}" \
        --argjson block "${block}" \
        --arg prefix "${PREFIX}" \
        --argjson from_origin "${from_origin}" \
        --argjson to_origin "${to_origin}" \
        --argjson signed_update_transactions "${updates}" \
        --argjson authorization_entry_changes "$((updates * 2))" \
        --argjson invalid_exposure_ms "${invalid_ms}" \
        --argjson unavailable_ms "${unavailable_ms}" \
        --argjson end_to_end_ms "${end_to_end_ms}" \
        --argjson signed_request_to_routinator_ms "${rp_ms}" \
        --argjson routinator_to_rtr_ms "${rtr_ms}" \
        --argjson rtr_to_enforcement_ms "${enforcement_ms}" \
        --arg final_state "${final_state}" \
        --argjson final_local_preference "${final_preference}" \
        --arg policy_digest "${digest}" '
        {
            lane:$lane,
            trial:$trial,
            block:$block,
            prefix:$prefix,
            from_origin:$from_origin,
            to_origin:$to_origin,
            signed_update_transactions:$signed_update_transactions,
            authorization_entry_changes:$authorization_entry_changes,
            invalid_exposure_ms:$invalid_exposure_ms,
            unavailable_ms:$unavailable_ms,
            end_to_end_ms:$end_to_end_ms,
            signed_request_to_routinator_ms:$signed_request_to_routinator_ms,
            routinator_to_rtr_ms:$routinator_to_rtr_ms,
            rtr_to_enforcement_ms:$rtr_to_enforcement_ms,
            final_state:$final_state,
            final_action:"accept",
            final_local_preference:$final_local_preference,
            policy_digest:$policy_digest,
            passed:true
        }' > "${directory}/metadata.json"
}

run_exact_trial() {
    local block=$1
    local block_trial=$2
    EXACT_TRIAL=$((EXACT_TRIAL + 1))
    GLOBAL_ORDER=$((GLOBAL_ORDER + 1))
    local trial=${EXACT_TRIAL}
    local old_origin=${CURRENT_ORIGIN}
    local new_origin
    new_origin=$(other_origin "${old_origin}")
    local directory
    directory=$(printf '%s/raw/exact/trial-%02d' "${OUTPUT}" "${trial}")
    mkdir -p "${directory}"
    capture_rib "${directory}/before-rib.json"
    capture_routinator "${directory}/before-routinator.json"

    local switch_start withdrawn_ns announce_start observed_ns auth_start rp_ns rtr_ns final_ns
    switch_start=$(monotonic_ns)
    event exact "${trial}" switch_requested "${switch_start}"
    set_origin_announcement "${old_origin}" false
    wait_route_absent "${directory}/after-withdraw-rib.json"
    withdrawn_ns=$(monotonic_ns)
    event exact "${trial}" old_route_absent "${withdrawn_ns}"
    announce_start=$(monotonic_ns)
    set_origin_announcement "${new_origin}" true
    wait_received_origin "${new_origin}" "${directory}/new-origin-received.json"
    observed_ns=$(monotonic_ns)
    event exact "${trial}" new_route_in_adj_rib_in "${observed_ns}"

    capture_routinator "${directory}/preauthorization-routinator.json"
    write_case "${new_origin}" Invalid "${directory}/preauthorization-case.json"
    evaluate_one baseline \
        "${directory}/preauthorization-routinator.json" \
        "${directory}/preauthorization-case.json" \
        "${directory}/preauthorization-decision.json"
    assert_route_absent "${directory}/preauthorization-rib.json"

    auth_start=$(monotonic_ns)
    event exact "${trial}" signed_authorization_requested "${auth_start}"
    docker exec "${KRILL}" krillc roas update -c testbed \
        --remove "${PREFIX} => ${old_origin}" \
        --add "${PREFIX} => ${new_origin}" >/dev/null
    POLICY_ORIGIN=${new_origin}
    wait_exact_routinator "${new_origin}" "${old_origin}" \
        "${directory}/final-routinator.json"
    rp_ns=$(monotonic_ns)
    event exact "${trial}" routinator_validated "${rp_ns}"
    wait_rtr_exact "${new_origin}" "${directory}/final-rtr-prefix-table.json"
    rtr_ns=$(monotonic_ns)
    event exact "${trial}" frr_rtr_table_updated "${rtr_ns}"
    # FRR 10.6.1 updates its RTR table but does not re-run the inbound policy
    # for this already received path in our build.  Trigger the documented
    # soft inbound re-evaluation and include it in end-to-end completion time.
    docker exec "${COLLECTOR}" \
        vtysh -c "clear bgp ${BGP_AF} unicast * soft in" >/dev/null
    write_case "${new_origin}" Valid "${directory}/final-case.json"
    evaluate_one baseline \
        "${directory}/final-routinator.json" \
        "${directory}/final-case.json" \
        "${directory}/final-decision.json"
    wait_route_present "${new_origin}" 300 "65000:10" \
        "${directory}/final-rib.json"
    final_ns=$(monotonic_ns)
    event exact "${trial}" valid_route_accepted "${final_ns}"
    docker exec "${KRILL}" krillc roas list -c testbed \
        > "${directory}/krill-roas.txt"

    local invalid_ms unavailable_ms end_to_end_ms bgp_ms auth_ms rp_ms rtr_ms enforcement_ms digest
    invalid_ms=$(elapsed_ms "${observed_ns}" "${final_ns}")
    unavailable_ms=$(elapsed_ms "${withdrawn_ns}" "${final_ns}")
    end_to_end_ms=$(elapsed_ms "${switch_start}" "${final_ns}")
    bgp_ms=$(elapsed_ms "${announce_start}" "${observed_ns}")
    auth_ms=$(elapsed_ms "${auth_start}" "${final_ns}")
    rp_ms=$(elapsed_ms "${auth_start}" "${rp_ns}")
    rtr_ms=$(elapsed_ms "${rp_ns}" "${rtr_ns}")
    enforcement_ms=$(elapsed_ms "${rtr_ns}" "${final_ns}")
    digest=$(policy_digest "${directory}/final-routinator.json")
    append_trial \
        "${GLOBAL_ORDER}" exact "${trial}" "${block}" "${block_trial}" \
        "${old_origin}" "${new_origin}" 1 2 \
        "${invalid_ms}" "${unavailable_ms}" "${end_to_end_ms}" "${bgp_ms}" \
        "${auth_ms}" Valid 300 "${digest}" "${rp_ms}" "${rtr_ms}" "${enforcement_ms}"
    write_trial_metadata \
        "${directory}" exact "${trial}" "${block}" "${old_origin}" "${new_origin}" \
        "${invalid_ms}" "${unavailable_ms}" "${end_to_end_ms}" Valid 300 1 "${digest}" \
        "${rp_ms}" "${rtr_ms}" "${enforcement_ms}"
    CURRENT_ORIGIN=${new_origin}
    log "exact trial ${trial}/${CHURN_TRIALS}: AS${old_origin}->AS${new_origin}, ${end_to_end_ms} ms"
}

run_da_trial() {
    local block=$1
    local block_trial=$2
    DA_TRIAL=$((DA_TRIAL + 1))
    GLOBAL_ORDER=$((GLOBAL_ORDER + 1))
    local trial=${DA_TRIAL}
    local old_origin=${CURRENT_ORIGIN}
    local new_origin
    new_origin=$(other_origin "${old_origin}")
    local directory
    directory=$(printf '%s/raw/da/trial-%02d' "${OUTPUT}" "${trial}")
    mkdir -p "${directory}"
    capture_rib "${directory}/before-rib.json"
    capture_routinator "${directory}/before-routinator.json"

    local switch_start withdrawn_ns announce_start observed_ns final_ns
    switch_start=$(monotonic_ns)
    event da "${trial}" switch_requested "${switch_start}"
    set_origin_announcement "${old_origin}" false
    wait_route_absent "${directory}/after-withdraw-rib.json"
    withdrawn_ns=$(monotonic_ns)
    event da "${trial}" old_route_absent "${withdrawn_ns}"
    announce_start=$(monotonic_ns)
    set_origin_announcement "${new_origin}" true
    wait_received_origin "${new_origin}" "${directory}/new-origin-received.json"
    observed_ns=$(monotonic_ns)
    event da "${trial}" new_route_in_adj_rib_in "${observed_ns}"

    capture_routinator "${directory}/final-routinator.json"
    local digest
    digest=$(policy_digest "${directory}/final-routinator.json")
    if [ "${digest}" != "${DA_POLICY_DIGEST}" ]; then
        echo "open policy changed during S2-ROV churn trial ${trial}" >&2
        return 1
    fi
    write_case "${new_origin}" Delegated "${directory}/final-case.json"
    evaluate_one da \
        "${directory}/final-routinator.json" \
        "${directory}/final-case.json" \
        "${directory}/final-decision.json"
    wait_route_present "${new_origin}" 200 "65000:20" \
        "${directory}/final-rib.json"
    final_ns=$(monotonic_ns)
    event da "${trial}" delegated_route_accepted "${final_ns}"
    docker exec "${KRILL}" krillc roas list -c testbed \
        > "${directory}/krill-roas.txt"

    local unavailable_ms end_to_end_ms bgp_ms
    unavailable_ms=$(elapsed_ms "${withdrawn_ns}" "${final_ns}")
    end_to_end_ms=$(elapsed_ms "${switch_start}" "${final_ns}")
    bgp_ms=$(elapsed_ms "${announce_start}" "${observed_ns}")
    append_trial \
        "${GLOBAL_ORDER}" da "${trial}" "${block}" "${block_trial}" \
        "${old_origin}" "${new_origin}" 0 0 \
        0.000 "${unavailable_ms}" "${end_to_end_ms}" "${bgp_ms}" \
        0.000 Delegated 200 "${digest}" 0.000 0.000 0.000
    write_trial_metadata \
        "${directory}" da "${trial}" "${block}" "${old_origin}" "${new_origin}" \
        0.000 "${unavailable_ms}" "${end_to_end_ms}" Delegated 200 0 "${digest}" \
        0.000 0.000 0.000
    CURRENT_ORIGIN=${new_origin}
    log "S2-ROV trial ${trial}/${CHURN_TRIALS}: AS${old_origin}->AS${new_origin}, ${end_to_end_ms} ms"
}

write_protocol() {
    local first_exact=$1
    local second_exact=$2
    jq -n \
        --arg prefix "${PREFIX}" \
        --argjson trials_per_lane "${CHURN_TRIALS}" \
        --argjson first_exact "${first_exact}" \
        --argjson da_trials "${CHURN_TRIALS}" \
        --argjson second_exact "${second_exact}" \
        --argjson frr_state_query_interval_s "${POLL_SECONDS}" \
        --argjson setup_signed_update_transactions "${SETUP_SIGNED_TRANSACTIONS}" \
        --argjson setup_authorization_entry_changes "${SETUP_ENTRY_CHANGES}" '
        {
            design:"reactive break-before-make origin handoff",
            prefix:$prefix,
            origins:[8075,18403],
            trials_per_lane:$trials_per_lane,
            execution_blocks:[
                {block:1,lane:"exact",trials:$first_exact},
                {block:2,lane:"da",trials:$da_trials},
                {block:3,lane:"exact",trials:$second_exact}
            ],
            setup_excluded_from_transition_metrics:true,
            setup_signed_update_transactions:$setup_signed_update_transactions,
            setup_authorization_entry_changes:$setup_authorization_entry_changes,
            exact_transition:{signed_update_transactions:1,authorization_entry_changes:2},
            da_transition:{signed_update_transactions:0,authorization_entry_changes:0},
            timing:{
                source:"Python time.monotonic_ns() served by one persistent helper process",
                event_field:"monotonic_ns",
                frr_state_query_interval_s:$frr_state_query_interval_s,
                routinator_rtr_query_interval_s:0.1,
                frr_rtr_poll_retry_interval_s:1
            },
            system_path:["Krill signing","RRDP","Routinator validation","FRR enforcement"]
        }' > "${OUTPUT}/protocol.json"
}

run_experiment() {
    if ! [[ "${CHURN_TRIALS}" =~ ^[1-9][0-9]*$ ]]; then
        echo "CHURN_TRIALS must be a positive integer" >&2
        return 2
    fi
    ensure_images
    clean_lab_state

    local run_id
    run_id=$(date -u +%Y%m%dT%H%M%SZ)
    OUTPUT="${E2E_DIR}/outputs/churn-${run_id}"
    if ! mkdir "${OUTPUT}"; then
        echo "refusing to overwrite an existing churn output: ${OUTPUT}" >&2
        return 1
    fi
    mkdir -p "${OUTPUT}/setup" "${OUTPUT}/raw"
    ln -sfn "churn-${run_id}" "${E2E_DIR}/outputs/latest-churn"
    EVENTS="${OUTPUT}/events.jsonl"
    TRIAL_CSV="${OUTPUT}/trials.csv"
    : > "${EVENTS}"
    printf 'global_order,lane,lane_trial,block,block_trial,from_origin,to_origin,signed_update_transactions,authorization_entry_changes,invalid_exposure_ms,unavailable_ms,end_to_end_ms,bgp_observation_ms,authorization_to_completion_ms,signed_request_to_routinator_ms,routinator_to_rtr_ms,rtr_to_enforcement_ms,final_state,final_action,final_local_preference,final_origin,policy_digest,passed\n' \
        > "${TRIAL_CSV}"

    local token
    token=$(openssl rand -hex 24)
    log "starting independent Krill, Routinator, and three-node FRR lab"
    start_lab "${token}"
    {
        docker exec "${KRILL}" krill --version
        docker exec "${ROUTINATOR}" routinator --version
        docker exec "${COLLECTOR}" /usr/lib/frr/bgpd --version | sed -n '1p'
        docker version --format 'Docker {{.Server.Version}}'
        uname -sr
    } > "${OUTPUT}/environment.txt"

    start_monotonic_clock

    local first_exact second_exact trial
    first_exact=$(((CHURN_TRIALS + 1) / 2))
    second_exact=$((CHURN_TRIALS - first_exact))

    setup_exact_lane "${OUTPUT}/setup/block-1-exact"
    for trial in $(seq 1 "${first_exact}"); do
        run_exact_trial 1 "${trial}"
    done

    setup_da_lane "${OUTPUT}/setup/block-2-da"
    for trial in $(seq 1 "${CHURN_TRIALS}"); do
        run_da_trial 2 "${trial}"
    done

    if [ "${second_exact}" -gt 0 ]; then
        setup_exact_lane "${OUTPUT}/setup/block-3-exact"
        for trial in $(seq 1 "${second_exact}"); do
            run_exact_trial 3 "${trial}"
        done
    fi

    write_protocol "${first_exact}" "${second_exact}"
    capture_logs
    python3 "${SUMMARIZER}" \
        --run-dir "${OUTPUT}" \
        --output "${OUTPUT}/summary.json"
    rm -f "${OUTPUT}/FAILED"
    log "origin-churn experiment complete: ${OUTPUT}"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-experiment}" in
        experiment)
            run_experiment
            ;;
        status)
            docker ps -a --filter "name=${CONTAINER_PREFIX}" \
                --format '{{.Names}}\t{{.Status}}\t{{.Image}}'
            ;;
        down)
            cleanup_containers
            ;;
        clean)
            clean_lab_state
            ;;
        *)
            echo "usage: $0 [experiment|status|down|clean]" >&2
            exit 2
            ;;
    esac
fi
