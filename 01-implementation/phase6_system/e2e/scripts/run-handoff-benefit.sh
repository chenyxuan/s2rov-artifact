#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
HANDOFF_AF=${HANDOFF_AF:-ipv4}
case "${HANDOFF_AF}" in
    ipv4|ipv6) ;;
    *) echo "HANDOFF_AF must be ipv4 or ipv6" >&2; exit 2 ;;
esac
BGP_AF=${HANDOFF_AF}
# Reuse only the topology and live-state primitives.  The accepted churn
# controls are deliberately not sourced because their OpenScope arm compiles
# both candidate origins before the timed handoff.
source "${SCRIPT_DIR}/run-churn-experiment.sh"

STAGED_COMPILER="${E2E_DIR}/src/staged_policy.py"
BENEFIT_SUMMARIZER="${E2E_DIR}/src/summarize_handoff_benefit.py"
BENEFIT_AUDITOR="${E2E_DIR}/src/audit_handoff_benefit.py"
SCALE_SUMMARIZER="${E2E_DIR}/src/summarize_scale.py"
SCALE_AUDITOR="${E2E_DIR}/src/audit_scale.py"

case "${HANDOFF_AF}" in
    ipv4)
        BENEFIT_CONFIG_REL="config/benefit"
        NETWORK="ssrov-benefit"
        VOLUME="ssrov-benefit-krill-data"
        CONTAINER_PREFIX="ssrov-benefit-"
        NETWORK_IPV4_SUBNET="172.30.60.0/24"
        NETWORK_IPV6_SUBNET=""
        KRILL_IPV4="172.30.60.2"
        KRILL_IPV6=""
        ROUTINATOR_IPV4="172.30.60.3"
        ROUTINATOR_IPV6=""
        COLLECTOR_IPV4="172.30.60.10"
        COLLECTOR_IPV6=""
        ORIGIN_A_IPV4="172.30.60.11"
        ORIGIN_A_IPV6=""
        ORIGIN_B_IPV4="172.30.60.12"
        ORIGIN_B_IPV6=""
        ORIGIN_A_PEER="172.30.60.11"
        ORIGIN_B_PEER="172.30.60.12"
        PREFIX="10.0.10.0/24"
        PREFIX_ADDRESS="10.0.10.0"
        PREFIX_LENGTH=24
        OPEN_PREFIX="10.0.0.0/16"
        OPEN_MIN_LENGTH=16
        OPEN_MAX_LENGTH=24
        OPEN_POLICY="10.0.0.0/16, 16-24 => 64501 inclusive"
        KEEPALIVE_PREFIX="10.255.255.0/24"
        KEEPALIVE_POLICY="10.255.255.0/24 => 64501"
        PROBE_ADDRESS_CIDR="10.0.10.1/24"
        PROBE_DESTINATION="10.0.10.1"
        OUTPUT_STEM="handoff-benefit"
        LATEST_LINK="latest-handoff-benefit"
        NGINX_CONFIG="${CONFIG_DIR}/krill/nginx.conf"
        ;;
    ipv6)
        BENEFIT_CONFIG_REL="config/benefit-v6"
        NETWORK="ssrov-benefit-v6"
        VOLUME="ssrov-benefit-v6-krill-data"
        CONTAINER_PREFIX="ssrov-benefit-v6-"
        NETWORK_IPV4_SUBNET="172.30.61.0/24"
        NETWORK_IPV6_SUBNET="fd30:61::/64"
        KRILL_IPV4="172.30.61.2"
        KRILL_IPV6="fd30:61::2"
        ROUTINATOR_IPV4="172.30.61.3"
        ROUTINATOR_IPV6="fd30:61::3"
        COLLECTOR_IPV4="172.30.61.10"
        COLLECTOR_IPV6="fd30:61::10"
        ORIGIN_A_IPV4="172.30.61.11"
        ORIGIN_A_IPV6="fd30:61::11"
        ORIGIN_B_IPV4="172.30.61.12"
        ORIGIN_B_IPV6="fd30:61::12"
        ORIGIN_A_PEER="fd30:61::11"
        ORIGIN_B_PEER="fd30:61::12"
        PREFIX="2001:db8:10::/48"
        PREFIX_ADDRESS="2001:db8:10::"
        PREFIX_LENGTH=48
        OPEN_PREFIX="2001:db8::/32"
        OPEN_MIN_LENGTH=32
        OPEN_MAX_LENGTH=48
        OPEN_POLICY="2001:db8::/32, 32-48 => 64501 inclusive"
        KEEPALIVE_PREFIX="2001:db8:ffff::/48"
        KEEPALIVE_POLICY="2001:db8:ffff::/48 => 64501"
        PROBE_ADDRESS_CIDR="2001:db8:10::1/48"
        PROBE_DESTINATION="2001:db8:10::1"
        OUTPUT_STEM="handoff-benefit-ipv6"
        LATEST_LINK="latest-handoff-benefit-ipv6"
        NGINX_CONFIG="${CONFIG_DIR}/benefit-v6/nginx.conf"
        ;;
esac

BENEFIT_CONFIG="${E2E_DIR}/${BENEFIT_CONFIG_REL}"
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
CHURN_CONFIG="${BENEFIT_CONFIG}"

HANDOFF_TRIALS=${HANDOFF_TRIALS:-40}
HANDOFF_BLOCK_SIZE=${HANDOFF_BLOCK_SIZE:-4}
HANDOFF_RANDOM_SEED=${HANDOFF_RANDOM_SEED:-20260828}
HANDOFF_DEADLINE_MS=${HANDOFF_DEADLINE_MS:-15000}
CHURN_TRIALS=${HANDOFF_TRIALS}
SCALE_TRIALS=${SCALE_TRIALS:-10}
SCALE_LEVELS=${SCALE_LEVELS:-"0 64 256 1024"}

POLICY_MODE="none"
POLICY_ORIGIN=0
SETUP_SIGNED_TRANSACTIONS=0
SETUP_ROA_ENTRY_CHANGES=0
GLOBAL_ORDER=0
CURRENT_ROUND=0
CURRENT_BLOCK=0
declare -A LANE_TRIAL=(
    [reactive_exact]=0
    [open_dynamic]=0
    [prepublished_exact]=0
)

log() {
    printf '[benefit-%s] %s\n' "${HANDOFF_AF}" "$*"
}

origin_peer() {
    case "$1" in
        8075) printf '%s' "${ORIGIN_A_PEER}" ;;
        18403) printf '%s' "${ORIGIN_B_PEER}" ;;
        *) echo "unsupported benefit origin: $1" >&2; return 1 ;;
    esac
}

run_frr() {
    local name=$1
    local address=$2
    local config=$3
    local ipv6_address=${4:-}
    local -a ipv6_args=()
    if [ -n "${ipv6_address}" ]; then
        ipv6_args+=(
            --ip6 "${ipv6_address}"
            --sysctl net.ipv6.conf.all.forwarding=1
            --sysctl net.ipv6.conf.default.forwarding=1
        )
    fi
    docker run -d \
        --name "${CONTAINER_PREFIX}${name}" \
        --hostname "${name}" \
        --network "${NETWORK}" \
        --ip "${address}" \
        "${ipv6_args[@]}" \
        --cap-add NET_ADMIN \
        --cap-add NET_RAW \
        --cap-add SYS_ADMIN \
        --sysctl net.ipv4.ip_forward=1 \
        -v "${CONFIG_DIR}/frr/daemons:/etc/frr/daemons:ro" \
        -v "${CONFIG_DIR}/frr/vtysh.conf:/etc/frr/vtysh.conf:ro" \
        -v "${BENEFIT_CONFIG}/frr/${config}:/etc/frr/frr.conf:ro" \
        "${FRR_IMAGE}" >/dev/null
}

start_lab() {
    local token=$1
    local -a network_args=(--subnet "${NETWORK_IPV4_SUBNET}")
    if [ -n "${NETWORK_IPV6_SUBNET}" ]; then
        network_args+=(--ipv6 --subnet "${NETWORK_IPV6_SUBNET}")
    fi
    docker network create "${network_args[@]}" "${NETWORK}" >/dev/null
    docker volume create "${VOLUME}" >/dev/null

    local -a krill_ipv6_args=()
    if [ -n "${KRILL_IPV6}" ]; then
        krill_ipv6_args+=(--ip6 "${KRILL_IPV6}")
    fi
    docker run -d \
        --name "${KRILL}" \
        --hostname krill \
        --network "${NETWORK}" \
        --ip "${KRILL_IPV4}" \
        "${krill_ipv6_args[@]}" \
        -e "KRILL_CLI_TOKEN=${token}" \
        -v "${VOLUME}:<home>/data" \
        -v "${NGINX_CONFIG}:/etc/nginx/sites-enabled/testbed:ro" \
        -v "${CONFIG_DIR}/krill/krill.conf.template:/opt/daroa/krill.conf.template:ro" \
        -v "${SCRIPT_DIR}/krill-entrypoint.sh:/opt/daroa/krill-entrypoint.sh:ro" \
        stripe-testbed:latest \
        bash /opt/daroa/krill-entrypoint.sh >/dev/null
    wait_krill

    local -a routinator_ipv6_args=()
    if [ -n "${ROUTINATOR_IPV6}" ]; then
        routinator_ipv6_args+=(--ip6 "${ROUTINATOR_IPV6}")
    fi
    docker run -d \
        --name "${ROUTINATOR}" \
        --hostname routinator \
        --network "${NETWORK}" \
        --ip "${ROUTINATOR_IPV4}" \
        "${routinator_ipv6_args[@]}" \
        -v "${SCRIPT_DIR}/routinator-entrypoint.sh:/opt/daroa/routinator-entrypoint.sh:ro" \
        stripe-routinator:latest \
        bash /opt/daroa/routinator-entrypoint.sh >/dev/null
    wait_routinator

    run_frr collector "${COLLECTOR_IPV4}" collector.conf "${COLLECTOR_IPV6}"
    run_frr origin-a "${ORIGIN_A_IPV4}" origin-a.conf "${ORIGIN_A_IPV6}"
    run_frr origin-b "${ORIGIN_B_IPV4}" origin-b.conf "${ORIGIN_B_IPV6}"
    wait_bgp_sessions

    local container
    for container in "${ORIGIN_A_CONTAINER}" "${ORIGIN_B_CONTAINER}"; do
        docker exec "${container}" ip link add probe0 type dummy
        docker exec "${container}" \
            ip address add "${PROBE_ADDRESS_CIDR}" dev probe0
        docker exec "${container}" ip link set probe0 up
    done
}

wait_policy_snapshot() {
    local lane=$1
    local origin=$2
    local output=$3
    local attempt document
    for attempt in $(seq 1 1800); do
        document=$(docker exec "${ROUTINATOR}" \
            curl -fsS http://127.0.0.1:3333/json 2>/dev/null || true)
        if jq -e \
            --arg lane "${lane}" \
            --arg prefix "${PREFIX}" \
            --arg open_prefix "${OPEN_PREFIX}" \
            --argjson prefix_length "${PREFIX_LENGTH}" \
            --argjson open_min_length "${OPEN_MIN_LENGTH}" \
            --argjson open_max_length "${OPEN_MAX_LENGTH}" \
            --argjson origin "${origin}" '
                def asnum: tostring | sub("^AS"; "") | tonumber;
                [.roas[]? | select(
                    .prefix == $prefix
                    or .prefix == $open_prefix
                )] as $r
                | if $lane == "reactive_exact" then
                    ($r | length) == 1
                    and any($r[];
                        .prefix == $prefix
                        and (.asn | asnum) == $origin
                        and .minLength == $prefix_length
                        and .maxLength == $prefix_length
                        and .inclusivity == null)
                  elif $lane == "open_dynamic" then
                    ($r | length) == 1
                    and any($r[];
                        .prefix == $open_prefix
                        and (.asn | asnum) == 64501
                        and .minLength == $open_min_length
                        and .maxLength == $open_max_length
                        and .inclusivity == "inclusive")
                  elif $lane == "prepublished_exact" then
                    ($r | length) == 2
                    and any($r[];
                        .prefix == $prefix
                        and (.asn | asnum) == 8075
                        and .minLength == $prefix_length
                        and .maxLength == $prefix_length
                        and .inclusivity == null)
                    and any($r[];
                        .prefix == $prefix
                        and (.asn | asnum) == 18403
                        and .minLength == $prefix_length
                        and .maxLength == $prefix_length
                        and .inclusivity == null)
                  else false end
            ' <<< "${document}" >/dev/null 2>&1; then
            printf '%s\n' "${document}" > "${output}"
            return 0
        fi
        sleep 0.1
    done
    echo "Routinator did not converge to ${lane}" >&2
    return 1
}

initialize_keepalive() {
    local directory=$1
    mkdir -p "${directory}"
    docker exec "${KRILL}" krillc roas update -c testbed \
        --add "${KEEPALIVE_POLICY}" >/dev/null
    SETUP_SIGNED_TRANSACTIONS=$((SETUP_SIGNED_TRANSACTIONS + 1))
    SETUP_ROA_ENTRY_CHANGES=$((SETUP_ROA_ENTRY_CHANGES + 1))
    local attempt document
    for attempt in $(seq 1 1800); do
        document=$(docker exec "${ROUTINATOR}" \
            curl -fsS http://127.0.0.1:3333/json 2>/dev/null || true)
        if jq -e \
            --arg keepalive_prefix "${KEEPALIVE_PREFIX}" \
            'any(.roas[]?;
                .prefix == $keepalive_prefix and .asn == "AS64501")' \
            <<< "${document}" >/dev/null 2>&1; then
            printf '%s\n' "${document}" > "${directory}/policy.json"
            return 0
        fi
        sleep 0.1
    done
    echo "Routinator did not validate the repository keepalive" >&2
    return 1
}

prepare_signed_policy() {
    local target=$1
    local directory=$2
    local previous=${POLICY_MODE}
    local -a args=()
    local changes=0
    mkdir -p "${directory}"

    case "${previous}" in
        none) ;;
        reactive_exact)
            args+=(--remove "${PREFIX} => ${POLICY_ORIGIN}")
            changes=$((changes + 1))
            ;;
        open_dynamic)
            args+=(--remove "${OPEN_POLICY}")
            changes=$((changes + 1))
            ;;
        prepublished_exact)
            args+=(--remove "${PREFIX} => 8075")
            args+=(--remove "${PREFIX} => 18403")
            changes=$((changes + 2))
            ;;
        *) echo "unsupported previous policy: ${previous}" >&2; return 1 ;;
    esac

    case "${target}" in
        reactive_exact)
            args+=(--add "${PREFIX} => ${CURRENT_ORIGIN}")
            changes=$((changes + 1))
            ;;
        open_dynamic)
            args+=(--add "${OPEN_POLICY}")
            changes=$((changes + 1))
            ;;
        prepublished_exact)
            args+=(--add "${PREFIX} => 8075")
            args+=(--add "${PREFIX} => 18403")
            changes=$((changes + 2))
            ;;
        *) echo "unsupported target policy: ${target}" >&2; return 1 ;;
    esac

    docker exec "${KRILL}" krillc roas update -c testbed \
        "${args[@]}" >/dev/null
    SETUP_SIGNED_TRANSACTIONS=$((SETUP_SIGNED_TRANSACTIONS + 1))
    SETUP_ROA_ENTRY_CHANGES=$((SETUP_ROA_ENTRY_CHANGES + changes))
    POLICY_MODE=${target}
    if [ "${target}" = "reactive_exact" ]; then
        POLICY_ORIGIN=${CURRENT_ORIGIN}
    else
        POLICY_ORIGIN=0
    fi
    wait_policy_snapshot "${target}" "${CURRENT_ORIGIN}" \
        "${directory}/policy.json"
    docker exec "${KRILL}" krillc roas list -c testbed \
        > "${directory}/krill-roas.txt"
}

capture_both_received() {
    local directory=$1
    capture_received 8075 "${directory}/received-a.json"
    capture_received 18403 "${directory}/received-b.json"
}

compile_received_policy() {
    local policy=$1
    local directory=$2
    python3 "${STAGED_COMPILER}" \
        --vrps "${policy}" \
        --cases "${BENEFIT_CONFIG}/empty-cases.json" \
        --received "${ORIGIN_A_PEER}=${directory}/received-a.json" \
        --received "${ORIGIN_B_PEER}=${directory}/received-b.json" \
        --router-asn 65000 \
        --address-family "${HANDOFF_AF}" \
        --output "${directory}/decisions.json" \
        --policy-output "${directory}/frr-policy.vty" \
        --fail-on-mismatch
}

install_pending_policy() {
    local directory=$1
    mkdir -p "${directory}"
    jq -n '{receivedRoutes:{}}' > "${directory}/received-a.json"
    jq -n '{receivedRoutes:{}}' > "${directory}/received-b.json"
    capture_routinator "${directory}/policy.json"
    compile_received_policy "${directory}/policy.json" "${directory}"
    apply_vty_file "${directory}/frr-policy.vty"
    wait_route_absent "${directory}/rib.json"
    docker exec "${COLLECTOR}" vtysh -c "show running-config" \
        > "${directory}/running-config.txt"
}

expected_state_raw() {
    case "$1" in
        open_dynamic) printf 'Delegated' ;;
        reactive_exact|prepublished_exact) printf 'Explicit' ;;
        *) return 1 ;;
    esac
}

expected_state_paper() {
    case "$1" in
        open_dynamic) printf 'OpenScope' ;;
        reactive_exact|prepublished_exact) printf 'Explicit' ;;
        *) return 1 ;;
    esac
}

expected_preference() {
    case "$1" in
        open_dynamic) printf '200' ;;
        reactive_exact|prepublished_exact) printf '300' ;;
        *) return 1 ;;
    esac
}

expected_community() {
    case "$1" in
        open_dynamic) printf '65000:20' ;;
        reactive_exact|prepublished_exact) printf '65000:10' ;;
        *) return 1 ;;
    esac
}

assert_one_dynamic_decision() {
    local lane=$1
    local origin=$2
    local decisions=$3
    local expected
    expected=$(expected_state_raw "${lane}")
    jq -e \
        --arg prefix "${PREFIX}" \
        --argjson origin "${origin}" \
        --arg state "${expected}" '
            length == 1
            and .[0].prefix == $prefix
            and .[0].origin == $origin
            and .[0].state == $state
            and .[0].action == "retain"
        ' "${decisions}" >/dev/null
}

wait_probe() {
    local output=$1
    local attempt
    local -a family_args=()
    if [ "${HANDOFF_AF}" = "ipv6" ]; then
        family_args+=(-6)
    fi
    for attempt in $(seq 1 300); do
        if docker exec "${COLLECTOR}" \
            ping "${family_args[@]}" -n -c 1 -W 1 "${PROBE_DESTINATION}" \
            > "${output}" 2>&1; then
            return 0
        fi
        sleep "${POLL_SECONDS}"
    done
    echo "data-plane probe did not reach ${PROBE_DESTINATION}" >&2
    return 1
}

prepare_current_action() {
    local lane=$1
    local directory=$2
    local state preference community
    mkdir -p "${directory}"
    state=$(expected_state_raw "${lane}")
    preference=$(expected_preference "${lane}")
    community=$(expected_community "${lane}")
    capture_both_received "${directory}"
    capture_routinator "${directory}/policy.json"
    compile_received_policy "${directory}/policy.json" "${directory}"
    assert_one_dynamic_decision "${lane}" "${CURRENT_ORIGIN}" \
        "${directory}/decisions.json"
    apply_vty_file "${directory}/frr-policy.vty"
    wait_route_present "${CURRENT_ORIGIN}" "${preference}" "${community}" \
        "${directory}/rib.json"
    wait_probe "${directory}/ping.txt"
    jq -n \
        --arg lane "${lane}" \
        --arg state "${state}" \
        --argjson origin "${CURRENT_ORIGIN}" \
        '{lane:$lane,state:$state,origin:$origin,setup_only:true}' \
        > "${directory}/metadata.json"
}

run_handoff_trial() {
    local lane=$1
    local round=$2
    local block=$3
    local block_trial=$4
    LANE_TRIAL[${lane}]=$((LANE_TRIAL[${lane}] + 1))
    GLOBAL_ORDER=$((GLOBAL_ORDER + 1))
    local trial=${LANE_TRIAL[${lane}]}
    local old_origin=${CURRENT_ORIGIN}
    local new_origin
    new_origin=$(other_origin "${old_origin}")
    local directory
    directory=$(printf '%s/raw/%s/trial-%03d' "${OUTPUT}" "${lane}" "${trial}")
    mkdir -p "${directory}"

    capture_rib "${directory}/before-rib.json"
    capture_routinator "${directory}/pre-policy.json"
    local switch_ns absent_ns observed_ns rp_ns compiler_start_ns compiler_end_ns
    local action_ns probe_ns
    switch_ns=$(monotonic_ns)
    event "${lane}" "${trial}" switch_requested "${switch_ns}"
    set_origin_announcement "${old_origin}" false
    wait_route_absent "${directory}/after-withdraw-rib.json"
    absent_ns=$(monotonic_ns)
    event "${lane}" "${trial}" old_route_absent "${absent_ns}"

    install_pending_policy "${directory}/pending"
    set_origin_announcement "${new_origin}" true
    wait_received_origin "${new_origin}" "${directory}/new-origin-received.json"
    observed_ns=$(monotonic_ns)
    event "${lane}" "${trial}" new_route_in_adj_rib_in "${observed_ns}"
    assert_route_absent "${directory}/pre-action-rib.json"
    capture_both_received "${directory}"
    capture_routinator "${directory}/pre-policy.json"

    local signed_updates=0 roa_changes=0
    if [ "${lane}" = "reactive_exact" ]; then
        event "${lane}" "${trial}" signed_roa_requested "$(monotonic_ns)"
        docker exec "${KRILL}" krillc roas update -c testbed \
            --remove "${PREFIX} => ${old_origin}" \
            --add "${PREFIX} => ${new_origin}" >/dev/null
        POLICY_ORIGIN=${new_origin}
        signed_updates=1
        roa_changes=2
        wait_policy_snapshot "${lane}" "${new_origin}" \
            "${directory}/final-policy.json"
    else
        cp "${directory}/pre-policy.json" "${directory}/final-policy.json"
    fi
    rp_ns=$(monotonic_ns)
    event "${lane}" "${trial}" rp_policy_available "${rp_ns}"

    compiler_start_ns=$(monotonic_ns)
    event "${lane}" "${trial}" compiler_started "${compiler_start_ns}"
    compile_received_policy "${directory}/final-policy.json" "${directory}"
    compiler_end_ns=$(monotonic_ns)
    event "${lane}" "${trial}" compiler_completed "${compiler_end_ns}"
    assert_one_dynamic_decision "${lane}" "${new_origin}" \
        "${directory}/decisions.json"

    apply_vty_file "${directory}/frr-policy.vty"
    local state_raw state_paper preference community
    state_raw=$(expected_state_raw "${lane}")
    state_paper=$(expected_state_paper "${lane}")
    preference=$(expected_preference "${lane}")
    community=$(expected_community "${lane}")
    wait_route_present "${new_origin}" "${preference}" "${community}" \
        "${directory}/final-rib.json"
    action_ns=$(monotonic_ns)
    event "${lane}" "${trial}" action_installed "${action_ns}"
    wait_probe "${directory}/ping.txt"
    probe_ns=$(monotonic_ns)
    event "${lane}" "${trial}" probe_succeeded "${probe_ns}"

    docker exec "${KRILL}" krillc roas list -c testbed \
        > "${directory}/krill-roas.txt"
    local observed_action_ms observed_probe_ms switch_action_ms switch_probe_ms
    local deadline_miss=false completion=true policy_hash direction
    observed_action_ms=$(elapsed_ms "${observed_ns}" "${action_ns}")
    observed_probe_ms=$(elapsed_ms "${observed_ns}" "${probe_ns}")
    switch_action_ms=$(elapsed_ms "${switch_ns}" "${action_ns}")
    switch_probe_ms=$(elapsed_ms "${switch_ns}" "${probe_ns}")
    if awk -v value="${observed_probe_ms}" -v limit="${HANDOFF_DEADLINE_MS}" \
        'BEGIN { exit !(value > limit) }'; then
        deadline_miss=true
        completion=false
    fi
    policy_hash=$(policy_digest "${directory}/final-policy.json")
    direction="AS${old_origin}-to-AS${new_origin}"

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,complete,,%s,%s,accept,%s,%s,%s,true\n' \
        "${GLOBAL_ORDER}" "${round}" "${block}" "${block_trial}" \
        "${lane}" "${trial}" "${old_origin}" "${new_origin}" "${direction}" \
        "${signed_updates}" "${roa_changes}" "${observed_action_ms}" \
        "${observed_probe_ms}" "${switch_action_ms}" "${switch_probe_ms}" \
        "${completion}" "${deadline_miss}" "${state_raw}" "${state_paper}" \
        "${preference}" "${new_origin}" "${policy_hash}" >> "${TRIAL_CSV}"

    jq -n \
        --arg lane "${lane}" \
        --argjson trial "${trial}" \
        --argjson round "${round}" \
        --argjson block "${block}" \
        --argjson block_trial "${block_trial}" \
        --arg prefix "${PREFIX}" \
        --argjson from_origin "${old_origin}" \
        --argjson to_origin "${new_origin}" \
        --arg direction "${direction}" \
        --argjson signed_update_transactions "${signed_updates}" \
        --argjson roa_entry_changes "${roa_changes}" \
        --argjson observed_to_action_ms "${observed_action_ms}" \
        --argjson observed_to_probe_ms "${observed_probe_ms}" \
        --argjson switch_to_action_ms "${switch_action_ms}" \
        --argjson switch_to_probe_ms "${switch_probe_ms}" \
        --argjson deadline_ms "${HANDOFF_DEADLINE_MS}" \
        --argjson completion "${completion}" \
        --argjson deadline_miss "${deadline_miss}" \
        --arg final_state_raw "${state_raw}" \
        --arg final_state_paper "${state_paper}" \
        --argjson final_local_preference "${preference}" \
        --argjson final_origin "${new_origin}" \
        --arg policy_digest "${policy_hash}" '
        {
            lane:$lane, trial:$trial, round:$round, block:$block,
            block_trial:$block_trial, prefix:$prefix,
            from_origin:$from_origin, to_origin:$to_origin,
            direction:$direction,
            signed_update_transactions:$signed_update_transactions,
            roa_entry_changes:$roa_entry_changes,
            observed_to_action_ms:$observed_to_action_ms,
            observed_to_probe_ms:$observed_to_probe_ms,
            switch_to_action_ms:$switch_to_action_ms,
            switch_to_probe_ms:$switch_to_probe_ms,
            deadline_ms:$deadline_ms, completion:$completion,
            deadline_miss:$deadline_miss, status:"complete",
            failure_category:null, final_state_raw:$final_state_raw,
            final_state_paper:$final_state_paper, final_action:"accept",
            final_local_preference:$final_local_preference,
            final_origin:$final_origin, policy_digest:$policy_digest,
            passed:true
        }' > "${directory}/metadata.json"

    CURRENT_ORIGIN=${new_origin}
    log "${lane} ${trial}/${HANDOFF_TRIALS}: ${direction}, observation-to-probe ${observed_probe_ms} ms"
}

generate_schedule() {
    local rounds=$1
    python3 - "${HANDOFF_RANDOM_SEED}" "${rounds}" <<'PY'
import random
import sys

seed = int(sys.argv[1])
rounds = int(sys.argv[2])
rng = random.Random(seed)
arms = ["reactive_exact", "open_dynamic", "prepublished_exact"]
print("round,lane")
for round_id in range(1, rounds + 1):
    order = arms.copy()
    rng.shuffle(order)
    for lane in order:
        print(f"{round_id},{lane}")
PY
}

write_protocol() {
    local rounds=$1
    jq -n \
        --arg address_family "${HANDOFF_AF}" \
        --arg prefix "${PREFIX}" \
        --arg probe_destination "${PROBE_DESTINATION}" \
        --argjson trials "${HANDOFF_TRIALS}" \
        --argjson block_size "${HANDOFF_BLOCK_SIZE}" \
        --argjson rounds "${rounds}" \
        --argjson seed "${HANDOFF_RANDOM_SEED}" \
        --argjson deadline "${HANDOFF_DEADLINE_MS}" \
        --argjson poll "${POLL_SECONDS}" \
        --argjson setup_transactions "${SETUP_SIGNED_TRANSACTIONS}" \
        --argjson setup_changes "${SETUP_ROA_ENTRY_CHANGES}" '
        {
            schema_version:"1.0",
            analysis_role:"primary_matched_handoff",
            design:"randomized complete-block unknown-origin handoff",
            address_family:$address_family,
            prefix:$prefix,
            probe_destination:$probe_destination,
            origins:[8075,18403],
            arms:["reactive_exact","open_dynamic","prepublished_exact"],
            trials_per_lane:$trials,
            trials_per_block:$block_size,
            randomized_complete_block_rounds:$rounds,
            random_seed:$seed,
            randomization_unit:"one arm block within each complete round",
            primary_endpoint:"first successful data-plane probe after new-route Adj-RIB-In observation",
            secondary_endpoint:"configured usable routing action after new-route Adj-RIB-In observation",
            deadline_ms:$deadline,
            inference_unit:"complete-round arm mean",
            setup_excluded_from_endpoints:true,
            setup_signed_update_transactions:$setup_transactions,
            setup_roa_entry_changes:$setup_changes,
            handoff_updates:{reactive_exact:1,open_dynamic:0,prepublished_exact:0},
            compiler_contract:"all arms compile only routes captured from live Adj-RIB-In after observation",
            open_scope_contract:"the signed policy and pretrial action map name neither endpoint origin",
            action_map:{Explicit:{local_preference:300,community:"65000:10"},OpenScope:{local_preference:200,community:"65000:20"}},
            timing:{source:"one persistent Python time.monotonic_ns helper",event_field:"monotonic_ns",router_poll_interval_s:$poll},
            system_path:["Krill signing","RRDP","Routinator validation","route-derived classifier","FRR action","ICMP probe"]
        }' > "${OUTPUT}/protocol.json"
}

capture_environment() {
    {
        docker exec "${KRILL}" krill --version
        docker exec "${ROUTINATOR}" routinator --version
        docker exec "${COLLECTOR}" /usr/lib/frr/bgpd --version | sed -n '1p'
        docker version --format 'Docker {{.Server.Version}}'
        uname -srmo
        lscpu | sed -n \
            -e '/^Architecture:/p' \
            -e '/^CPU(s):/p' \
            -e '/^Model name:/p' \
            -e '/^Thread(s) per core:/p' \
            -e '/^Core(s) per socket:/p' \
            -e '/^Socket(s):/p'
        awk '/^MemTotal:/ {print}' /proc/meminfo
        printf 'Git commit %s\n' "$(git -C "${E2E_DIR}" rev-parse HEAD)"
        docker image inspect --format 'Image {{.Id}} {{json .RepoDigests}}' \
            stripe-testbed:latest stripe-routinator:latest "${FRR_IMAGE}"
    } > "${OUTPUT}/environment.txt"
    (
        cd "${E2E_DIR}"
        sha256sum \
            scripts/run-handoff-benefit.sh \
            scripts/run-churn-experiment.sh \
            scripts/krill-entrypoint.sh \
            scripts/routinator-entrypoint.sh \
            src/daroa_agent.py \
            src/daroa_policy_dualstack.py \
            src/staged_policy.py \
            src/summarize_handoff_benefit.py \
            src/audit_handoff_benefit.py \
            config/krill/krill.conf.template \
            "${BENEFIT_CONFIG_REL}/empty-cases.json" \
            "${BENEFIT_CONFIG_REL}/frr/collector.conf" \
            "${BENEFIT_CONFIG_REL}/frr/origin-a.conf" \
            "${BENEFIT_CONFIG_REL}/frr/origin-b.conf" \
            "${NGINX_CONFIG#${E2E_DIR}/}"
    ) > "${OUTPUT}/source.sha256"
    git -C "${E2E_DIR}" status --short -- . > "${OUTPUT}/git-status.txt"
}

write_artifact_inventory() {
    (
        cd "${OUTPUT}"
        find raw -type f -print0 | sort -z | xargs -0 sha256sum
    ) > "${OUTPUT}/raw.sha256"
}

scale_current_origin() {
    local origin peer document count=0 selected=""
    for origin in 8075 18403; do
        peer=$(origin_peer "${origin}")
        document=$(docker exec "${COLLECTOR}" \
            vtysh -c "show bgp ${BGP_AF} unicast neighbors ${peer} received-routes json" \
            2>/dev/null || true)
        if jq -e \
            --arg prefix "${PREFIX}" \
            --argjson origin "${origin}" '
                .receivedRoutes[$prefix]?
                | .path | split(" ") | map(select(length > 0))
                | last | tonumber == $origin
            ' <<< "${document}" >/dev/null 2>&1; then
            selected=${origin}
            count=$((count + 1))
        fi
    done
    if [ "${count}" -ne 1 ]; then
        echo "expected exactly one announced target origin, found ${count}" >&2
        return 1
    fi
    printf '%s' "${selected}"
}

scale_require_live_lab() {
    local name
    for name in "${CONTAINERS[@]}"; do
        if [ "$(docker inspect -f '{{.State.Running}}' "${name}" 2>/dev/null || true)" != "true" ]; then
            echo "${name} is not running; run the matched handoff lab first" >&2
            return 1
        fi
    done
    wait_bgp_sessions
    scale_current_origin >/dev/null
}

scale_has_exact() {
    local origin=$1
    local key="${PREFIX}-${PREFIX_LENGTH}"
    docker exec "${KRILL}" krillc roas list -c testbed 2>/dev/null \
        | awk -v key="${key}" -v origin="${origin}" \
            '$1 == key && $3 == origin { found=1 } END { exit !found }'
}

scale_has_open() {
    local entry="${OPEN_PREFIX}, ${OPEN_MIN_LENGTH}-${OPEN_MAX_LENGTH} => 64501 inclusive"
    docker exec "${KRILL}" krillc roas list -c testbed 2>/dev/null \
        | grep -Fqx "${entry}"
}

scale_background_prefix() {
    local index=$1
    if [ "${HANDOFF_AF}" = "ipv4" ]; then
        local offset=$((index * 64))
        local second=$((18 + offset / 65536))
        local third=$(((offset / 256) % 256))
        local fourth=$((offset % 256))
        printf '198.%s.%s.%s/26' "${second}" "${third}" "${fourth}"
    else
        printf '2001:db8:8000:%x::/64' "${index}"
    fi
}

scale_validated_background_count() {
    local expression
    if [ "${HANDOFF_AF}" = "ipv4" ]; then
        expression='[.roas[]? | select(.prefix | test("^198\\.(18|19)\\."))] | length'
    else
        expression='[.roas[]? | select(.prefix | test("^2001:db8:8000:"))] | length'
    fi
    docker exec "${ROUTINATOR}" \
        curl -fsS http://127.0.0.1:3333/json 2>/dev/null \
        | jq "${expression}"
}

scale_wait_background_count() {
    local expected=$1
    local attempt actual
    for attempt in $(seq 1 480); do
        actual=$(scale_validated_background_count || printf '%s' -1)
        if [ "${actual}" = "${expected}" ]; then
            return 0
        fi
        sleep 0.25
    done
    echo "validated ${HANDOFF_AF} background count did not reach ${expected}" >&2
    return 1
}

scale_update_background_range() {
    local operation=$1
    local first=$2
    local last=$3
    if [ "${last}" -lt "${first}" ]; then
        return 0
    fi
    local -a args=()
    local index
    for index in $(seq "${first}" "${last}"); do
        args+=("--${operation}" "$(scale_background_prefix "${index}") => 65010")
    done
    docker exec "${KRILL}" krillc roas update -c testbed "${args[@]}" >/dev/null
}

scale_remove_existing_background() {
    local -a prefixes=()
    local pattern
    if [ "${HANDOFF_AF}" = "ipv4" ]; then
        pattern='^198[.](18|19)[.]'
    else
        pattern='^2001:db8:8000:'
    fi
    while IFS= read -r prefix; do
        [ -n "${prefix}" ] && prefixes+=("${prefix}")
    done < <(
        docker exec "${KRILL}" krillc roas list -c testbed 2>/dev/null \
            | awk -v pattern="${pattern}" '$1 ~ pattern {print $1}' \
            | sed -E 's#(/[0-9]+)-[0-9]+$#\1#'
    )
    if [ "${#prefixes[@]}" -gt 0 ]; then
        local -a args=()
        local prefix
        for prefix in "${prefixes[@]}"; do
            args+=(--remove "${prefix} => 65010")
        done
        docker exec "${KRILL}" krillc roas update -c testbed "${args[@]}" >/dev/null
    fi
    scale_wait_background_count 0
}

scale_wait_policy() {
    local origin=$1
    local exact_expected=$2
    local background_expected=$3
    local output=$4
    local other attempt document
    other=$(other_origin "${origin}")
    for attempt in $(seq 1 1800); do
        document=$(docker exec "${ROUTINATOR}" \
            curl -fsS http://127.0.0.1:3333/json 2>/dev/null || true)
        if jq -e \
            --arg prefix "${PREFIX}" \
            --arg open_prefix "${OPEN_PREFIX}" \
            --arg af "${HANDOFF_AF}" \
            --argjson origin "${origin}" \
            --argjson other "${other}" \
            --argjson prefix_length "${PREFIX_LENGTH}" \
            --argjson open_min "${OPEN_MIN_LENGTH}" \
            --argjson open_max "${OPEN_MAX_LENGTH}" \
            --argjson exact_expected "${exact_expected}" \
            --argjson background_expected "${background_expected}" '
                def asnum: tostring | sub("^AS"; "") | tonumber;
                def background:
                    if $af == "ipv4" then (.prefix | test("^198\\.(18|19)\\."))
                    else (.prefix | test("^2001:db8:8000:")) end;
                ([.roas[]? | select(
                    .prefix == $prefix
                    and (.asn | asnum) == $origin
                    and .minLength == $prefix_length
                    and .maxLength == $prefix_length
                    and .inclusivity == null
                )] | length) == (if $exact_expected then 1 else 0 end)
                and all(.roas[]?;
                    .prefix != $prefix or (.asn | asnum) != $other)
                and any(.roas[]?;
                    .prefix == $open_prefix
                    and (.asn | asnum) == 64501
                    and .minLength == $open_min
                    and .maxLength == $open_max
                    and .inclusivity == "inclusive")
                and ([.roas[]? | select(background)] | length) == $background_expected
            ' <<< "${document}" >/dev/null 2>&1; then
            printf '%s\n' "${document}" > "${output}"
            return 0
        fi
        sleep 0.1
    done
    echo "Routinator did not reach the requested scale-policy state" >&2
    return 1
}

scale_compile_state() {
    local lane=$1
    local origin=$2
    local directory=$3
    local preference community
    mkdir -p "${directory}"
    capture_both_received "${directory}"
    capture_routinator "${directory}/routinator-vrps.json"
    compile_received_policy "${directory}/routinator-vrps.json" "${directory}"
    assert_one_dynamic_decision "${lane}" "${origin}" "${directory}/decisions.json"
    apply_vty_file "${directory}/frr-policy.vty"
    preference=$(expected_preference "${lane}")
    community=$(expected_community "${lane}")
    wait_route_present "${origin}" "${preference}" "${community}" \
        "${directory}/target-rib.json"
    docker exec "${COLLECTOR}" \
        vtysh -c "show bgp ${BGP_AF} unicast json" \
        > "${directory}/bgp-rib.json"
    python3 "${AGENT}" check-enforced \
        --routes "${directory}/bgp-rib.json" \
        --decisions "${directory}/decisions.json" \
        --output "${directory}/enforcement.json" \
        --fail-on-mismatch
}

scale_prepare_lab() {
    local directory=$1
    mkdir -p "${directory}"
    scale_remove_existing_background
    CURRENT_ORIGIN=$(scale_current_origin)
    local inactive
    inactive=$(other_origin "${CURRENT_ORIGIN}")
    local -a args=()
    if ! scale_has_open; then
        args+=(--add "${OPEN_POLICY}")
    fi
    if ! scale_has_exact "${CURRENT_ORIGIN}"; then
        args+=(--add "${PREFIX} => ${CURRENT_ORIGIN}")
    fi
    if scale_has_exact "${inactive}"; then
        args+=(--remove "${PREFIX} => ${inactive}")
    fi
    if [ "${#args[@]}" -gt 0 ]; then
        docker exec "${KRILL}" krillc roas update -c testbed "${args[@]}" >/dev/null
    fi
    scale_wait_policy "${CURRENT_ORIGIN}" true 0 "${directory}/routinator-vrps.json"
    scale_compile_state reactive_exact "${CURRENT_ORIGIN}" "${directory}/action"
}

scale_restore_lab() {
    local directory=$1
    mkdir -p "${directory}"
    scale_remove_existing_background
    local -a args=()
    if scale_has_open; then
        args+=(--remove "${OPEN_POLICY}")
    fi
    if ! scale_has_exact 8075; then
        args+=(--add "${PREFIX} => 8075")
    fi
    if ! scale_has_exact 18403; then
        args+=(--add "${PREFIX} => 18403")
    fi
    if [ "${#args[@]}" -gt 0 ]; then
        docker exec "${KRILL}" krillc roas update -c testbed "${args[@]}" >/dev/null
    fi
    local attempt document restored=false
    for attempt in $(seq 1 1800); do
        document=$(docker exec "${ROUTINATOR}" \
            curl -fsS http://127.0.0.1:3333/json 2>/dev/null || true)
        if jq -e \
            --arg prefix "${PREFIX}" \
            --arg open_prefix "${OPEN_PREFIX}" '
                def asnum: tostring | sub("^AS"; "") | tonumber;
                any(.roas[]?; .prefix == $prefix and (.asn | asnum) == 8075)
                and any(.roas[]?; .prefix == $prefix and (.asn | asnum) == 18403)
                and all(.roas[]?; .prefix != $open_prefix)
            ' <<< "${document}" >/dev/null 2>&1; then
            printf '%s\n' "${document}" > "${directory}/routinator-vrps.json"
            restored=true
            break
        fi
        sleep 0.1
    done
    if [ "${restored}" != "true" ]; then
        echo "failed to restore the prepublished exact policy" >&2
        return 1
    fi
    CURRENT_ORIGIN=$(scale_current_origin)
    scale_compile_state prepublished_exact "${CURRENT_ORIGIN}" "${directory}/action"
}

scale_capture_environment() {
    capture_environment
    (
        cd "${E2E_DIR}"
        sha256sum \
            src/summarize_scale.py \
            src/audit_scale.py
    ) > "${OUTPUT}/source-scale.sha256"
}

scale_write_protocol() {
    jq -n \
        --arg address_family "${HANDOFF_AF}" \
        --arg prefix "${PREFIX}" \
        --arg levels "${SCALE_LEVELS}" \
        --argjson trials "${SCALE_TRIALS}" '
        {
            schema_version:"dual-stack-policy-scale-v1",
            design:"matched single-route signed-policy scale",
            address_family:$address_family,
            target_prefix:$prefix,
            levels:($levels | split(" ") | map(select(length > 0) | tonumber)),
            trials_per_transition:$trials,
            transitions:["remove","restore"],
            timed_path:["Krill publication","RRDP","Routinator validation","route-derived classification","FRR installation","live-route enforcement check"],
            route_checks_per_transition:1,
            background_policy:"noncovering exact entries with no live routes",
            comparison_contract:"IPv4 and IPv6 use the same topology, target-route count, levels, trials, and stopping condition"
        }' > "${OUTPUT}/protocol.json"
}

run_scale_experiment() {
    if [ "${SCALE_TRIALS}" -ne 10 ] 2>/dev/null; then
        echo "SCALE_TRIALS must be 10 for the paper experiment" >&2
        return 2
    fi
    if [ "${SCALE_LEVELS}" != "0 64 256 1024" ]; then
        echo "SCALE_LEVELS must be '0 64 256 1024' for the paper experiment" >&2
        return 2
    fi
    scale_require_live_lab
    local run_id
    run_id=$(date -u +%Y%m%dT%H%M%SZ)
    OUTPUT="${E2E_DIR}/outputs/policy-scale-${HANDOFF_AF}-${run_id}"
    mkdir "${OUTPUT}"
    ln -sfn "policy-scale-${HANDOFF_AF}-${run_id}" \
        "${E2E_DIR}/outputs/latest-policy-scale-${HANDOFF_AF}"
    local samples="${OUTPUT}/policy-scale-samples.csv"
    local payloads="${OUTPUT}/policy-scale-payloads.csv"
    printf 'background_stripes,total_validated_entries,trial,transition,milliseconds\n' \
        > "${samples}"
    printf 'background_stripes,total_validated_entries,json_bytes,setup_ms\n' \
        > "${payloads}"

    start_monotonic_clock
    scale_prepare_lab "${OUTPUT}/setup"
    local current=0 level
    for level in ${SCALE_LEVELS}; do
        local setup_start_ns setup_end_ns setup_ms
        setup_start_ns=$(monotonic_ns)
        if [ "${level}" -gt "${current}" ]; then
            scale_update_background_range add "${current}" "$((level - 1))"
            scale_wait_background_count "${level}"
        fi
        setup_end_ns=$(monotonic_ns)
        setup_ms=$(elapsed_ms "${setup_start_ns}" "${setup_end_ns}")

        local level_dir="${OUTPUT}/background-${level}"
        mkdir -p "${level_dir}"
        capture_routinator "${level_dir}/validated-policy.json"
        local total_entries json_bytes
        total_entries=$(jq '.roas | length' "${level_dir}/validated-policy.json")
        json_bytes=$(wc -c < "${level_dir}/validated-policy.json")
        printf '%s,%s,%s,%s\n' \
            "${level}" "${total_entries}" "${json_bytes}" "${setup_ms}" \
            >> "${payloads}"

        log "scale level ${level}: ${SCALE_TRIALS} remove/restore cycles"
        local trial
        for trial in $(seq 1 "${SCALE_TRIALS}"); do
            local trial_dir
            trial_dir=$(printf '%s/trial-%02d' "${level_dir}" "${trial}")
            mkdir -p "${trial_dir}/remove" "${trial_dir}/restore"
            local start_ns end_ns transition_ms

            start_ns=$(monotonic_ns)
            docker exec "${KRILL}" krillc roas update -c testbed \
                --remove "${PREFIX} => ${CURRENT_ORIGIN}" >/dev/null
            scale_wait_policy "${CURRENT_ORIGIN}" false "${level}" \
                "${trial_dir}/remove/routinator-vrps.json"
            scale_compile_state open_dynamic "${CURRENT_ORIGIN}" \
                "${trial_dir}/remove"
            end_ns=$(monotonic_ns)
            transition_ms=$(elapsed_ms "${start_ns}" "${end_ns}")
            printf '%s,%s,%s,remove,%s\n' \
                "${level}" "${total_entries}" "${trial}" "${transition_ms}" \
                >> "${samples}"

            start_ns=$(monotonic_ns)
            docker exec "${KRILL}" krillc roas update -c testbed \
                --add "${PREFIX} => ${CURRENT_ORIGIN}" >/dev/null
            scale_wait_policy "${CURRENT_ORIGIN}" true "${level}" \
                "${trial_dir}/restore/routinator-vrps.json"
            scale_compile_state reactive_exact "${CURRENT_ORIGIN}" \
                "${trial_dir}/restore"
            end_ns=$(monotonic_ns)
            transition_ms=$(elapsed_ms "${start_ns}" "${end_ns}")
            printf '%s,%s,%s,restore,%s\n' \
                "${level}" "${total_entries}" "${trial}" "${transition_ms}" \
                >> "${samples}"
        done
        current=${level}
    done

    scale_restore_lab "${OUTPUT}/cleanup"
    scale_write_protocol
    scale_capture_environment
    capture_logs
    (
        cd "${OUTPUT}"
        find background-* setup cleanup -type f -print0 \
            | sort -z | xargs -0 sha256sum
    ) > "${OUTPUT}/raw.sha256"
    python3 "${SCALE_SUMMARIZER}" \
        --run-dir "${OUTPUT}" \
        --output "${OUTPUT}/summary.json" \
        --address-family "${HANDOFF_AF}" \
        --target-prefix "${PREFIX}"
    python3 "${SCALE_AUDITOR}" \
        --run-dir "${OUTPUT}" \
        --output "${OUTPUT}/independent-audit.json" \
        --address-family "${HANDOFF_AF}"
    rm -f "${OUTPUT}/FAILED"
    log "matched policy-scale experiment complete: ${OUTPUT}"
}

run_benefit_experiment() {
    if ! [[ "${HANDOFF_TRIALS}" =~ ^[1-9][0-9]*$ ]]; then
        echo "HANDOFF_TRIALS must be a positive integer" >&2
        return 2
    fi
    if ! [[ "${HANDOFF_BLOCK_SIZE}" =~ ^[1-9][0-9]*$ ]]; then
        echo "HANDOFF_BLOCK_SIZE must be a positive integer" >&2
        return 2
    fi
    if [ $((HANDOFF_TRIALS % HANDOFF_BLOCK_SIZE)) -ne 0 ]; then
        echo "HANDOFF_TRIALS must be divisible by HANDOFF_BLOCK_SIZE" >&2
        return 2
    fi
    if ! [[ "${HANDOFF_RANDOM_SEED}" =~ ^[0-9]+$ ]]; then
        echo "HANDOFF_RANDOM_SEED must be a nonnegative integer" >&2
        return 2
    fi

    ensure_images
    clean_lab_state
    local run_id
    run_id=$(date -u +%Y%m%dT%H%M%SZ)
    OUTPUT="${E2E_DIR}/outputs/${OUTPUT_STEM}-${run_id}"
    mkdir "${OUTPUT}"
    mkdir -p "${OUTPUT}/setup" "${OUTPUT}/raw"
    ln -sfn "${OUTPUT_STEM}-${run_id}" \
        "${E2E_DIR}/outputs/${LATEST_LINK}"
    EVENTS="${OUTPUT}/events.jsonl"
    TRIAL_CSV="${OUTPUT}/trials.csv"
    : > "${EVENTS}"
    printf 'global_order,round,block,block_trial,lane,trial,from_origin,to_origin,direction,signed_update_transactions,roa_entry_changes,observed_to_action_ms,observed_to_probe_ms,switch_to_action_ms,switch_to_probe_ms,completion,deadline_miss,status,failure_category,final_state_raw,final_state_paper,final_action,final_local_preference,final_origin,policy_digest,passed\n' \
        > "${TRIAL_CSV}"

    local token
    token=$(openssl rand -hex 24)
    log "starting isolated matched handoff lab"
    start_lab "${token}"
    start_monotonic_clock
    initialize_keepalive "${OUTPUT}/setup/repository-keepalive"

    local rounds
    rounds=$((HANDOFF_TRIALS / HANDOFF_BLOCK_SIZE))
    generate_schedule "${rounds}" > "${OUTPUT}/block-order.csv"

    local round lane block=0 block_trial
    while IFS=, read -r round lane; do
        if [ "${round}" = "round" ]; then
            continue
        fi
        block=$((block + 1))
        prepare_signed_policy "${lane}" \
            "$(printf '%s/setup/block-%02d-%s' "${OUTPUT}" "${block}" "${lane}")"
        prepare_current_action "${lane}" \
            "$(printf '%s/setup/block-%02d-%s/action' "${OUTPUT}" "${block}" "${lane}")"
        for block_trial in $(seq 1 "${HANDOFF_BLOCK_SIZE}"); do
            run_handoff_trial "${lane}" "${round}" "${block}" "${block_trial}"
        done
    done < "${OUTPUT}/block-order.csv"

    write_protocol "${rounds}"
    capture_environment
    capture_logs
    write_artifact_inventory
    python3 "${BENEFIT_SUMMARIZER}" \
        --run-dir "${OUTPUT}" --output "${OUTPUT}/summary.json"
    python3 "${BENEFIT_AUDITOR}" \
        --run-dir "${OUTPUT}" --source-root "${E2E_DIR}" \
        --output "${OUTPUT}/independent-audit.json"
    rm -f "${OUTPUT}/FAILED"
    log "matched handoff experiment complete: ${OUTPUT}"
}

case "${1:-experiment}" in
    experiment) run_benefit_experiment ;;
    scale) run_scale_experiment ;;
    status)
        docker ps -a --filter "name=${CONTAINER_PREFIX}" \
            --format '{{.Names}}\t{{.Status}}\t{{.Image}}'
        ;;
    down) cleanup_containers ;;
    clean) clean_lab_state ;;
    *)
        echo "usage: $0 [experiment|scale|status|down|clean]" >&2
        exit 2
        ;;
esac
