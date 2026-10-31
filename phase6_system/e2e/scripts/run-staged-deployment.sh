#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
E2E_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
CONFIG_DIR="${E2E_DIR}/config"
STAGED_CONFIG="${CONFIG_DIR}/staged"
CASES="${STAGED_CONFIG}/cases.json"
POLICY_COMPILER="${E2E_DIR}/src/staged_policy.py"
SUMMARIZER="${E2E_DIR}/src/summarize_staged.py"

NETWORK="daroa-staged"
VOLUME="daroa-staged-krill-data"
PREFIX="daroa-staged-"
FRR_IMAGE="quay.io/frrouting/frr:10.6.1"
ROUTINATOR_IMAGE="stripe-routinator-staged:latest"
TRANSITION_TRIALS=${STAGED_TRANSITION_TRIALS:-30}

KRILL="${PREFIX}krill"
ROUTINATOR="${PREFIX}routinator"
T1="${PREFIX}t1"
T2="${PREFIX}t2"
T3="${PREFIX}t3"
SINK="${PREFIX}sink"

ORIGIN_NAMES=(
    holder explicit delegate open-control aggregate-attacker
    closed-attacker ineligible unrelated
)
ORIGIN_ADDRESSES=(
    172.30.0.21 172.30.0.22 172.30.0.23 172.30.0.24
    172.30.0.25 172.30.0.26 172.30.0.27 172.30.0.28
)
T1_UPSTREAM=("${ORIGIN_ADDRESSES[@]}")
T2_UPSTREAM=(172.30.0.11)
T3_UPSTREAM=(172.30.0.12)
SINK_UPSTREAM=(172.30.0.13)

CONTAINERS=("${KRILL}" "${ROUTINATOR}" "${T1}" "${T2}" "${T3}" "${SINK}")
for name in "${ORIGIN_NAMES[@]}"; do
    CONTAINERS+=("${PREFIX}${name}")
done

log() {
    printf '[staged] %s\n' "$*"
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

ensure_images() {
    bash "${SCRIPT_DIR}/build-staged-images.sh"
    if ! docker image inspect "${FRR_IMAGE}" >/dev/null 2>&1; then
        docker pull "${FRR_IMAGE}"
    fi
}

wait_krill() {
    local attempt
    for attempt in $(seq 1 120); do
        if docker exec "${KRILL}" krillc health >/dev/null 2>&1; then
            return
        fi
        sleep 1
    done
    docker logs "${KRILL}" >&2
    echo "staged Krill did not become healthy" >&2
    exit 1
}

wait_routinator() {
    local attempt
    for attempt in $(seq 1 120); do
        if docker exec "${ROUTINATOR}" \
            curl -fsS http://127.0.0.1:3333/status >/dev/null 2>&1; then
            return
        fi
        sleep 1
    done
    docker logs "${ROUTINATOR}" >&2
    echo "staged Routinator did not become healthy" >&2
    exit 1
}

wait_routinator_query() {
    local jq_query=$1
    local attempt document
    for attempt in $(seq 1 120); do
        document=$(docker exec "${ROUTINATOR}" \
            curl -fsS http://127.0.0.1:3333/json 2>/dev/null || true)
        if jq -e "${jq_query}" >/dev/null 2>&1 <<< "${document}"; then
            return
        fi
        sleep 1
    done
    docker exec "${ROUTINATOR}" curl -fsS http://127.0.0.1:3333/json >&2 || true
    echo "validated policy did not satisfy: ${jq_query}" >&2
    exit 1
}

run_frr() {
    local name=$1
    local address=$2
    local config=$3
    docker run -d \
        --name "${PREFIX}${name}" \
        --hostname "${name}" \
        --network "${NETWORK}" \
        --ip "${address}" \
        --cap-add NET_ADMIN \
        --cap-add NET_RAW \
        --cap-add SYS_ADMIN \
        --sysctl net.ipv4.ip_forward=1 \
        -v "${CONFIG_DIR}/frr/daemons:/etc/frr/daemons:ro" \
        -v "${CONFIG_DIR}/frr/vtysh.conf:/etc/frr/vtysh.conf:ro" \
        -v "${STAGED_CONFIG}/frr/${config}:/etc/frr/frr.conf:ro" \
        "${FRR_IMAGE}" >/dev/null
}

start_lab() {
    local token=$1
    docker network create --subnet 172.30.0.0/24 "${NETWORK}" >/dev/null
    docker volume create "${VOLUME}" >/dev/null

    docker run -d \
        --name "${KRILL}" \
        --hostname krill \
        --network "${NETWORK}" \
        --ip 172.30.0.2 \
        -e "KRILL_CLI_TOKEN=${token}" \
        -v "${VOLUME}:/home/cnic/data" \
        -v "${CONFIG_DIR}/krill/nginx.conf:/etc/nginx/sites-enabled/testbed:ro" \
        -v "${CONFIG_DIR}/krill/krill.conf.template:/opt/daroa/krill.conf.template:ro" \
        -v "${SCRIPT_DIR}/krill-entrypoint.sh:/opt/daroa/krill-entrypoint.sh:ro" \
        stripe-testbed:latest \
        bash /opt/daroa/krill-entrypoint.sh >/dev/null
    wait_krill

    docker run -d \
        --name "${ROUTINATOR}" \
        --hostname routinator \
        --network "${NETWORK}" \
        --ip 172.30.0.3 \
        -v "${SCRIPT_DIR}/routinator-entrypoint.sh:/opt/daroa/routinator-entrypoint.sh:ro" \
        "${ROUTINATOR_IMAGE}" \
        bash /opt/daroa/routinator-entrypoint.sh >/dev/null
    wait_routinator

    run_frr t1 172.30.0.11 t1.conf
    run_frr t2 172.30.0.12 t2.conf
    run_frr t3 172.30.0.13 t3.conf
    run_frr sink 172.30.0.14 sink.conf

    local index
    for index in "${!ORIGIN_NAMES[@]}"; do
        run_frr \
            "${ORIGIN_NAMES[${index}]}" \
            "${ORIGIN_ADDRESSES[${index}]}" \
            "${ORIGIN_NAMES[${index}]}.conf"
    done
}

established_count() {
    local container=$1
    docker exec "${container}" \
        vtysh -c "show bgp ipv4 unicast summary json" 2>/dev/null \
        | jq '[.. | objects | select(.state? == "Established" or .peerState? == "Established")] | length'
}

wait_bgp_count() {
    local container=$1
    local expected=$2
    local attempt actual
    for attempt in $(seq 1 120); do
        actual=$(established_count "${container}" 2>/dev/null || printf '0')
        if [ "${actual}" -ge "${expected}" ]; then
            return
        fi
        sleep 1
    done
    docker exec "${container}" vtysh -c "show bgp ipv4 unicast summary" >&2 || true
    echo "${container} did not reach ${expected} BGP sessions" >&2
    exit 1
}

wait_all_bgp() {
    wait_bgp_count "${T1}" 9
    wait_bgp_count "${T2}" 2
    wait_bgp_count "${T3}" 2
    wait_bgp_count "${SINK}" 1
}

legacy_view_ok() {
    local container=$1
    local cache table
    cache=$(docker exec "${container}" \
        vtysh -c "show rpki cache-connection json" 2>/dev/null || true)
    table=$(docker exec "${container}" \
        vtysh -c "show rpki prefix-table json" 2>/dev/null || true)
    jq -e 'any(.connections[]?; .state == "connected")' \
        >/dev/null 2>&1 <<< "${cache}" \
        && jq -e '
            (.prefixes | length) == 2 and
            any(.prefixes[]?; .prefix == "10.0.0.0" and
                .prefixLenMin == 16 and .prefixLenMax == 16 and .asn == 64501) and
            any(.prefixes[]?; .prefix == "10.0.1.0" and
                .prefixLenMin == 24 and .prefixLenMax == 24 and .asn == 8075)
        ' >/dev/null 2>&1 <<< "${table}"
}

wait_legacy_view() {
    local container attempt
    for container in "${T1}" "${T2}" "${T3}"; do
        for attempt in $(seq 1 120); do
            if legacy_view_ok "${container}"; then
                break
            fi
            sleep 1
        done
        if ! legacy_view_ok "${container}"; then
            docker exec "${container}" \
                vtysh -c "show rpki cache-connection" >&2 || true
            docker exec "${container}" \
                vtysh -c "show rpki prefix-table" >&2 || true
            echo "legacy-safe RTR view failed on ${container}" >&2
            exit 1
        fi
    done
}

peer_filename() {
    tr '.' '_' <<< "$1"
}

capture_received() {
    local container=$1
    local destination=$2
    shift 2
    mkdir -p "${destination}"
    local peer filename
    for peer in "$@"; do
        filename=$(peer_filename "${peer}")
        docker exec "${container}" vtysh -c \
            "show bgp ipv4 unicast neighbors ${peer} received-routes json" \
            > "${destination}/${filename}.json"
    done
}

capture_node() {
    local node=$1
    local destination=$2
    shift 2
    mkdir -p "${destination}"
    capture_received "${PREFIX}${node}" "${destination}/received" "$@"
    docker exec "${PREFIX}${node}" \
        vtysh -c "show bgp ipv4 unicast json" > "${destination}/bgp-rib.json"
    if [ "${node}" != "sink" ]; then
        docker exec "${PREFIX}${node}" \
            vtysh -c "show route-map json" \
            > "${destination}/route-maps.json"
        docker exec "${PREFIX}${node}" \
            vtysh -c "show rpki cache-connection json" \
            > "${destination}/rpki-cache.json"
        docker exec "${PREFIX}${node}" \
            vtysh -c "show rpki prefix-table json" \
            > "${destination}/rpki-prefix-table.json"
    fi
}

apply_vty() {
    local container=$1
    local source=$2
    docker exec -i "${container}" vtysh < "${source}" >/dev/null
}

apply_legacy() {
    local node=$1
    local asn=$2
    shift 2
    local command_file=$1
    shift
    {
        echo "configure terminal"
        echo "router bgp ${asn}"
        echo " address-family ipv4 unicast"
        local peer
        for peer in "$@"; do
            echo "  neighbor ${peer} route-map LEGACY-IN in"
        done
        echo " exit-address-family"
        echo "exit"
        echo "end"
    } > "${command_file}"
    apply_vty "${PREFIX}${node}" "${command_file}"
    docker exec "${PREFIX}${node}" \
        vtysh -c "clear bgp ipv4 unicast * soft in" >/dev/null
}

compile_capability() {
    local node=$1
    local asn=$2
    local capability=$3
    local destination=$4
    shift 4
    local peers=("$@")
    mkdir -p "${destination}"
    capture_received "${PREFIX}${node}" "${destination}/received" "${peers[@]}"

    if [ "${capability}" = "L" ]; then
        apply_legacy "${node}" "${asn}" "${destination}/legacy-policy.vty" "${peers[@]}"
        return
    fi

    if [ "${capability}" = "S" ]; then
        apply_legacy "${node}" "${asn}" "${destination}/legacy-policy.vty" "${peers[@]}"
    fi

    local received_args=()
    local peer filename
    for peer in "${peers[@]}"; do
        filename=$(peer_filename "${peer}")
        received_args+=(--received "${peer}=${destination}/received/${filename}.json")
    done
    local policy_args=(
        --vrps "${destination}/../routinator-validated-policy.json"
        --cases "${CASES}"
        --router-asn "${asn}"
        --output "${destination}/decisions.json"
        --fail-on-mismatch
        "${received_args[@]}"
    )
    if [ "${capability}" = "D" ]; then
        policy_args+=(--policy-output "${destination}/da-policy.vty")
    fi
    python3 "${POLICY_COMPILER}" "${policy_args[@]}"

    if [ "${capability}" = "D" ]; then
        apply_vty "${PREFIX}${node}" "${destination}/da-policy.vty"
        docker exec "${PREFIX}${node}" \
            vtysh -c "clear bgp ipv4 unicast * soft in" >/dev/null
    fi
}

route_present() {
    local container=$1
    local prefix=$2
    local origin=$3
    docker exec "${container}" \
        vtysh -c "show bgp ipv4 unicast ${prefix} json" 2>/dev/null \
        | jq -e --arg origin "${origin}" '
            any(.paths[]?;
                ((.aspath.string // .path // "") | split(" ") | last) == $origin)
        ' >/dev/null 2>&1
}

wait_route_state() {
    local container=$1
    local expected=$2
    local attempt
    for attempt in $(seq 1 120); do
        if route_present "${container}" 10.0.1.0/24 8075; then
            if [ "${expected}" = "present" ] \
                && route_present "${container}" 10.0.2.0/24 18403; then
                return
            fi
            if [ "${expected}" = "absent" ] \
                && ! route_present "${container}" 10.0.2.0/24 18403; then
                return
            fi
        fi
        sleep 0.25
    done
    docker exec "${container}" \
        vtysh -c "show bgp ipv4 unicast" >&2 || true
    echo "${container} did not reach delegated-route state ${expected}" >&2
    exit 1
}

capture_stage() {
    local stage_dir=$1
    capture_node t1 "${stage_dir}/t1" "${T1_UPSTREAM[@]}"
    capture_node t2 "${stage_dir}/t2" "${T2_UPSTREAM[@]}"
    capture_node t3 "${stage_dir}/t3" "${T3_UPSTREAM[@]}"
    capture_node sink "${stage_dir}/sink" "${SINK_UPSTREAM[@]}"
    docker exec "${ROUTINATOR}" \
        curl -fsS http://127.0.0.1:3333/json \
        > "${stage_dir}/routinator-validated-policy.json"
}

write_stage_metadata() {
    local stage_dir=$1
    local label=$2
    local publication=$3
    local pattern=$4
    local elapsed_ms=$5
    jq -n \
        --arg label "${label}" \
        --arg publication "${publication}" \
        --arg pattern "${pattern}" \
        --arg cases_file "${CASES}" \
        --argjson elapsed_ms "${elapsed_ms}" \
        '{label: $label, publication: $publication, pattern: $pattern,
          cases_file: $cases_file, elapsed_ms: $elapsed_ms}' \
        > "${stage_dir}/stage.json"
}

apply_pattern() {
    local pattern=$1
    local publication=$2
    local label=$3
    local stage_dir=$4
    mkdir -p "${stage_dir}"
    docker exec "${ROUTINATOR}" \
        curl -fsS http://127.0.0.1:3333/json \
        > "${stage_dir}/routinator-validated-policy.json"

    local start_ms end_ms delegated_state prefix_all_da
    start_ms=$(date +%s%3N)
    prefix_all_da=true

    local t1_cap=${pattern:0:1}
    local t2_cap=${pattern:1:1}
    local t3_cap=${pattern:2:1}

    compile_capability t1 65001 "${t1_cap}" "${stage_dir}/t1" "${T1_UPSTREAM[@]}"
    if [ "${t1_cap}" = "D" ]; then
        delegated_state=present
    else
        delegated_state=absent
        prefix_all_da=false
    fi
    wait_route_state "${T1}" "${delegated_state}"

    compile_capability t2 65002 "${t2_cap}" "${stage_dir}/t2" "${T2_UPSTREAM[@]}"
    if [ "${prefix_all_da}" = true ] && [ "${t2_cap}" = "D" ]; then
        delegated_state=present
    else
        delegated_state=absent
        prefix_all_da=false
    fi
    wait_route_state "${T2}" "${delegated_state}"

    compile_capability t3 65003 "${t3_cap}" "${stage_dir}/t3" "${T3_UPSTREAM[@]}"
    if [ "${prefix_all_da}" = true ] && [ "${t3_cap}" = "D" ]; then
        delegated_state=present
    else
        delegated_state=absent
    fi
    wait_route_state "${T3}" "${delegated_state}"
    wait_route_state "${SINK}" "${delegated_state}"

    end_ms=$(date +%s%3N)
    capture_stage "${stage_dir}"

    # Recompute shadow decisions from the final pre-policy view.  D decisions
    # were already the inputs used to install each router's policy.
    if [ "${t1_cap}" = "S" ]; then
        compile_capability t1 65001 S "${stage_dir}/t1" "${T1_UPSTREAM[@]}"
    fi
    if [ "${t2_cap}" = "S" ]; then
        compile_capability t2 65002 S "${stage_dir}/t2" "${T2_UPSTREAM[@]}"
    fi
    if [ "${t3_cap}" = "S" ]; then
        compile_capability t3 65003 S "${stage_dir}/t3" "${T3_UPSTREAM[@]}"
    fi

    write_stage_metadata \
        "${stage_dir}" "${label}" "${publication}" "${pattern}" \
        "$((end_ms - start_ms))"

    local attempt
    for attempt in $(seq 1 30); do
        capture_stage "${stage_dir}"
        if python3 "${SUMMARIZER}" --stage-dir "${stage_dir}"; then
            return
        fi
        sleep 0.5
    done
    python3 "${SUMMARIZER}" --stage-dir "${stage_dir}" || true
    echo "staged assertions failed for ${label} (${pattern})" >&2
    exit 1
}

publish_fallback() {
    docker exec "${KRILL}" krillc roas update -c testbed \
        --add "10.0.0.0/16 => 64501" \
        --add "10.0.1.0/24 => 8075" >/dev/null
    wait_routinator_query '
        (.roas | length) == 2 and
        any(.roas[]?; .prefix == "10.0.0.0/16" and .asn == "AS64501") and
        any(.roas[]?; .prefix == "10.0.1.0/24" and .asn == "AS8075")
    '
    wait_legacy_view
}

publish_open_policy() {
    docker exec "${KRILL}" krillc roas update -c testbed \
        --add "10.0.0.0/16, 16-24 => 64501 inclusive" >/dev/null
    wait_routinator_query '
        any(.roas[]?; .prefix == "10.0.0.0/16" and
            .asn == "AS64501" and .inclusivity == "inclusive")
    '
    wait_legacy_view
}

withdraw_open_policy() {
    docker exec "${KRILL}" krillc roas update -c testbed \
        --remove "10.0.0.0/16, 16-24 => 64501 inclusive" >/dev/null
    wait_routinator_query '
        (.roas | length) == 2 and
        all(.roas[]?; .inclusivity != "inclusive")
    '
    wait_legacy_view
}

run_transition_trials() {
    local run_dir=$1
    local trials=$2
    local csv="${run_dir}/transition-trials.csv"
    printf 'trial,transition,pattern,milliseconds,passed,stage_dir\n' > "${csv}"
    local trial transition pattern label stage_dir start_ms end_ms passed
    for trial in $(seq 1 "${trials}"); do
        for transition in rollback upgrade; do
            if [ "${transition}" = "rollback" ]; then
                pattern=LLL
            else
                pattern=DDD
            fi
            label=$(printf 'transition-%02d-%s' "${trial}" "${transition}")
            stage_dir="${run_dir}/transitions/${label}"
            start_ms=$(date +%s%3N)
            apply_pattern "${pattern}" dual "${label}" "${stage_dir}"
            end_ms=$(date +%s%3N)
            if jq -e '.passed == true' "${stage_dir}/checks.json" >/dev/null; then
                passed=true
            else
                passed=false
            fi
            printf '%s,%s,%s,%s,%s,%s\n' \
                "${trial}" "${transition}" "${pattern}" \
                "$((end_ms - start_ms))" "${passed}" \
                "${stage_dir#${run_dir}/}" >> "${csv}"
        done
    done
}

run_experiment() {
    local trials=$1
    ensure_images
    clean_lab_state

    local run_id run_dir token
    run_id=$(date -u +%Y%m%dT%H%M%SZ)
    run_dir="${E2E_DIR}/outputs/staged-${run_id}"
    mkdir -p "${run_dir}/stages" "${run_dir}/transitions"
    ln -sfn "staged-${run_id}" "${E2E_DIR}/outputs/latest-staged"

    token=$(openssl rand -hex 24)
    log "starting isolated Krill, legacy-safe Routinator, and 12-node FRR topology"
    start_lab "${token}"
    wait_all_bgp

    {
        docker exec "${KRILL}" krill --version
        docker exec "${ROUTINATOR}" routinator --version
        docker exec "${T1}" /usr/lib/frr/bgpd --version | head -1
        docker version --format 'Docker {{.Server.Version}}'
        printf 'transition_trials=%s\n' "${trials}"
    } > "${run_dir}/environment.txt"
    (
        cd "${E2E_DIR}"
        find \
            scripts/run-staged-deployment.sh \
            scripts/build-staged-images.sh \
            src/staged_policy.py \
            src/summarize_staged.py \
            config/staged \
            config/krill/krill.conf.template \
            patches/routinator-legacy-safe-rtr.patch \
            -type f -print0 \
            | LC_ALL=C sort -z \
            | xargs -0 sha256sum
    ) > "${run_dir}/source.sha256"
    git -C "${E2E_DIR}" status --short -- . \
        > "${run_dir}/git-status.txt"

    log "publishing conservative conventional fallback"
    publish_fallback
    apply_pattern LLL conventional conventional-LLL \
        "${run_dir}/stages/00-conventional-LLL"

    log "adding the signed open policy while retaining the conventional fallback"
    publish_open_policy
    apply_pattern LLL dual dual-LLL "${run_dir}/stages/01-dual-LLL"
    apply_pattern SSS dual dual-SSS "${run_dir}/stages/02-dual-SSS"

    local index=3 pattern
    for pattern in DLL LDL LLD DDL DLD LDD DDD; do
        apply_pattern "${pattern}" dual "dual-${pattern}" \
            "$(printf '%s/stages/%02d-dual-%s' "${run_dir}" "${index}" "${pattern}")"
        index=$((index + 1))
    done

    log "running ${trials} full-path upgrade/rollback trials"
    run_transition_trials "${run_dir}" "${trials}"

    apply_pattern LLL dual rollback-LLL \
        "$(printf '%s/stages/%02d-rollback-LLL' "${run_dir}" "${index}")"
    index=$((index + 1))
    withdraw_open_policy
    apply_pattern LLL conventional withdraw-LLL \
        "$(printf '%s/stages/%02d-withdraw-LLL' "${run_dir}" "${index}")"

    python3 "${SUMMARIZER}" --run-dir "${run_dir}" \
        --output "${run_dir}/summary.json"
    log "staged-deployment experiment complete: ${run_dir}"
}

case "${1:-experiment}" in
    experiment)
        run_experiment "${TRANSITION_TRIALS}"
        ;;
    smoke)
        run_experiment "${STAGED_SMOKE_TRIALS:-1}"
        ;;
    status)
        docker ps -a --filter "name=${PREFIX}" \
            --format '{{.Names}}\t{{.Status}}\t{{.Image}}'
        ;;
    down)
        cleanup_containers
        ;;
    clean)
        clean_lab_state
        ;;
    *)
        echo "usage: $0 [experiment|smoke|status|down|clean]" >&2
        exit 2
        ;;
esac
