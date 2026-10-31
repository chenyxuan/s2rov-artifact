#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# Reuse the accepted two-lane harness's topology, live-state probes, and trial
# record format. Its main dispatch is guarded when sourced.
source "${SCRIPT_DIR}/run-churn-experiment.sh"

CONTROL_SUMMARIZER="${E2E_DIR}/src/summarize_churn_controls.py"
CONTROL_TRIALS=${CONTROL_TRIALS:-30}
CONTROL_BLOCK_SIZE=${CONTROL_BLOCK_SIZE:-3}
CONTROL_RANDOM_SEED=${CONTROL_RANDOM_SEED:-20260823}
CHURN_TRIALS=${CONTROL_TRIALS}
KEEPALIVE_POLICY="10.255.255.0/24 => 64501"

BGP_ONLY_TRIAL=0
PREPUBLISHED_EXACT_TRIAL=0
BLOCK_ORDER=""
SETUP_CSV=""

wait_relevant_routinator_policy() {
    local mode=$1
    local origin=$2
    local output=$3
    local attempt document
    for attempt in $(seq 1 1800); do
        document=$(docker exec "${ROUTINATOR}" \
            curl -fsS http://127.0.0.1:3333/json 2>/dev/null || true)
        if jq -e \
            --arg mode "${mode}" \
            --argjson origin "${origin}" '
                def asnum: tostring | sub("^AS"; "") | tonumber;
                [.roas[]? | select(
                    .prefix == "10.0.10.0/24"
                    or .prefix == "10.0.0.0/16"
                )] as $relevant
                | if $mode == "bgp_only" then
                    ($relevant | length) == 0
                  elif $mode == "exact" then
                    ($relevant | length) == 1
                    and any($relevant[];
                        .prefix == "10.0.10.0/24"
                        and (.asn | asnum) == $origin
                        and .inclusivity == null)
                  elif $mode == "prepublished_exact" then
                    ($relevant | length) == 2
                    and any($relevant[];
                        .prefix == "10.0.10.0/24"
                        and (.asn | asnum) == 8075
                        and .inclusivity == null)
                    and any($relevant[];
                        .prefix == "10.0.10.0/24"
                        and (.asn | asnum) == 18403
                        and .inclusivity == null)
                  elif $mode == "da" then
                    ($relevant | length) == 1
                    and any($relevant[];
                        .prefix == "10.0.0.0/16"
                        and (.asn | asnum) == 64501
                        and .minLength == 16
                        and .maxLength == 24
                        and .inclusivity == "inclusive")
                  else false end
            ' <<< "${document}" >/dev/null 2>&1; then
            printf '%s\n' "${document}" > "${output}"
            return 0
        fi
        sleep 0.1
    done
    echo "Routinator did not converge to ${mode}" >&2
    return 1
}

initialize_repository_keepalive() {
    local directory=$1
    local attempt document
    mkdir -p "${directory}"
    docker exec "${KRILL}" krillc roas update -c testbed \
        --add "${KEEPALIVE_POLICY}" >/dev/null
    SETUP_SIGNED_TRANSACTIONS=$((SETUP_SIGNED_TRANSACTIONS + 1))
    SETUP_ENTRY_CHANGES=$((SETUP_ENTRY_CHANGES + 1))
    for attempt in $(seq 1 1800); do
        document=$(docker exec "${ROUTINATOR}" \
            curl -fsS http://127.0.0.1:3333/json 2>/dev/null || true)
        if jq -e '
            any(.roas[]?;
                .prefix == "10.255.255.0/24"
                and .asn == "AS64501"
                and .inclusivity == null)
        ' <<< "${document}" >/dev/null 2>&1; then
            printf '%s\n' "${document}" \
                > "${directory}/routinator-vrps.json"
            docker exec "${KRILL}" krillc roas list -c testbed \
                > "${directory}/krill-roas.txt"
            return 0
        fi
        sleep 0.1
    done
    echo "Routinator did not validate the unrelated repository keepalive" >&2
    return 1
}

wait_relevant_rtr_policy() {
    local mode=$1
    local origin=$2
    local output=$3
    local attempt document
    for attempt in $(seq 1 1800); do
        document=$(docker exec "${COLLECTOR}" \
            vtysh -c "show rpki prefix-table json" 2>/dev/null || true)
        if jq -e \
            --arg mode "${mode}" \
            --arg prefix "${PREFIX_ADDRESS}" \
            --argjson origin "${origin}" '
                [.prefixes[]? | select(
                    .prefix == $prefix
                    and .prefixLenMin == 24
                    and .prefixLenMax == 24
                )] as $relevant
                | if $mode == "exact" then
                    ($relevant | length) == 1
                    and any($relevant[]; .asn == $origin)
                  elif $mode == "prepublished_exact" then
                    ($relevant | length) == 2
                    and any($relevant[]; .asn == 8075)
                    and any($relevant[]; .asn == 18403)
                  else false end
            ' <<< "${document}" >/dev/null 2>&1; then
            printf '%s\n' "${document}" > "${output}"
            return 0
        fi
        sleep 0.1
    done
    echo "FRR RTR table did not converge to ${mode}" >&2
    return 1
}

wait_bgp_only_route() {
    local origin=$1
    local output=$2
    local attempt document
    for attempt in $(seq 1 3600); do
        document=$(docker exec "${COLLECTOR}" \
            vtysh -c "show bgp ipv4 unicast ${PREFIX} json" 2>/dev/null || true)
        if jq -e \
            --argjson origin "${origin}" '
                any(.paths[]?;
                    (.aspath.string | split(" ")
                        | map(select(length > 0)) | last | tonumber) == $origin
                    and (.locPrf // 100) == 100
                    and ((.community.string // "") | length) == 0)
            ' <<< "${document}" >/dev/null 2>&1; then
            printf '%s\n' "${document}" > "${output}"
            return 0
        fi
        sleep "${POLL_SECONDS}"
    done
    docker exec "${COLLECTOR}" \
        vtysh -c "show bgp ipv4 unicast ${PREFIX}" >&2 || true
    echo "BGP-only route from AS${origin} did not enter the Loc-RIB cleanly" >&2
    return 1
}

replace_signed_policy() {
    local target=$1
    local directory=$2
    local previous=${POLICY_MODE}
    local -a args=()
    local changes=0
    local reset_collector=false
    mkdir -p "${directory}"

    if [ "${previous}" != "${target}" ]; then
        case "${previous}" in
            none|bgp_only) ;;
            exact)
                args+=(--remove "${PREFIX} => ${POLICY_ORIGIN}")
                changes=$((changes + 1))
                ;;
            da)
                args+=(--remove "${OPEN_POLICY}")
                changes=$((changes + 1))
                reset_collector=true
                ;;
            prepublished_exact)
                args+=(--remove "${PREFIX} => 8075")
                args+=(--remove "${PREFIX} => 18403")
                changes=$((changes + 2))
                ;;
            *)
                echo "unsupported current policy mode: ${previous}" >&2
                return 1
                ;;
        esac

        case "${target}" in
            bgp_only) ;;
            exact)
                args+=(--add "${PREFIX} => ${CURRENT_ORIGIN}")
                changes=$((changes + 1))
                ;;
            da)
                args+=(--add "${OPEN_POLICY}")
                changes=$((changes + 1))
                ;;
            prepublished_exact)
                args+=(--add "${PREFIX} => 8075")
                args+=(--add "${PREFIX} => 18403")
                changes=$((changes + 2))
                ;;
            *)
                echo "unsupported target policy mode: ${target}" >&2
                return 1
                ;;
        esac

        if [ "${#args[@]}" -gt 0 ]; then
            docker exec "${KRILL}" krillc roas update -c testbed \
                "${args[@]}" >/dev/null
            SETUP_SIGNED_TRANSACTIONS=$((SETUP_SIGNED_TRANSACTIONS + 1))
            SETUP_ENTRY_CHANGES=$((SETUP_ENTRY_CHANGES + changes))
        fi
    fi

    POLICY_MODE=${target}
    if [ "${target}" = "exact" ]; then
        POLICY_ORIGIN=${CURRENT_ORIGIN}
    elif [ "${target}" = "da" ]; then
        POLICY_ORIGIN=64501
    else
        POLICY_ORIGIN=0
    fi

    wait_relevant_routinator_policy "${target}" "${CURRENT_ORIGIN}" \
        "${directory}/routinator-vrps.json"

    if [ "${reset_collector}" = "true" ]; then
        docker restart "${COLLECTOR}" >/dev/null
        wait_bgp_sessions
    fi

    case "${target}" in
        bgp_only)
            apply_vty_file "${CHURN_CONFIG}/frr/bgp-only-policy.vty"
            wait_bgp_only_route "${CURRENT_ORIGIN}" \
                "${directory}/active-rib.json"
            ;;
        exact)
            wait_relevant_rtr_policy exact "${CURRENT_ORIGIN}" \
                "${directory}/frr-rtr-prefix-table.json"
            apply_vty_file "${CHURN_CONFIG}/frr/exact-policy.vty"
            wait_route_present "${CURRENT_ORIGIN}" 300 "65000:10" \
                "${directory}/active-rib.json"
            ;;
        prepublished_exact)
            wait_relevant_rtr_policy prepublished_exact "${CURRENT_ORIGIN}" \
                "${directory}/frr-rtr-prefix-table.json"
            apply_vty_file "${CHURN_CONFIG}/frr/exact-policy.vty"
            wait_route_present "${CURRENT_ORIGIN}" 300 "65000:10" \
                "${directory}/active-rib.json"
            ;;
        da)
            python3 "${AGENT}" evaluate \
                --vrps "${directory}/routinator-vrps.json" \
                --cases "${CHURN_CONFIG}/cases.json" \
                --output "${directory}/decisions.json" \
                --policy-output "${directory}/frr-policy.vty" \
                --fail-on-mismatch
            apply_vty_file "${directory}/frr-policy.vty"
            wait_route_present "${CURRENT_ORIGIN}" 200 "65000:20" \
                "${directory}/active-rib.json"
            DA_POLICY_DIGEST=$(policy_digest \
                "${directory}/routinator-vrps.json")
            ;;
    esac
    docker exec "${KRILL}" krillc roas list -c testbed \
        > "${directory}/krill-roas.txt"
}

run_static_control_trial() {
    local lane=$1
    local block=$2
    local block_trial=$3
    local trial expected_state expected_decision expected_preference expected_community expected_mode
    if [ "${lane}" = "bgp_only" ]; then
        BGP_ONLY_TRIAL=$((BGP_ONLY_TRIAL + 1))
        trial=${BGP_ONLY_TRIAL}
        expected_state=BGPOnly
        expected_decision=NotFound
        expected_preference=100
        expected_community=""
        expected_mode=baseline
    elif [ "${lane}" = "prepublished_exact" ]; then
        PREPUBLISHED_EXACT_TRIAL=$((PREPUBLISHED_EXACT_TRIAL + 1))
        trial=${PREPUBLISHED_EXACT_TRIAL}
        expected_state=Valid
        expected_decision=Valid
        expected_preference=300
        expected_community=65000:10
        expected_mode=baseline
    else
        echo "unsupported static lane: ${lane}" >&2
        return 1
    fi
    GLOBAL_ORDER=$((GLOBAL_ORDER + 1))

    local old_origin=${CURRENT_ORIGIN}
    local new_origin
    new_origin=$(other_origin "${old_origin}")
    local directory
    directory=$(printf '%s/raw/%s/trial-%02d' "${OUTPUT}" "${lane}" "${trial}")
    mkdir -p "${directory}"
    capture_rib "${directory}/before-rib.json"
    capture_routinator "${directory}/before-routinator.json"

    local switch_start withdrawn_ns announce_start observed_ns final_ns
    switch_start=$(monotonic_ns)
    event "${lane}" "${trial}" switch_requested "${switch_start}"
    set_origin_announcement "${old_origin}" false
    wait_route_absent "${directory}/after-withdraw-rib.json"
    withdrawn_ns=$(monotonic_ns)
    event "${lane}" "${trial}" old_route_absent "${withdrawn_ns}"
    announce_start=$(monotonic_ns)
    set_origin_announcement "${new_origin}" true
    wait_received_origin "${new_origin}" \
        "${directory}/new-origin-received.json"
    observed_ns=$(monotonic_ns)
    event "${lane}" "${trial}" new_route_in_adj_rib_in "${observed_ns}"

    capture_routinator "${directory}/final-routinator.json"
    local digest
    digest=$(policy_digest "${directory}/final-routinator.json")
    write_case "${new_origin}" "${expected_decision}" \
        "${directory}/final-case.json"
    evaluate_one "${expected_mode}" \
        "${directory}/final-routinator.json" \
        "${directory}/final-case.json" \
        "${directory}/final-decision.json"
    if [ "${lane}" = "bgp_only" ]; then
        wait_bgp_only_route "${new_origin}" "${directory}/final-rib.json"
    else
        wait_route_present "${new_origin}" "${expected_preference}" \
            "${expected_community}" "${directory}/final-rib.json"
    fi
    final_ns=$(monotonic_ns)
    event "${lane}" "${trial}" route_accepted "${final_ns}"
    docker exec "${KRILL}" krillc roas list -c testbed \
        > "${directory}/krill-roas.txt"

    local unavailable_ms end_to_end_ms bgp_ms
    unavailable_ms=$(elapsed_ms "${withdrawn_ns}" "${final_ns}")
    end_to_end_ms=$(elapsed_ms "${switch_start}" "${final_ns}")
    bgp_ms=$(elapsed_ms "${announce_start}" "${observed_ns}")
    append_trial \
        "${GLOBAL_ORDER}" "${lane}" "${trial}" "${block}" "${block_trial}" \
        "${old_origin}" "${new_origin}" 0 0 \
        0.000 "${unavailable_ms}" "${end_to_end_ms}" "${bgp_ms}" \
        0.000 "${expected_state}" "${expected_preference}" "${digest}" \
        0.000 0.000 0.000
    write_trial_metadata \
        "${directory}" "${lane}" "${trial}" "${block}" \
        "${old_origin}" "${new_origin}" 0.000 "${unavailable_ms}" \
        "${end_to_end_ms}" "${expected_state}" "${expected_preference}" \
        0 "${digest}" 0.000 0.000 0.000
    CURRENT_ORIGIN=${new_origin}
    log "${lane} trial ${trial}/${CONTROL_TRIALS}: AS${old_origin}->AS${new_origin}, ${end_to_end_ms} ms"
}

generate_block_order() {
    local rounds=$1
    python3 - "${CONTROL_RANDOM_SEED}" "${rounds}" <<'PY'
import random
import sys

seed = int(sys.argv[1])
rounds = int(sys.argv[2])
rng = random.Random(seed)
arms = ["exact", "da", "bgp_only", "prepublished_exact"]
print("round,lane")
for round_id in range(1, rounds + 1):
    order = arms.copy()
    rng.shuffle(order)
    for lane in order:
        print(f"{round_id},{lane}")
PY
}

write_control_protocol() {
    local rounds=$1
    jq -n \
        --arg prefix "${PREFIX}" \
        --argjson trials_per_lane "${CONTROL_TRIALS}" \
        --argjson block_size "${CONTROL_BLOCK_SIZE}" \
        --argjson rounds "${rounds}" \
        --argjson random_seed "${CONTROL_RANDOM_SEED}" \
        --argjson frr_state_query_interval_s "${POLL_SECONDS}" \
        --argjson setup_signed_update_transactions "${SETUP_SIGNED_TRANSACTIONS}" \
        --argjson setup_authorization_entry_changes "${SETUP_ENTRY_CHANGES}" '
        {
            design:"reactive break-before-make origin handoff with matched controls",
            prefix:$prefix,
            origins:[8075,18403],
            arms:["exact","da","bgp_only","prepublished_exact"],
            trials_per_lane:$trials_per_lane,
            randomized_complete_block_rounds:$rounds,
            trials_per_block:$block_size,
            block_order_file:"block-order.csv",
            random_seed:$random_seed,
            randomization_unit:"three-trial block within each complete four-arm round",
            setup_excluded_from_transition_metrics:true,
            setup_file:"setup.csv",
            environment_file:"environment.txt",
            source_hash_file:"source.sha256",
            git_status_file:"git-status.txt",
            repository_keepalive:"10.255.255.0/24 => AS64501 (unrelated to the measured prefix)",
            setup_signed_update_transactions:$setup_signed_update_transactions,
            setup_authorization_entry_changes:$setup_authorization_entry_changes,
            handoff_updates:{exact:1,da:0,bgp_only:0,prepublished_exact:0},
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

capture_control_environment() {
    {
        docker exec "${KRILL}" krill --version
        docker exec "${ROUTINATOR}" routinator --version
        docker exec "${COLLECTOR}" /usr/lib/frr/bgpd --version | sed -n '1p'
        docker version --format 'Docker {{.Server.Version}}'
        uname -srmo
        lscpu | sed -n \
            -e '/^Architecture:/p' \
            -e '/^CPU(s):/p' \
            -e '/^On-line CPU(s) list:/p' \
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
            scripts/run-churn-experiment.sh \
            scripts/run-churn-controls.sh \
            src/daroa_agent.py \
            src/summarize_churn.py \
            src/summarize_churn_controls.py \
            config/krill/krill.conf.template \
            config/churn/cases.json \
            config/churn/frr/collector.conf \
            config/churn/frr/exact-policy.vty \
            config/churn/frr/bgp-only-policy.vty \
            config/churn/frr/origin-a.conf \
            config/churn/frr/origin-b.conf
    ) > "${OUTPUT}/source.sha256"
    git -C "${E2E_DIR}" status --short -- . \
        > "${OUTPUT}/git-status.txt"
}

run_control_experiment() {
    if ! [[ "${CONTROL_TRIALS}" =~ ^[1-9][0-9]*$ ]]; then
        echo "CONTROL_TRIALS must be a positive integer" >&2
        return 2
    fi
    if ! [[ "${CONTROL_BLOCK_SIZE}" =~ ^[1-9][0-9]*$ ]]; then
        echo "CONTROL_BLOCK_SIZE must be a positive integer" >&2
        return 2
    fi
    if [ $((CONTROL_TRIALS % CONTROL_BLOCK_SIZE)) -ne 0 ]; then
        echo "CONTROL_TRIALS must be divisible by CONTROL_BLOCK_SIZE" >&2
        return 2
    fi
    if ! [[ "${CONTROL_RANDOM_SEED}" =~ ^[0-9]+$ ]]; then
        echo "CONTROL_RANDOM_SEED must be a nonnegative integer" >&2
        return 2
    fi

    ensure_images
    clean_lab_state
    local run_id
    run_id=$(date -u +%Y%m%dT%H%M%SZ)
    OUTPUT="${E2E_DIR}/outputs/controls-${run_id}"
    if ! mkdir "${OUTPUT}"; then
        echo "refusing to overwrite an existing controls output: ${OUTPUT}" >&2
        return 1
    fi
    mkdir -p "${OUTPUT}/setup" "${OUTPUT}/raw"
    ln -sfn "controls-${run_id}" "${E2E_DIR}/outputs/latest-controls"
    EVENTS="${OUTPUT}/events.jsonl"
    TRIAL_CSV="${OUTPUT}/trials.csv"
    BLOCK_ORDER="${OUTPUT}/block-order.csv"
    SETUP_CSV="${OUTPUT}/setup.csv"
    : > "${EVENTS}"
    printf 'global_order,lane,lane_trial,block,block_trial,from_origin,to_origin,signed_update_transactions,authorization_entry_changes,invalid_exposure_ms,unavailable_ms,end_to_end_ms,bgp_observation_ms,authorization_to_completion_ms,signed_request_to_routinator_ms,routinator_to_rtr_ms,rtr_to_enforcement_ms,final_state,final_action,final_local_preference,final_origin,policy_digest,passed\n' \
        > "${TRIAL_CSV}"
    printf 'block,round,lane,setup_ms\n' > "${SETUP_CSV}"

    local token
    token=$(openssl rand -hex 24)
    log "starting four-arm matched-control lab"
    start_lab "${token}"
    capture_control_environment
    start_monotonic_clock

    local bootstrap_start bootstrap_end bootstrap_ms
    bootstrap_start=$(monotonic_ns)
    initialize_repository_keepalive "${OUTPUT}/setup/repository-keepalive"
    bootstrap_end=$(monotonic_ns)
    bootstrap_ms=$(elapsed_ms "${bootstrap_start}" "${bootstrap_end}")
    printf '0,0,repository_keepalive,%s\n' "${bootstrap_ms}" \
        >> "${SETUP_CSV}"

    local rounds
    rounds=$((CONTROL_TRIALS / CONTROL_BLOCK_SIZE))
    generate_block_order "${rounds}" > "${BLOCK_ORDER}"

    local round lane block=0 block_trial setup_start setup_end setup_ms
    while IFS=, read -r round lane; do
        if [ "${round}" = "round" ]; then
            continue
        fi
        block=$((block + 1))
        setup_start=$(monotonic_ns)
        replace_signed_policy "${lane}" \
            "$(printf '%s/setup/block-%02d-%s' "${OUTPUT}" "${block}" "${lane}")"
        setup_end=$(monotonic_ns)
        setup_ms=$(elapsed_ms "${setup_start}" "${setup_end}")
        printf '%s,%s,%s,%s\n' "${block}" "${round}" "${lane}" "${setup_ms}" \
            >> "${SETUP_CSV}"
        for block_trial in $(seq 1 "${CONTROL_BLOCK_SIZE}"); do
            case "${lane}" in
                exact) run_exact_trial "${block}" "${block_trial}" ;;
                da) run_da_trial "${block}" "${block_trial}" ;;
                bgp_only|prepublished_exact)
                    run_static_control_trial "${lane}" "${block}" "${block_trial}"
                    ;;
                *)
                    echo "unknown block lane: ${lane}" >&2
                    return 1
                    ;;
            esac
        done
    done < "${BLOCK_ORDER}"

    write_control_protocol "${rounds}"
    capture_logs
    python3 "${CONTROL_SUMMARIZER}" \
        --run-dir "${OUTPUT}" \
        --output "${OUTPUT}/summary.json"
    rm -f "${OUTPUT}/FAILED"
    log "four-arm control experiment complete: ${OUTPUT}"
}

case "${1:-experiment}" in
    experiment)
        run_control_experiment
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
