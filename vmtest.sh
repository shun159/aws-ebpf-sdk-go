#!/usr/bin/env bash

set -euo pipefail

script="$(realpath "$0")"
readonly script

if [[ "${1:-}" = "--virt" ]]; then
    shift

    input="$1"
    shift

    # Use sudo if /dev/kvm isn't accessible by the current user.
    sudo=""
    if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
        sudo="sudo"
    fi
    readonly sudo

    testdir="$(dirname "$1")"
    output="$(mktemp -d --tmpdir=/var/tmp/)"
    printf -v cmd "%q " "$@"

    if [[ "$(stat -c '%t:%T' -L /proc/$$/fd/0)" == "1:3" ]]; then
        mkfifo "${output}/fake-stdin"
        exec 0<> "${output}/fake-stdin"
    fi

    for ((i = 0; i < 3; i++)); do
        if ! $sudo vmtest -k "${input}/bzImage" "
            insmod ${input}/ifb.ko &&
            insmod ${input}/sch_ingress.ko &&
            insmod ${input}/cls_bpf.ko &&
            lsmod | grep ifb &&
            cd ${input}/aws-ebpf-sdk-go/pkg/xdp &&
            ${cmd}"; then
            exit 23
        fi

        if [[ -e "${output}/status" ]]; then
            break
        fi

        if [[ -v CI ]]; then
            echo "Retrying test run due to qemu crash"
            continue
        fi

        exit 42
    done

    rc=$(<"${output}/status")
    $sudo rm -r "$output"
    exit $rc

elif [[ "${1:-}" = "--exec-test" ]]; then
    shift

    mount -t bpf bpf /sys/fs/bpf
    mount -t tracefs tracefs /sys/kernel/debug/tracing

    if [[ -f "/run/input/bpf/bpf_testmod/bpf_testmod.ko" ]]; then
        insmod "/run/input/bpf/bpf_testmod/bpf_testmod.ko"
    fi

    dmesg --clear
    rc=0
    "$@" || rc=$?
    dmesg
    echo $rc > "/run/output/status"
    exit $rc # this return code is "swallowed" by qemu
fi

if [[ -z "${1:-}" ]]; then
    echo "Expecting kernel version or path as first argument"
    exit 1
fi

readonly input="$(mktemp -d --tmpdir=/var/tmp/)"
readonly tmp_dir="${TMPDIR:-/var/tmp}"

fetch() {
    echo Fetching "${1}"
    pushd "${tmp_dir}" > /dev/null
    curl --no-progress-meter \
        -L -O --fail \
        --etag-compare "${1}.etag" \
        --etag-save "${1}.etag" \
        "https://github.com/cilium/ci-kernels/raw/${BRANCH:-master}/${1}"
    local ret=$?
    popd > /dev/null
    return $ret
}

export KERNEL_VERSION="${1}"

readonly kernel="linux-${1}.bz"
readonly selftests="linux-${1}-selftests-bpf.tgz"

fetch "${kernel}"
cp "${tmp_dir}/${kernel}" "${input}/bzImage"
cp "${PWD}/bzImage" "${input}/bzImage"
cp "${PWD}/ifb.ko" "${input}/ifb.ko"
cp "${PWD}/sch_ingress.ko" "${input}/sch_ingress.ko"
cp "${PWD}/cls_bpf.ko" "${input}/cls_bpf.ko"


mkdir "${input}/aws-ebpf-sdk-go"
cp -r `pwd` "${input}"

if fetch "${selftests}"; then
    echo "Decompressing selftests"
    mkdir "${input}/bpf"
    tar --strip-components=4 -xf "${tmp_dir}/${selftests}" -C "${input}/bpf"
else
    echo "No selftests found, disabling"
fi

shift

args=(./...)
if (( $# > 0 )); then
    args=("$@")
fi

export GOFLAGS=-mod=readonly
export CGO_ENABLED=0

echo Testing on "${kernel}"
GOTMPDIR=/var/tmp AWS_EBPF_SDK_LOG_FILE=/dev/null go test -exec "$script --virt $input" "${args[@]}" 
echo "Test successful on ${kernel}"

rm -r "${input}"
