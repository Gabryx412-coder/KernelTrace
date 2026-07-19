//! Integration test del container awareness: esercita le funzioni di
//! parsing pubbliche per Docker, Podman e Kubernetes con path di cgroup
//! realistici, così come apparirebbero su un host reale.

use kerneltrace_agent::container::cgroups::extract_cgroup_path;
use kerneltrace_agent::container::docker::extract_docker_container_id;
use kerneltrace_agent::container::kubernetes::extract_kubernetes_pod_info;
use kerneltrace_agent::container::podman::extract_podman_container_id;

#[test]
fn recognizes_docker_container_from_realistic_cgroup_file() {
    let container_id = "a".repeat(64);
    let cgroup_contents = format!("0::/system.slice/docker-{container_id}.scope\n");

    let path = extract_cgroup_path(&cgroup_contents).expect("should extract path");
    let extracted_id = extract_docker_container_id(path).expect("should recognize docker container");

    assert_eq!(extracted_id, container_id);
}

#[test]
fn recognizes_podman_container_from_realistic_cgroup_file() {
    let container_id = "b".repeat(64);
    let cgroup_contents = format!("0::/machine.slice/libpod-{container_id}.scope\n");

    let path = extract_cgroup_path(&cgroup_contents).expect("should extract path");
    let extracted_id = extract_podman_container_id(path).expect("should recognize podman container");

    assert_eq!(extracted_id, container_id);
}

#[test]
fn recognizes_kubernetes_pod_from_realistic_cgroup_file() {
    let container_id = "c".repeat(64);
    let cgroup_contents = format!(
        "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod11111111_2222_3333_4444_555555555555.slice/cri-containerd-{container_id}.scope\n"
    );

    let path = extract_cgroup_path(&cgroup_contents).expect("should extract path");
    let info = extract_kubernetes_pod_info(path).expect("should recognize kubernetes pod");

    assert_eq!(info.pod_uid, "11111111-2222-3333-4444-555555555555");
    assert_eq!(info.container_id, Some(container_id));
}

#[test]
fn non_containerized_process_cgroup_does_not_match_any_runtime() {
    let cgroup_contents = "0::/user.slice/user-1000.slice/session-1.scope\n";
    let path = extract_cgroup_path(cgroup_contents).expect("should extract path");

    assert!(extract_docker_container_id(path).is_none());
    assert!(extract_podman_container_id(path).is_none());
    assert!(extract_kubernetes_pod_info(path).is_none());
}