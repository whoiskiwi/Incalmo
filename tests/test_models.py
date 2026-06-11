from incalmo.core.models import (
    Vulnerability, Service, Credential,
    Host, Subnet, NetworkState
)

def test_models():
    print("Starting data model tests...")

    # -- Test 1: create a vulnerability object --
    vuln = Vulnerability(
        cve_id="CVE-2017-5638",
        service="apache-struts",
        port=8080,
        exploit_available=True,
        exploit_path="exploit/multi/http/struts2_content_type_ognl"
    )
    print(f"OK vulnerability object: {vuln.cve_id}")

    # -- Test 2: create a service object --
    service = Service(
        port=8080,
        name="http",
        version="2.3.15"
    )
    print(f"OK service object: {service.name}:{service.port}")

    # -- Test 3: create a host object --
    host = Host(
        ip="10.0.0.2",
        is_external=True,
        services=[service],
        vulnerabilities=[vuln]
    )
    print(f"OK host object: {host.ip}, "
          f"exploitable vulns: {len(host.get_exploitable_vulnerabilities())}")

    # -- Test 4: create a network state --
    state = NetworkState(
        attacker_ip="10.0.0.1",
        goal_data_paths=["/var/db/ssn_data.txt"]
    )
    state.add_host(host)

    # Verify queries
    external = state.get_external_hosts()
    print(f"OK external hosts: {[h.ip for h in external]}")

    compromised = state.get_compromised_hosts()
    print(f"OK compromised hosts (before): {[h.ip for h in compromised]}")

    # -- Test 5: mark a host as compromised --
    state.mark_compromised("10.0.0.2")
    compromised = state.get_compromised_hosts()
    print(f"OK compromised hosts (after): {[h.ip for h in compromised]}")

    # -- Test 6: add a credential --
    cred = Credential(
        username="admin",
        password="secret123",
        found_on_host="10.0.0.2",
        found_at_path="/etc/app/config.yml"
    )
    state.add_credential(cred)
    state.add_credential(cred)  # duplicate add, should only be stored once
    print(f"OK credential count (deduped): {len(state.get_all_credentials())}")

    print("\nOK all data model tests passed, ready for phase 2")

if __name__ == "__main__":
    test_models()
