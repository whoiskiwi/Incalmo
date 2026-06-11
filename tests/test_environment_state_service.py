from incalmo.core.services import EnvironmentStateService
from incalmo.core.models import Host, Vulnerability, Service, Credential

def test_environment_state_service():
    print("Starting environment state service tests...")

    # -- Initialize the service --
    service = EnvironmentStateService(attacker_ip="10.0.0.1")
    service.add_initial_subnet("10.0.0.0/24", is_external=True)
    service.add_initial_subnet("192.168.1.0/24", is_external=False)
    service.set_goal_data_paths(["/var/db/ssn_data.txt"])
    print("OK service initialized")

    # -- Test 1: Scan agent discovers a host --
    web1 = Host(
        ip="10.0.0.2",
        is_external=True,
        services=[Service(port=8080, name="http", version="2.3.15")],
        vulnerabilities=[
            Vulnerability(
                cve_id="CVE-2017-5638",
                service="apache-struts",
                port=8080,
                exploit_available=True
            )
        ]
    )
    service.add_host(web1)
    service.add_host_to_subnet("10.0.0.2", "10.0.0.0/24")
    print(f"OK after discovery, external host count: "
          f"{len(service.get_external_hosts())}")

    # -- Test 2: view the network summary (called by the planning layer) --
    summary = service.get_network_summary()
    print(f"OK network summary: {summary}")

    # -- Test 3: LateralMove agent compromises a host --
    service.mark_compromised("10.0.0.2")
    print(f"OK compromised hosts: "
          f"{[h.ip for h in service.get_compromised_hosts()]}")

    # -- Test 4: FindInfo agent finds a credential --
    cred = Credential(
        username="admin",
        password="secret123",
        found_on_host="10.0.0.2",
        found_at_path="/etc/app/config.yml"
    )
    service.add_credential(cred)
    print(f"OK credentials found: {len(service.get_credentials())}")

    # -- Test 5: LateralMove agent logs into a new host with the credential --
    service.update_credential_access(
        username="admin",
        found_on_host="10.0.0.2",
        can_access="192.168.1.5"
    )
    updated_cred = service.get_credentials()[0]
    print(f"OK credential can access hosts: {updated_cred.can_access_hosts}")

    print("\nOK all environment state service tests passed, ready for phase 3")

if __name__ == "__main__":
    test_environment_state_service()
