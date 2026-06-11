from incalmo.core.services import EnvironmentStateService
from incalmo.core.agents import ScanAgent

def test_scan_agent():
    print("Starting ScanAgent tests...")

    # Initialize the environment state service
    env_service = EnvironmentStateService(attacker_ip="127.0.0.1")

    # Initialize the ScanAgent
    agent = ScanAgent(env_service=env_service)

    # Scan localhost (127.0.0.1); can be tested without a real target machine
    print("\n-- Test 1: scan localhost --")
    result = agent.run(target="127.0.0.1", is_external=True)
    print(f"Scan result: {result['message']}")

    # Check whether the environment state service was updated
    all_hosts = env_service.get_all_hosts()
    print(f"Host count in the environment state service: {len(all_hosts)}")

    if all_hosts:
        host = all_hosts[0]
        print(f"Host IP: {host.ip}")
        print(f"Open ports: {host.get_open_ports()}")
        print(f"Vulnerabilities found: {[v.cve_id for v in host.vulnerabilities]}")

    # View the network summary
    summary = env_service.get_network_summary()
    print(f"\nNetwork summary: {summary}")

    print("\nOK ScanAgent test complete, ready for phase 4")

if __name__ == "__main__":
    test_scan_agent()
