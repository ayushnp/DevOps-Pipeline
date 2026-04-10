import json
import os
import sys
from google.cloud import secretmanager

def rotate_gcp_secret(secret_id):
    client = secretmanager.SecretManagerServiceClient()
    project_id = "ci-cd-pipeline-492918" # Replace with your ID
    secret_path = f"projects/{project_id}/secrets/{secret_id}"
    
    # In a real demo, generate a new random string or API key here
    new_secret_value = "ROTATED_VALUE_BY_JENKINS_" + os.popen('hostname').read().strip()
    
    client.add_secret_version(
        request={"parent": secret_path, "payload": {"data": new_secret_value.encode("UTF-8")}}
    )
    print(f"Successfully rotated secret: {secret_id}")

if __name__ == "__main__":
    report_path = sys.argv[1]
    if os.path.exists(report_path):
        with open(report_path) as f:
            data = json.load(f)
            # Find all unique leaked rules/secrets
            unique_leaks = {leak['RuleID'] for leak in data}
            for rule in unique_leaks:
                # We assume secret name in GCP matches Gitleaks RuleID
                # For demo, we rotate our 'DOCKERHUB_PASS'
                rotate_gcp_secret("DOCKERHUB_PASS")