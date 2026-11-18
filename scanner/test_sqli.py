
import requests

# Our local VulnScope application
url = "http://127.0.0.1:5000/lab/sqli"

# SQL injection test input
payload = "' OR '1'='1"

# Send the payload to our application
response = requests.get(
    url,
    params={"username": payload},
    timeout=5
)

# Read the server response
data = response.json()

print("SQL Injection Test Results")
print("--------------------------")
print("Payload:", payload)
print("Status Code:", response.status_code)
print("Users Found:", len(data["results"]))

# Check if the vulnerability exists
if len(data["results"]) == 3:
    print("SQL Injection vulnerability detected!")
else:
    print("Expected lab behavior not detected.")


# Test the secure endpoint
secure_url = "http://127.0.0.1:5000/lab/sqli-safe"

secure_response = requests.get(
    secure_url,
    params={"username": payload},
    timeout=5
)

secure_response.raise_for_status()
secure_data = secure_response.json()

print("\nSecure Endpoint Test")
print("--------------------")
print("Status Code:", secure_response.status_code)
print("Users Found:", len(secure_data["results"]))

if len(secure_data["results"]) == 0:
    print("PASS: SQL injection prevented!")
else:
    print("FAIL: Unexpected users returned!")
