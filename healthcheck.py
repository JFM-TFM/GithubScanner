import httpx
from os import getenv

HEALTHCHECK_URL = getenv("HEALTHCHECK_URL")
data = {}

try:
    response = httpx.post(HEALTHCHECK_URL, json=data)
    response.raise_for_status() # Raise an exception for 4xx/5xx responses
    print(f"Status Code: {response.status_code}")
    print("Response JSON:")
    print(response.json())

except httpx.HTTPStatusError as e:
    print(f"HTTP error occurred: {e.response.status_code}")
    
except httpx.RequestError as e:
    print(f"An error occurred while requesting: {e}")