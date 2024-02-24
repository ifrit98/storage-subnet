import requests
import argparse

def register_user(base_url, username: str, password: str):
    response = requests.post(f"{base_url}/register/", json={"username": username, "password": password})
    return response.json()

def get_access_token(base_url, username: str, password: str):
    data = {"username": username, "password": password}
    response = requests.post(f"{base_url}/token", data=data)
    return response.json()['access_token']

def upload_file(base_url, token: str, file_content: str):
    files = {"file": ("test.txt", file_content)}
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(f"{base_url}/uploadfiles/", files=files, headers=headers)
    return response.json()

def retrieve_user_data(base_url, token: str, file_hash: str):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{base_url}/retrieve/{file_hash}", headers=headers)
    return response.json()

# Add some fake users to the database
def test_create_fake_users():
    redis_db = get_database()

    # Create a new user
    fake_user_jane = UserInDB(
        username="janedoe",
        hashed_password=pwd_context.hash("password123"),
        seed="b6825ec6168f72e90b1244b1d2307433ad8394ad65b7ef4af10966bc103a39bf",
        wallet_name="janedoe",
        wallet_hotkey="default",
        wallet_mnemonic="ocean bean until sauce near place labor admit dismiss long asthma tunnel"
    )
    create_user(fake_user_jane)

    # Retrieve the user
    user = get_user("janedoe")
    assert user == fake_user_jane, "User doesn't match expected"

    fake_user_john = UserInDB(
            username="johndoe", 
            hashed_password=pwd_context.hash("example"), 
            seed="a6825ec6168f72e90b1244b1d2307433ad8394ad65b7ef4af10966bc103a39ae", 
            wallet_name = 'johndoe',   # should be equivalent to username for consistency
            wallet_hotkey = 'default', # can be default
            wallet_mnemonic = 'family bean until sauce near place labor admit dismiss long asthma tunnel' 
        )

    create_user(fake_user_john)
    user = get_user("johndoe")
    assert user == fake_user_john, "User doesn't match expected"


def main():
    parser = argparse.ArgumentParser(description="Test FastAPI application")
    parser.add_argument('--host', type=str, default='localhost', help='Host where the FastAPI app is running')
    parser.add_argument('--port', type=str, default='8000', help='Port on which the FastAPI app is running')
    args = parser.parse_args()

    base_url = f"http://{args.host}:{args.port}"

    username = "testuser"
    password = "testpassword"
    file_content = "This is a test string."

    print("Registering user...")
    register_response = register_user(base_url, username, password)
    print(register_response)

    print("Getting access token...")
    token = get_access_token(base_url, username, password)
    print("Access Token:", token)

    print("Uploading file...")
    upload_response = upload_file(base_url, token, file_content)
    print(upload_response)

    print("Retrieving file...")
    retrieved_data = retrieve_user_data(base_url, token, upload_response['file_hash'])
    print(retrieved_data)

if __name__ == "__main__":
    main()
