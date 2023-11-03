from flask import Flask, request, jsonify, abort
from pymongo import MongoClient
from datetime import datetime, timedelta
import secrets
import string
import time

config = {
    "mongodb_uri": "mongodb://root:Shohp8sa!@db1.sinimustaahallitustavastaan.org:27017,db2.sinimustaahallitustavastaan.org:27017,db3.sinimustaahallitustavastaan.org:27017/?replicaSet=rs0&readPreference=nearest&authMechanism=DEFAULT",
    "mongodb_section": "attack_system"
}

app = Flask(__name__)

# MongoDB connection
client = MongoClient(config.get("mongodb_uri"))
db = client[config.get("mongodb_section")]

def generate_random_token():
    # Define characters to use for generating the token
    characters = string.ascii_letters + string.digits
    token_length = 32

    # Create a random seed using the current time
    current_time = str(time.time()).encode()
    random_seed = secrets.token_bytes(16)  # 16 bytes for a good random seed

    # Set the random seed for secrets module
    secrets.SystemRandom().seed(current_time + random_seed)

    # Generate the random token
    random_token = ''.join(secrets.choice(characters) for _ in range(token_length))

    return random_token

@app.route("/register/", methods=["POST"])
def register():
    data = request.get_json()
    
    ip_address = data.get('ip_address')
    
    token = generate_random_token()
    
    start_time = datetime.now()
    
    db.servers.insert_one({"ip": ip_address, "token": token, "start_time": start_time})
    
    response = {"token": token}
    
    return jsonify(response)


# API endpoint for adding attack information
@app.route('/attacks/', methods=['POST'])
def add_attack():
    token = request.headers.get('Token')
    
    token_exists = not (db.servers.find_one({"token": token}) is None)
    
    if not token_exists:
        abort(401)
    
    data = request.get_json()

    attack_data = data.get("attacks")

    # Store the attack information in MongoDB
    for attack in attack_data:
        db.logs.insert_one({"server_token": token, "attacker_ip": attack.get("ip"), "attack_time": attack.get("time"), "text": attack.get("text")})

    return jsonify({"message": "Attack information added successfully."}), 200

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)

