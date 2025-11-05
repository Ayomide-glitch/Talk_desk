import os
from flask import Flask, request, jsonify
import uuid
from Utils.hash import verify
from Utils.OTP import generate_otp,verify_otp,send_otp_mail
from connections.Redis import r
from Models.queries import create_user,get_user,update_user
from Models.queries import create_message,admin_check_message,get_user_messages,get_message_by_id,mark_message_as_read
from dotenv import load_dotenv

from connections.postgres import connection

load_dotenv()

app = Flask(__name__)

#signup route
@app.route('/signup',methods=['POST'])
def signup():
    data = request.get_json()
    name = data.get('name')
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')

    try:
      create_user(name, username, email, password,role)
      return jsonify({'status':"User created successfully"}),200
    except ValueError:
        return jsonify({"error": "Invalid input or empty field(s)"}),500

#login route
@app.route('/login', methods=['POST'])
def login():

    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    user = get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # user = (user_id, name, username, email, password, role)
    user_id= user[0]
    hash_pw = user[4]
    role = user[5]

    if not verify(password, hash_pw):
        return jsonify({"error": "Invalid password"}), 401

    # Create session in Redis
    session_id = str(uuid.uuid4())
    r.hset(f"session:{session_id}", mapping={
        "user_id": user_id,
        "username": username,
        "role": role
    })
    r.setex(f"session:{session_id}", 3600)  # expires in 1 hour

    return jsonify({
        "message": "Login successful",
        "session_id": session_id,
        "role": role
    }), 200

#generation and sending of otp
@app.route("/generate_otp", methods=["POST"])
def generate_and_send_otp():
    session_id = request.headers.get("session_id")
    data = request.get_json()
    email = data.get("email")
    if not email or not session_id:
       return jsonify({"error": "Email and session ID required"}), 400

    otp = generate_otp(email)
    send_otp_mail(email, otp)

    return jsonify({"message": "OTP sent successfully"}), 200


@app.route("/message", methods=["POST"])
def send_message():
    session_id = request.headers.get("session_id")
    if not session_id:
        return jsonify({"error": "Session ID required"}), 400
    r.hgetall(f"session:{session_id}")

    data = request.get_json()
    email = data.get("email")
    otp = data.get("otp")
    sender_id = data.get("sender_id")
    subject = data.get("subject")
    content = data.get("content")
    message_id = str(uuid.uuid4())
    receiver_id = os.getenv("RECEIVER_ID")

    if not verify_otp(email, otp):
        return jsonify({"error": "Invalid or expired OTP"}), 403

    create_message(message_id,sender_id, receiver_id, subject, content, False)

    return jsonify({"message": "Message sent successfully"}), 201


@app.route("/messages", methods=["GET"])
def get_messages():
    session_id = request.headers.get("session_id")
    if not session_id:
        return jsonify({"error": "Session ID required or expired"}), 400

    session_data=r.hgetall(f"session:{session_id}")
    user_id = session_data.get("user_id")
    role = session_data.get("role")
    try:
      if role is "Admin":
        return admin_check_message()
      elif role is "User":
        return get_user_messages(user_id)
    except NameError:
      return jsonify({"error": str("Invalid role or spelling")}), 500
    finally:
      return jsonify({"message": "Message accessed successfully"}), 200


@app.route("/messages/<message_id>/reply", methods=["POST"])
def admin_reply_message(message_id):
    session_id = request.headers.get("session_id")
    if not session_id:
        return jsonify({"error": "Session ID required or expired"}), 400

    data = request.get_json()

    reply_subject = data.get("subject")
    reply_content = data.get("content")

    # Get session info from Redis
    session_data = r.hgetall(f"session:{session_id}")
    if not session_data:
        return jsonify({"error": "Session expired or invalid"}), 403

    role = session_data.get("role")
    admin_id = session_data.get("user_id")

    # Check if admin is allowed
    if role != "Admin":
        return jsonify({"error": "Access denied: Admins only"}), 403

    # Fetch the original message to get the user (sender)
    original_message = get_message_by_id(message_id)
    if not original_message:
        return jsonify({"error": "Original message not found"}), 404
    else:
        mark_message_as_read(message_id)


    # Create a new message as a reply
    reply_id = str(uuid.uuid4())  # new unique message ID
    receiver_id = original_message["sender_id"]  # send back to user

    try:
        create_message(
            message_id=reply_id,
            sender_id=admin_id,
            receiver_id=receiver_id,
            subject=reply_subject,
            content=reply_content,
            is_read=False
        )

        return jsonify({
            "message": "Reply sent successfully",
            "reply_id": reply_id
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/messages/<message_id>/close", methods=["PUT"])
def close_ticket(message_id):
    session_id = request.headers.get("session_id")

    session_data = r.hgetall(f"session:{session_id}")
    if not session_data:
        return jsonify({"error": "Session expired or invalid"}), 403
    role = session_data.get("role")

    if role != "Admin":
        return jsonify({"error": "Access denied: Admins only"}), 403
    try:
        with connection.cursor() as cursor:
            cursor.execute("""UPDATE desk_messages SET status = 'closed' WHERE message_id = %s""",(message_id,))
        connection.commit()
        return jsonify({"message": "Message ticket closed successfully"}), 200
    except ConnectionError:
        connection.rollback()
        return jsonify({"error": str("Ensure ticket is closed,if not rerun it")}), 500


@app.route('/update_user', methods=['PUT'])
def update_user():
    session_id = request.headers.get("session_id")

    # Get session info from Redis
    session_data = r.hgetall(f"session:{session_id}")
    if not session_data:
        return jsonify({"error": "Session expired or invalid"}), 403

    user_id = session_data.get("user_id")
    role = session_data.get("role")

    # Only logged-in users or admins can update
    if not user_id:
        return jsonify({"error": "Invalid session"}), 401

    # Extract the fields to update
    data=request.get_json()
    name = data.get("name")
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    role_update = data.get("role")  # Optional — only admin can change this

    # Regular users can’t change their role
    if role != "Admin" and role_update:
        return jsonify({"error": "Only admins can change user roles"}), 403

    try:
        # Hash new password if provided
        from Utils.hash import hash_password
        hashed_pw = hash_password(password) if password else None

        # Update user info
        update_user(user_id, name, username, email, hashed_pw, role_update or role)

        return jsonify({"message": "User profile updated successfully"}), 200
    except ValueError:
        return jsonify({"error": str("Reenter new password")}), 500

@app.route('/delete/user', methods=['PUT'])
def delete_user():
    session_id = request.headers.get("session_id")

    # Get session info from Redis
    session_data = r.hgetall(f"session:{session_id}")
    if not session_data:
        return jsonify({"error": "Session expired or invalid"}), 403

    user_id = session_data.get("user_id")
    role = session_data.get("role")

    if role != "Admin":
        return jsonify({"error": "Access denied: Admins only"}), 403
    else:
      delete_user(user_id)
    return jsonify({"message": "User profile deleted successfully"}), 200

if __name__ == '__main__':
    app.run(debug=True)