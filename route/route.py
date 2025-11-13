import os
from flask import Flask, request, jsonify, url_for
import uuid

from werkzeug.utils import secure_filename, send_from_directory

from Utils.OTP import generate_otp, verify_otp, send_otp_mail
from Utils.hash import verify
from connections.Redis import r
from Models.queries import create_user, get_user, retrieve_user,update_user, delete_user
from Models.queries import create_message,admin_check_message,get_user_messages,get_message_by_id,mark_message_as_read
from Utils.mail import send_login_alert,send_close_ticket, message_sent
from route.upload_route import create_folder, allowed_file, create_user_folder
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
      return jsonify({'status':"User created successfully"}),201
    except ValueError:
        return jsonify({"error": "Invalid input or empty field(s)"}),400

#login route
@app.route('/login', methods=['POST'])
def login():

    data = request.get_json()
    ip_address = request.remote_addr
    username = data.get('username')
    password = data.get('password')

    user = get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # user = (user_id, name, username, email, password, role)
    user_id= user[0]
    user_email = user[3]
    hash_pw = user[4]
    role = user[5]

    if not verify(password, hash_pw):
        return jsonify({"error": "Invalid password"}), 401

    # Create session in Redis
    session_id = str(uuid.uuid4())
    r.hset(username, mapping={
        "user_id": user_id,
        "session_id": session_id,
        "role": role
    })

    r.expire(username, 3600)  # expires in 1 hour

    send_login_alert(user_email=user_email, ip_address=ip_address)

    return jsonify({
        "message": "Login successful",
        "session_id": session_id,
        "role": role
    }), 200

#generation and sending of otp
@app.route("/generate_otp", methods=["POST"])
def generate_and_send_otp():
    session_id = request.headers.get("Session-Id")

    data = request.get_json()

    username = data.get("username")
    email = data.get("email")

    if not session_id or not username:
        return jsonify({"error": "session_id and username required"}), 400

    session_data = r.hgetall(username)

    if not session_data:
        return jsonify({"error": "Session not found"}), 404

    stored_session_id = session_data.get("session_id")
    if session_id != stored_session_id:
        return jsonify({"error": "Invalid or expired session ID"}), 401

    # Generate and send OTP
    otp = generate_otp(email)
    send_otp_mail(email, otp)

    return jsonify({"message": "OTP sent successfully"}), 200


@app.route("/message", methods=["POST"])
def send_message():
    session_id = request.headers.get("Session_Id")
    data = request.form  # Use form data because we may include a file
    username = data.get("username")
    email = data.get("email")
    otp = data.get("otp")
    sender_id = data.get("sender_id")
    subject = data.get("subject")
    content = data.get("content")
    receiver_id = os.getenv("RECEIVER_ID")
    file = request.files.get("file")

    #  Validate session
    session_data = r.hgetall(username)
    if not session_data:
        return jsonify({"error": "Session not found"}), 404

    stored_session_id = session_data.get("session_id")
    if session_id != stored_session_id:
        return jsonify({"error": "Session ID invalid or expired"}), 400

    #  Verify OTP
    if not verify_otp(email, otp):
        return jsonify({"error": "Invalid or expired OTP"}), 403


    create_folder()
    file_url = None  # Default in case user doesn’t upload file

    if file and file.filename != "":
        #  Handle optional file upload
        if not allowed_file(file.filename):
            return jsonify({"error": "File type not allowed"}), 403

        # Make user-specific folder
        user_folder = create_user_folder(username)

        #save file
        filename = secure_filename(file.filename)
        file_path = os.path.join(user_folder, filename)
        file.save(file_path)

        #Generate URL for accessing the file
        file_url = url_for('uploaded_file', username=username, filename=filename, _external=True)

    # Create new message ID and store in DB
    message_id = str(uuid.uuid4())

    create_message(
        message_id=message_id,
        sender_id=sender_id,
        receiver_id=receiver_id,
        subject=subject,
        content=content,
        is_read=False,
        file_url=file_url
    )
    message_sent(email=email,subjects=subject,content=content,file_url=file_url)
    return jsonify({
        "message": "Message sent successfully",
        "message_id": message_id,
        "file_url": file_url
    }), 201


# noinspection PyArgumentList
@app.route('/uploads/<username>/<filename>', methods=['GET'])
def uploaded_file(username, filename):
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    return send_from_directory(user_folder, filename)

@app.route("/messages", methods=["GET"])
def get_messages():
    session_id = request.headers.get("Session_Id")
    username = request.args.get("username")  # use query param

    # Validate session
    session_data = r.hgetall(username)
    if not session_data:
        return jsonify({"error": "Session not found"}), 404

    if session_id != session_data.get("session_id"):
        return jsonify({"error": "Session ID invalid or expired"}), 400

    user_id = session_data.get("user_id")
    role = session_data.get("role")

    try:
        if role == "Admin":
            return admin_check_message()
        elif role == "User":
            return get_user_messages(user_id)
        else:
            return jsonify({"error": "Invalid role"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/messages/<message_id>/reply", methods=["POST"])
def admin_reply_message(message_id):
    session_id = request.headers.get("Session_Id")

    data = request.get_json()
    username = data.get("username")
    reply_subject = data.get("subject")
    reply_content = data.get("content")

    session_data= r.hgetall(username)
    if session_id != session_data:
        return jsonify({"error": "Session ID invalid or expired"}), 400

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
    receiver_id = original_message["sender_id"] # send back to user
    receiver_user = retrieve_user(receiver_id)
    receiver_email = receiver_user["email"]
    create_message(
        message_id=reply_id,
        sender_id=admin_id,
        receiver_id=receiver_id,
        subject=reply_subject,
        content=reply_content,
        is_read=False,
        file_url=None)
    message_sent(receiver_email,reply_subject,reply_content,file_url=None)
    return jsonify({
        "message": "Reply sent successfully",
        "reply_id": reply_id
    }), 201



@app.route("/messages/<message_id>/close", methods=["PUT"])
def close_ticket(message_id):
    session_id = request.headers.get("Session_Id")

    data = request.get_json()
    username = data.get("username")

    user = get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    email = user["email"]
    session_data = r.hgetall(username)
    if session_id != session_data.get(session_id):
        return jsonify({"error": "Session ID expired or invalid"}), 400

    role = session_data.get("role")

    if role != "Admin":
        return jsonify({"error": "Access denied: Admins only"}), 403
    try:
        with connection.cursor() as cursor:
            cursor.execute("""UPDATE desk_messages SET status = 'closed' WHERE message_id = %s""",(message_id,))
        connection.commit()

        if send_close_ticket(email):
          return jsonify({"message": "Message ticket closed successfully"}), 200
    except ConnectionError:
        connection.rollback()
        return jsonify({"error": str("Ensure ticket is closed,if not rerun it")}), 500


@app.route('/<username>/update_user', methods=['PUT'])
def updates_user(username):
    session_id = request.headers.get("Session-Id")


    #username place in part parameter


    # Get session info from Redis
    session_data =r.hgetall(username)
    stored_session_id = session_data.get("session_id")
    if session_id != stored_session_id :
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
        update_user(username,name, email, hashed_pw, role_update or role)
        print(update_user(username,name, email, hashed_pw))

        return jsonify({"message": "User profile updated successfully"}), 200
    except ValueError:
        return jsonify({"error": str("Reenter new password")}), 500

@app.route('/delete/username', methods=['DELETE'])
def delete_users():
    session_id = request.headers.get("Session_Id")
    username = request.args.get("username")
    # Get session info from Redis
    session_data = r.hgetall(username)

    if session_id != session_data.get(session_id):
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