from connections.postgres import connection
from Utils.hash import hash_password

def create_user(name,username,email,password,role='user'): #to register a new user
    with connection.cursor() as cursor:
        hash_pw=hash_password(password)
        cursor.execute("""
      INSERT INTO desk_user(name, username, email, password, role)
      VALUES (%s, %s, %s, %s, %s)
      """, (name, username, email, hash_pw, role))
    connection.commit()

def get_user_id(name):
    with connection.cursor() as cursor:
        cursor.execute("""SELECT user_id FROM desk_user WHERE name = %s""", (name,))
        result = cursor.fetchone()
        return result[0] if result else None

def get_user(username): #to fetch a user (for login, dashboard, etc.)
    with connection.cursor() as cursor:
        cursor.execute(""" SELECT * FROM desk_user WHERE username = %s""", (username, ))
        result = cursor.fetchone()
        return result

def retrieve_user(user_id):
    with connection.cursor() as cursor:
        cursor.execute(""" SELECT * FROM desk_user WHERE user_id = %s""", (user_id,))
        result = cursor.fetchone()
        return result

def update_user(username,name=None, email=None, password=None, role=None): #to update profile info

    with connection.cursor() as cursor:
        cursor.execute("""
            UPDATE desk_user
            SET
                name = COALESCE(%s, name),
                email = COALESCE(%s, email),
                password = COALESCE(%s, password),
                role = COALESCE(%s, role)
            WHERE username = %s
        """, (name, email, password, role, username))
    connection.commit()

def get_all_users():
    with connection.cursor() as cursor:
        cursor.execute("SELECT user_id, name, username, email, role FROM desk_user")
        return cursor.fetchall()

def delete_user(user_id):
  try:
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM desk_user WHERE user_id = %s", (user_id,))
  except Exception as e:
      connection.rollback()
      print(e)
  finally:
      connection.commit()

def create_message(message_id,sender_id,receiver_id,subject,content,is_read): #to send or save a new message
 try:
    with connection.cursor() as cursor:
        cursor.execute("""INSERT INTO desk_messages(message_id,sender_id,receiver_id,subject,content,is_read) 
                       VALUES(%s,%s,%s,%s,%s,%s)""", (message_id,sender_id,receiver_id,subject,content,is_read)
                       )
 except Exception as e:
     connection.rollback()
     print(e)
 finally:
     connection.commit()

def get_user_messages(user_id): #Retrieve all messages for a specific user
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT * FROM desk_message
            WHERE sender_id = %s OR receiver_id = %s
            ORDER BY created_at DESC
        """, (user_id, user_id))
        return cursor.fetchall()

def admin_check_message(): #for admin to see all messages
    with connection.cursor() as cursor:
        cursor.execute(""" SELECT * FROM desk_messages WHERE message_id IS NOT NULL""")
        result = cursor.fetchall()
        return result

def get_message_by_id(message_id):
    with connection.cursor() as cursor:
        cursor.execute(""" SELECT * FROM desk_messages WHERE message_id = %s""", (message_id,))
        result = cursor.fetchone()
        if result:
            return {
            "message_id": result[0],
            "sender_id": result[1],
            "receiver_id": result[2],
            "subject": result[3],
            "content": result[4],
            "is_read": result[5]
            }
        return None

def delete_message(message_id): #to remove a message
  try:
    with connection.cursor() as cursor:
        cursor.execute(""" DELETE FROM desk_messages WHERE message_id = %s """, (message_id,))
  except Exception as e:
      connection.rollback()
      print(e)
  finally:
      connection.commit()

def mark_message_as_read(message_id): #To update the status of a message.
  try:
    with connection.cursor() as cursor:
        cursor.execute("""
             UPDATE desk_messages
             SET is_read = TRUE
             WHERE message_id = %s
         """, (message_id,))
  except Exception as e:
      connection.rollback()
      print(e)
  finally:
      connection.commit()


