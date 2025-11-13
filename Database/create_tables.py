from connections.postgres import connection

def create_user_table():
    with connection.cursor() as cursor:
        cursor.execute("""CREATE TABLE IF NOT EXISTS desk_user (
        user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(100) NOT NULL,
        username VARCHAR(100) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT now()
    )""")
    connection.commit()

def create_message_table():
    with connection.cursor() as cursor:
        cursor.execute('''CREATE TABLE IF NOT EXISTS desk_messages(
          message_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          sender_id UUID REFERENCES desk_user(user_id) ON DELETE CASCADE,
          receiver_id UUID REFERENCES desk_user(user_id) ON DELETE CASCADE,
          subject VARCHAR(200),
          content TEXT NOT NULL,
          is_read BOOLEAN DEFAULT FALSE,
          file_url VARCHAR(200) DEFAULT 'None',
          status VARCHAR(20) DEFAULT 'open',
         created_at TIMESTAMP DEFAULT now()
         )''')
    connection.commit()

def alter():
    with connection.cursor() as cursor:
        cursor.execute("""ALTER TABLE desk_messages ADD COLUMN  """)
    connection.commit()
def alter_url():
    with connection.cursor() as cursor:
        cursor.execute("""ALTER TABLE desk_user ADD COLUMN """)
def create_all_tables():
  # create_user_table()
  create_message_table()
  # alter()
  # alter_url()
print("All tables created")
print("Table updated")

if __name__ == '__main__':
    create_all_tables()


