import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        host="mysql-roote.alwaysdata.net",
        user="roote",  # Remplace par ton user MySQL
        password="azerty12**",  # Remplace par ton mot de passe MySQL
        database="roote_detectfraude"
    )