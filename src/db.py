import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",  # Remplace par ton user MySQL
        password="JeSuis12**",  # Remplace par ton mot de passe MySQL
        database="detectfraude"
    )