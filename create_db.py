import mysql.connector

db = mysql.connector.connect(
    host="localhost",
    user="root",
    passwd="root"
)

cursor = db.cursor()
cursor.execute("CREATE DATABASE weather_app")

cursor.execute("SHOW DATABASES")
a = cursor.fetchall()
print(a)