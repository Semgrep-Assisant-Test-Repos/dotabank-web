import psycopg2
conn = psycopg2.connect(
    "dbname=test user=postgres password='thisisapassword!#@'"
)
# Some other stuff

