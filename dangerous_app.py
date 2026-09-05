import os

# 🚨 SIZMIŞ GİZLİ AÇAR
OPENAI_API_KEY = "sk-proj-9999888877776666555544443333222211110000"

# 🚨 SQL INJECTION
def get_user(user_id):
    return f"SELECT * FROM users WHERE id = {user_id}"

# 🚨 REMOTE CODE EXECUTION (eval)
def run_code(code):
    return eval(code)
