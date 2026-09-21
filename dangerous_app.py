import os

# LEAKED API KEYS
OPENAI_API_KEY = "sk-proj-9999888877776666555544443333222211110000"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# SQL INJECTION
def get_user(user_id):
    return f"SELECT * FROM users WHERE id = {user_id}"

# REMOTE CODE EXECUTION
def run_code(code):
    return eval(code)
