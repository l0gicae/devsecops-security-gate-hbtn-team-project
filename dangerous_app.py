import os

# 🚨 1. SIZMIŞ GİZLİ AÇARLAR
OPENAI_API_KEY = "sk-proj-9999888877776666555544443333222211110000"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# 🚨 2. SQL INJECTION
def get_user_profile(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

# 🚨 3. REMOTE CODE EXECUTION (eval)
def run_calculator(user_input):
    return eval(user_input)
