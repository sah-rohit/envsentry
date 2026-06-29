import os

port = int(os.getenv("PORT", "8080"))
api_key = os.environ["API_KEY"]
debug = os.getenv("DEBUG") == "True"
deprecated_var = os.getenv("LEGACY_TOKEN")
