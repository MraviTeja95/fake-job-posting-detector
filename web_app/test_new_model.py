import os
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables
load_dotenv(dotenv_path='c:/Users/BAVAN KUMAR/fake-job-posting-detector/.env')

api_key = os.environ.get("NVIDIA_API_KEY")
print(f"API Key present: {bool(api_key)}")

if api_key:
    try:
        client = OpenAI(
            base_url="https://integrate.api.nvidia.com/v1",
            api_key=api_key
        )
        
        print("Attempting to call NVIDIA abacusai/dracarys-llama-3.1-70b-instruct...")
        completion = client.chat.completions.create(
            model="abacusai/dracarys-llama-3.1-70b-instruct",
            messages=[
                {"role": "user", "content": "Hello, are you working? Respond with 'YES' if you are."}
            ],
            temperature=0.5,
            top_p=1,
            max_tokens=10,
            stream=True
        )
        
        response_text = ""
        for chunk in completion:
            if chunk.choices and chunk.choices[0].delta.content is not None:
                response_text += chunk.choices[0].delta.content
        
        print(f"Response: {response_text}")
    except Exception as e:
        print(f"Error calling LLM: {e}")
else:
    print("NVIDIA_API_KEY not found in .env")
