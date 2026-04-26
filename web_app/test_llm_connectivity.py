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
        
        print("Attempting to call NVIDIA Llama-3.1-70B (non-streaming)...")
        completion = client.chat.completions.create(
            model="meta/llama-3.1-70b-instruct",
            messages=[
                {"role": "user", "content": "Hello, are you working? Respond with 'YES' if you are."}
            ],
            temperature=0.0,
            max_tokens=10,
            stream=False
        )
        
        print(f"Completion type: {type(completion)}")
        print(f"Completion: {completion}")
        
        if hasattr(completion, 'choices'):
            response_text = completion.choices[0].message.content
            print(f"Response: {response_text}")
        else:
            print("Completion object does not have 'choices' attribute.")
            
    except Exception as e:
        print(f"Error calling LLM: {e}")
else:
    print("NVIDIA_API_KEY not found in .env")
