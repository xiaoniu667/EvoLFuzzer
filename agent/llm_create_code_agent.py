from llm_utils import call_chatgpt_programmer

class ProgrammerAgent:
    def __init__(self, entry):
        self.entry = entry

    def write_code(self):
        prompt = f"Create a python function that follows the following code requirements: {self.entry['Prompt']}"
        code = call_chatgpt_programmer(prompt)
        return code