import logging
import sys
import json
from sandbox import DockerSandbox
from agent import Agent

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')

def test():
    # Load test spec
    with open('test_spec.json', 'r') as f:
        spec = json.load(f)
        
    sandbox = DockerSandbox()
    try:
        # Start sandbox
        sandbox.start(lab_id="test_lab_1")
        
        # Test basic command
        print("Testing basic bash command inside sandbox...")
        res = sandbox.execute_bash("ls -la && docker ps")
        print(f"Output: \n{res}\n")
        
        # Run agent
        agent = Agent(sandbox)
        result = agent.run(spec)
        
        print(f"Agent finished with result: {result}")
        print("\\nFull History:")
        for msg in agent.history:
            print(f"--- {msg['role'].upper()} ---\\n{msg['content']}\\n")
            
    finally:
        sandbox.cleanup()

if __name__ == "__main__":
    test()
