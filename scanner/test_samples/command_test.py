import os
import subprocess

user_input = input("Enter command: ")

os.system(user_input)

subprocess.call(user_input, shell=True)

subprocess.Popen(user_input, shell=True)