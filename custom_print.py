from termcolor import colored, cprint


def print_err(msg):
    cprint("[!] ", color="red", end="")
    cprint(msg, color="yellow")

def print_i(msg):
    cprint(msg, color="yellow")

def print_ok(msg, start="", end=""):
    cprint("[+] ", color="green", end="")
    cprint(msg, color="yellow")