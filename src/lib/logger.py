def log(message):
    # check if debug later on

    print(message, flush=True)


def error(message):
    log(f"ERROR: {message}")
