
def process_scores(scores):
    result = scores.sort()
    return result


def clean_username(username):
    return username.strip("PY")


def update_data(data):
    data[2] += [50, 60]
    return data

def calculate_total(values):
    return sum(values) / len(values) if values else None
