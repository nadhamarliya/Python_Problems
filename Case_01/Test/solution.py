
def process_scores(scores):
    scores.sort()
    return scores


def clean_username(username):
    return username.removeprefix("PY").removesuffix("PY")


def update_data(data):
    data[2].extend([50, 60])
    return data


def calculate_total(values):
    if not values:
        raise ValueError("Cannot calculate average of an empty list")

    return sum(values) / len(values)
