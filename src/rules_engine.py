import yaml
from database import check_threshold_rule, insert_alert, is_suppressed

def load_rules(path="rules.yaml"):
    with open(path, "r") as f:
        config = yaml.safe_load(f)
    return config["rules"]

def run_rules():
    rules = load_rules()
    for rule in rules:
        name = rule["name"]
        event_type = rule["event_type"]
        threshold = rule["threshold"]
        window_seconds = rule["window_seconds"]
        distinct_column = rule.get("distinct_column")  # None if missing
        group_by_ip = rule.get("group_by_ip", True)     # defaults to grouped, like before
        username = rule.get("username")                 # None if missing
        # How long a fired alert stays "active" before the same rule+entity can
        # alert again. Defaults to the rule's own window_seconds when not set
        # explicitly, rather than requiring every rule in rules.yaml to add it.
        suppression_seconds = rule.get("suppression_seconds", window_seconds)

        matches = check_threshold_rule(event_type, threshold, window_seconds, distinct_column, group_by_ip, username)

        if matches:
            for match in matches:
                # Grouped rules (group_by_ip=True) return (source_ip, count);
                # ungrouped rules (e.g. rate_spike) return just (count,) since
                # there's no single entity to attribute the count to.
                if len(match) == 2:
                    matched_entity, count = match
                else:
                    matched_entity, count = None, match[0]

                if is_suppressed(name, matched_entity, suppression_seconds):
                    print(f"{name}: {matched_entity} still active (suppressed, alerted within {suppression_seconds}s)")
                    continue

                print(f"[ALERT] {name} triggered: {matched_entity} count={count}")
                insert_alert(name, matched_entity, count, window_seconds)
        else:
            print(f"{name}: no matches")

if __name__ == "__main__":
    run_rules()
