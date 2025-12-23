from datetime import datetime

from datetime import datetime

def build_timestamp(date_str, time_str):
    combined = f"{date_str} {time_str}"
    formats = ["%Y-%m-%d %H:%M:%S"]
    for fmt in formats:
        try:
            return datetime.strptime(combined, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unrecognized timestamp format: {combined}")

# Test cases
print(build_timestamp("2025-12-14", "16:22:11"))
print(build_timestamp("2025-01-01", "00:00:00"))
