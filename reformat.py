# reformat_alerts.py
# Script to rewrite alerts.log in the correct format
with open("alerts.log", "r", encoding="utf-8") as f:
    lines = f.readlines()

# Process each line and reformat it
new_lines = []
for line in lines:
    if "[ALERT]" in line:
        # Extract timestamp and message from the current format
        match = line.strip().split(" - ", 1)
        if len(match) == 2:
            timestamp = match[0].replace("[ALERT] ", "").strip()
            message = match[1].strip()
            # Rewrite in the expected format
            new_line = f"[ALERT] [{timestamp}] {message}"
            new_lines.append(new_line)
        else:
            new_lines.append(line.strip())  # Keep the line as-is if it doesn't match
    else:
        new_lines.append(line.strip())

# Write the reformatted lines back to alerts.log
with open("alerts.log", "w", encoding="utf-8") as f:
    for line in new_lines:
        f.write(line + "\n")